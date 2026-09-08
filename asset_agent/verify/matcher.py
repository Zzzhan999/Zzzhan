"""与 agent1 漏洞库（vulns.db）的只读匹配。

匹配逻辑与 agent1 的 assets.py 保持一致：
  - 产品级：指纹产品名 vs 漏洞受影响产品 / CPE 的 vendor:product；
  - 版本级：资产指纹版本 vs CPE 具体版本/版本范围（vs/ve/vs_ex/ve_ex）；
  - 结论分级：exact（版本命中）/ product（仅产品命中）。

以只读方式打开 vulns.db（mode=ro），绝不写入 agent1 的库。
"""

import json
import os
import re
import sqlite3

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# 产品名归一化别名（CPE 词汇 -> 指纹常用词，键为下划线归一化后的形式）
PRODUCT_ALIASES = {
    "http server": "apache http server",
    "httpd": "apache http server",
    "iis": "microsoft iis",
    "asp net": "microsoft asp.net",
    "tomcat": "apache tomcat",
    "winword": "microsoft word",
    "excel": "microsoft excel",
}


def norm_product(s: str) -> str:
    """归一化产品名：小写、下划线转空格、去多余空白。"""
    return re.sub(r"\s+", " ", (s or "").lower().replace("_", " ")).strip()


def _parse_version(v: str):
    v = (v or "").strip().strip('"').lower()
    if not v or v in ("*", "-", "n/a", "latest", "any"):
        return None
    segs = re.findall(r"\d+|[a-z]+", v.replace(",", "."))
    return tuple(segs) if segs else None


def _cmp_version(a, b):
    """比较两个版本元组。a<b -> -1, a>b -> 1, 相等 -> 0；无法比较 -> None。"""
    if a is None or b is None:
        return None
    for x, y in zip(a, b):
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        else:
            if x != y:
                return -1 if x < y else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


def _version_in_range(asset_ver: str, detail: dict) -> bool:
    """资产版本是否落在 CPE 的版本/范围约束内（与 agent1 一致）。"""
    cpe_ver = detail.get("version", "*")
    if cpe_ver and cpe_ver != "*":
        av, cv = _parse_version(asset_ver), _parse_version(cpe_ver)
        c = _cmp_version(av, cv)
        if c is None:
            return True  # 无法解析时保守视为命中
        return c == 0
    if not (detail.get("vs") or detail.get("ve") or detail.get("vs_ex") or detail.get("ve_ex")):
        return True  # 无版本约束 -> 影响所有版本
    av = _parse_version(asset_ver)
    if av is None:
        return True  # 资产版本未知，保守命中
    if detail.get("vs"):
        c = _cmp_version(av, _parse_version(detail["vs"]))
        if c is not None and c < 0:
            return False
    if detail.get("vs_ex"):
        c = _cmp_version(av, _parse_version(detail["vs_ex"]))
        if c is not None and c <= 0:
            return False
    if detail.get("ve"):
        c = _cmp_version(av, _parse_version(detail["ve"]))
        if c is not None and c > 0:
            return False
    if detail.get("ve_ex"):
        c = _cmp_version(av, _parse_version(detail["ve_ex"]))
        if c is not None and c >= 0:
            return False
    return True


def _cpe_products_match(fp_product: str, fp_vendor: str, cpe: dict) -> bool:
    """指纹产品 vs CPE 产品是否匹配（含别名与 vendor 软匹配）。"""
    p1 = norm_product(fp_product)
    p2 = norm_product(cpe.get("product", ""))
    if not p1 or not p2:
        return False
    if p1 == p2:
        ok = True
    elif PRODUCT_ALIASES.get(p2) == p1 or PRODUCT_ALIASES.get(p1) == p2:
        ok = True
    elif p2 in p1:  # 指纹产品名包含 CPE 产品名，如 "apache http server" ⊇ "http server"
        ok = True
    # 反向包含（p1 in p2，如 "nginx" ⊂ "nginx javascript"）禁止，避免把
    # 更具体的 CPE 产品（如 njs 模块）误配给笼统指纹。
    else:
        ok = False
    if not ok:
        return False
    # vendor 软匹配：指纹有 vendor 时要求 CPE vendor 一致或为空
    if fp_vendor and cpe.get("vendor") and norm_product(fp_vendor) != norm_product(cpe["vendor"]):
        # 允许少数已知的 vendor 别名偏差（如 apache vs httpd）
        if not (norm_product(fp_vendor) in ("apache",) and norm_product(cpe["vendor"]) in ("apache", "httpd")):
            return False
    return True


def _products_match(fp_product: str, fp_vendor: str, affected: str) -> bool:
    """指纹产品 vs affected_products 里的 'vendor:product' 字符串。"""
    ap = affected.strip()
    if ":" in ap:
        av, ap2 = ap.split(":", 1)
    else:
        av, ap2 = "", ap
    return _cpe_products_match(fp_product, fp_vendor, {"vendor": av, "product": ap2})


class VulnDBReader:
    """只读访问 agent1 的漏洞库。"""

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"漏洞库不存在: {path}（请先运行 agent1: python main.py sync --days 7）")
        uri = f"file:{os.path.abspath(path)}?mode=ro"
        self.conn = sqlite3.connect(uri, uri=True)
        self.conn.row_factory = sqlite3.Row

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

    def _candidates(self, product: str) -> list[dict]:
        """按产品名分词粗筛候选 CVE（只查受影响产品/CPE 证据列）。

        用 token 做 LIKE 保证召回（如 "apache http server" 能命中
        "apache:http server" 与 cpe product "http_server"），
        精确性由后续 _cpe_products_match 严格过滤。
        """
        tokens = [t for t in re.split(r"\s+", (product or "").lower()) if len(t) >= 2]
        if not tokens:
            return []
        where, params = [], []
        for t in tokens:
            like = f"%{t}%"
            where.append("affected_products LIKE ?")
            params.append(like)
            where.append("cpes_json LIKE ?")
            params.append(like)
        rows = self.conn.execute(
            "SELECT cve_id, summary, summary_cn, severity, cvss_score, known_exploited, "
            "affected_products, cpes_json FROM vulnerabilities "
            f"WHERE {' OR '.join(where)} "
            "ORDER BY cvss_score DESC NULLS LAST LIMIT 500", params).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        try:
            return self.conn.execute("SELECT COUNT(*) c FROM vulnerabilities").fetchone()["c"]
        except Exception:
            return 0


def _load_list(raw) -> list:
    try:
        v = json.loads(raw or "[]")
        return v if isinstance(v, list) else []
    except Exception:
        return []


def match_fingerprint(reader: VulnDBReader, product: str, version: str = "",
                      vendor: str = "") -> list[dict]:
    """对单个指纹做匹配，返回命中列表。

    每个命中: {cve_id, severity, cvss_score, known_exploited, match_level, evidence}
      evidence: {"cpe": {..}, "range_check": "...", "via": "cpe"|"product"}

    判定规则：
      - CPE 列表包含该产品时：任一 CPE 满足版本范围 -> 命中（有版本=exact，无版本=product）；
        所有 CPE 都不满足版本范围 -> 该 CVE 判为不适用（不回退产品级）。
      - CPE 列表为空或不含该产品时：回退到 affected_products 产品级匹配。
    """
    if not product:
        return []
    hits: list[dict] = []
    seen: set[str] = set()
    for cand in reader._candidates(product):
        cve = cand["cve_id"]
        # 兼容新旧 cpes_json 格式：dict 列表 / "vendor:product" 字符串列表
        cpes: list[dict] = []
        for c in _load_list(cand.get("cpes_json")):
            if isinstance(c, dict):
                cpes.append(c)
            else:
                s = str(c)
                vp = s.split(":", 1)
                cpes.append({"vendor": vp[0] if len(vp) > 1 else "",
                             "product": vp[1] if len(vp) > 1 else s, "version": "*"})
        hit_cpes = [c for c in cpes if _cpe_products_match(product, vendor, c)]
        best: dict | None = None
        if hit_cpes:
            # 产品出现在 CPE 中：只看版本范围命中
            passing = [c for c in hit_cpes if _version_in_range(version, c)]
            if not passing:
                continue  # 版本被 CPE 范围排除 -> 不适用
            for c in passing:
                cand_sev = (cand.get("severity") or "").upper()
                level = "exact" if version else "product"
                ev = {
                    "via": "cpe",
                    "cpe": {k: c.get(k, "") for k in
                            ("vendor", "product", "version", "vs", "ve", "vs_ex", "ve_ex")},
                    "range_check": f"version={version or '*'} 满足该 CPE 约束" if version
                                   else "资产版本未知，按产品级命中",
                }
                if best is None or SEV_ORDER.get(cand_sev, 9) < SEV_ORDER.get(
                        (best.get("severity") or "").upper(), 9):
                    best = {"cve_id": cve, "severity": cand.get("severity"),
                            "cvss_score": cand.get("cvss_score"),
                            "known_exploited": bool(cand.get("known_exploited")),
                            "match_level": level, "evidence": ev}
        elif not cpes:
            # 无任何 CPE 数据：回退 affected_products 产品级匹配
            for ap in _load_list(cand.get("affected_products")):
                if _products_match(product, vendor, str(ap)):
                    best = {"cve_id": cve, "severity": cand.get("severity"),
                            "cvss_score": cand.get("cvss_score"),
                            "known_exploited": bool(cand.get("known_exploited")),
                            "match_level": "product",
                            "evidence": {"via": "product", "affected_product": str(ap)}}
                    break
        # else: CPE 列表存在但不含该产品 -> 也不回退，避免噪音
        if best and best["cve_id"] not in seen:
            seen.add(best["cve_id"])
            hits.append(best)
    hits.sort(key=lambda h: (h["cvss_score"] is None, -(h["cvss_score"] or 0)))
    return hits


def run_matching(db, reader: VulnDBReader, host_id: int | None = None) -> dict:
    """对库内指纹批量匹配并入库。返回统计。"""
    fps = db.list_fingerprints(host_id=host_id)
    new = updated = 0
    for fp in fps:
        hits = match_fingerprint(reader, fp["product"], fp["version"], fp["vendor"])
        for h in hits:
            db.upsert_match(
                host_id=fp["host_id"], cve_id=h["cve_id"], severity=h["severity"],
                cvss=h["cvss_score"], known_exploited=h["known_exploited"],
                match_level=h["match_level"], evidence=h["evidence"],
                service_id=fp["service_id"], fingerprint_id=fp["id"])
            new += 1
    return {"fingerprints": len(fps), "matches": new}

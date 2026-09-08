"""扫描引擎：把「自动扫描」流水线抽成可复用函数。

CLI（main.py scan）与服务器调度器（scheduler.py）共用同一套扫描逻辑，
保证命令行与常驻服务行为一致。
"""

import ipaddress
import sys
from pathlib import Path

from .db import Database

DEFAULT_PORTS = "80,443,22,21,8080,8443,8000,8888,3306,6379,5432,27017,9200,7001,3389,445,1433"


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def looks_like_domain(s: str) -> bool:
    return "." in s and not s.startswith(("http://", "https://"))


def read_hosts_file(path: str) -> list[str]:
    out = []
    for line in open(path, "r", encoding="utf-8-sig"):
        h = line.strip()
        if h and not h.startswith("#"):
            out.append(h)
    return out


def _gen_report(db, fmt: str) -> str:
    from . import report
    return report.generate(db, fmt=fmt)


def run_scan(targets: list[str], ports: str = DEFAULT_PORTS, vuln_db: str | None = None,
             timeout: float = 2.0, workers: int = 200, no_ct: bool = False,
             scope=None, db: Database | None = None,
             progress=None) -> dict:
    """执行完整自动扫描流水线，返回结果摘要。

    targets   待扫描目标（域名/IP），须已在授权范围内
    scope     授权范围对象（含 ensure()），None 时不校验（服务端模式由调用方保证）
    db        Database 实例，None 时新建（默认 data/assets.db）
    progress  可选回调 progress(str)，用于转发阶段信息到日志/界面
    """
    from .discovery import subdomains as sd
    from .discovery import portscan as ps
    from .discovery import fingerprint as fp_mod, webtech
    from .verify import matcher, checks as chk, explore

    owned_db = db is None
    if db is None:
        db = Database()
    _log = progress or (lambda s: None)

    if scope is None:
        from .scope import load_default
        scope = load_default()
    if scope is not None and not getattr(scope, "empty", False):
        _log(f"[0] 范围依据: {scope.describe()}")

    summary = {"hosts": 0, "open": 0, "fingerprints": 0, "matches": 0,
               "findings": 0, "checks": 0, "snapshot": None, "report": None,
               "rejected": [], "targets": list(targets), "notice": []}

    # ---- [1] 目标展开（范围校验 + 子域名发现） ----
    _log("[1/7] 目标展开（范围校验 + 子域名发现）...")
    expanded = []
    for t in targets:
        if scope is not None and not scope.empty:
            try:
                scope.ensure(t)
            except Exception as e:
                _log(f"  [拒绝] {e}")
                summary["rejected"].append(str(t))
                continue
        if looks_like_domain(t) and not is_ip(t):
            try:
                r = sd.discover_subdomains(t, use_ct=not no_ct)
            except Exception as e:
                _log(f"  [!] 子域名发现失败({e})，使用目标本身")
                r = {"names": [t], "resolved": {}}
            for n in r["names"]:
                ips = r["resolved"].get(n, [])
                db.upsert_host(n, ip=ips[0] if ips else "", host_type="domain",
                               source="scan")
                expanded.append((n, ips[0] if ips else n))
            _log(f"  {t} -> 展开 {len(r['names'])} 个主机")
        else:
            db.upsert_host(t, ip="" if is_ip(t) else t, source="scan")
            expanded.append((t, t))
    if not expanded:
        _log("[!] 没有通过授权范围的目标，扫描终止。")
        summary["notice"].append("no targets in scope")
        return summary
    _log(f"  共 {len(expanded)} 个待扫描主机")
    summary["hosts"] = len(expanded)

    # ---- [2] 端口扫描 ----
    _log("[2/7] 端口扫描 ...")
    ports_list = ps.parse_ports(ports)
    n_open = 0
    for name, ip in expanded:
        hid = db.upsert_host(name, source="scan")
        try:
            opens = ps.scan_host(ip, ports_list, timeout=timeout, workers=workers)
        except Exception as e:
            _log(f"  [!] {name} 端口扫描失败: {e}")
            continue
        for o in opens:
            db.upsert_service(hid, ip=ip, port=o["port"], service=o["service"])
        n_open += len(opens)
        line = ", ".join(f"{o['port']}/{o['service'] or '?'}" for o in opens)
        _log(f"  {name:<38} 开放 {len(opens)} 端口: {line or '-'}")
    if not n_open:
        _log("  [提示] 未发现开放端口，跳过后续验证。")
        db.log_scan("scan", ",".join(expanded[0]), "no open ports")
        summary["notice"].append("no open ports")
        return summary
    _log(f"  共开放 {n_open} 个端口")
    summary["open"] = n_open

    # ---- [3] 指纹识别 ----
    _log("[3/7] 服务指纹识别 ...")
    n_fp = 0
    for sv in db.list_services():
        h = db.get_host(sv["host_id"]) or {}
        target = h.get("ip") or h.get("host") or sv["ip"]
        try:
            fp = fp_mod.fingerprint_service(target, sv["port"], sv["service"],
                                            timeout=timeout)
        except Exception:
            continue
        http = fp["http"] or {}
        tech = webtech.detect_all(headers=http.get("headers"), body=http.get("body", ""),
                                  banner=fp["banner"])
        db.upsert_service(sv["host_id"], ip=sv["ip"], port=sv["port"],
                          service=fp["service"] or sv["service"], banner=fp["banner"],
                          http_status=http.get("status"), http_title=http.get("title", ""),
                          http_server=(http.get("headers") or {}).get("server", ""),
                          tech=tech, tls=fp["tls"])
        for t in tech:
            db.upsert_fingerprint(sv["host_id"], sv["id"], t["product"], t["version"],
                                  t["vendor"], 1.0, t["source"])
            n_fp += 1
    _log(f"  识别 {n_fp} 个产品指纹")
    summary["fingerprints"] = n_fp

    # ---- [4] 漏洞库匹配（版本级） ----
    _log("[4/7] 漏洞库匹配（只读 agent1 漏洞库）...")
    n_match = 0
    if vuln_db:
        try:
            reader = matcher.VulnDBReader(vuln_db)
            before = len(db.list_matches())
            m_res = matcher.run_matching(db, reader)
            n_match = len(db.list_matches()) - before  # 本次实际新增的唯一 CVE 数
            _log(f"  漏洞库 {reader.count()} 条 CVE -> 版本命中 {n_match} 条（新增唯一 CVE）")
            reader.close()
        except FileNotFoundError as e:
            _log(f"  [!] {e}（跳过匹配，报告不含 CVE 明细）")
    else:
        _log("  [!] 未指定漏洞库路径，跳过 CVE 匹配")
    summary["matches"] = n_match

    # ---- [5] 主动漏洞检测 ----
    _log("[5/7] 主动漏洞检测（只读、非破坏）...")
    findings = explore.run_explore(db, timeout=timeout)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))
    for f in findings[:30]:
        _log(f"  [{f['severity']:<8}] {f['name']}  {f['evidence'][:90]}")
    if len(findings) > 30:
        _log(f"  ... 其余 {len(findings) - 30} 条见报告")
    _log(f"  共发现 {len(findings)} 个问题")
    summary["findings"] = len(findings)

    # ---- [6] 安全检查 ----
    _log("[6/7] 安全检查 ...")
    n_chk = 0
    for sv in db.list_services():
        if sv["http_status"] is None and sv["service"] not in ("https", "https-alt", "ssl"):
            continue
        h = db.get_host(sv["host_id"]) or {}
        target = h.get("ip") or h.get("host") or sv["ip"]
        is_https = sv["service"] in ("https", "https-alt", "ssl") or sv["port"] in (443, 8443)
        probe = fp_mod.http_probe(target, sv["port"], timeout=timeout, is_https=is_https)
        results = chk.run_checks(target, sv["port"], sv["service"], probe or {"headers": None},
                                 is_https, timeout=timeout)
        for r in results:
            db.add_check(sv["host_id"], sv["id"], r["name"], r["status"], r["detail"])
            n_chk += 1
    _log(f"  记录 {n_chk} 条检查结果")
    summary["checks"] = n_chk

    # ---- [7] 报告 + 快照 ----
    _log("[7/7] 生成报告并保存快照 ...")
    try:
        report_path = _gen_report(db, "html")
        summary["report"] = report_path
    except Exception as e:
        _log(f"  [!] 报告生成失败: {e}")
        report_path = None
    try:
        snap_id = db.capture_snapshot(source="scan")
        summary["snapshot"] = snap_id
    except Exception as e:
        _log(f"  [!] 快照保存失败: {e}")
        snap_id = None
    db.log_scan("scan", ",".join(t for t, _ in expanded)[:200],
                f"hosts={len(expanded)}, open={n_open}, fingerprints={n_fp}, "
                f"matches={n_match}, findings={len(findings)}, snapshot={snap_id}")
    if report_path:
        _log(f"  报告: {report_path}")
    if snap_id:
        _log(f"  快照: #{snap_id}")
    if owned_db:
        db.close()
    return summary

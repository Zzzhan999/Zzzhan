"""导出：资产清单 / 漏洞匹配 / 安全检查结果 -> CSV / JSON / Markdown。

统一入口 export_all(db, fmt, out) 与按需导出函数。
"""

import csv
import io
import json
import os
from datetime import datetime
from pathlib import Path

from .verify.risk import host_risk, risk_level


def _out_dir() -> str:
    return str(Path(__file__).resolve().parent.parent / "data" / "exports")


def _fmt_list(items: list[tuple], headers: list[str], fmt: str) -> str:
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(headers)
        for it in items:
            w.writerow(["" if v is None else v for v in it])
        return buf.getvalue()
    if fmt == "json":
        return json.dumps(
            [dict(zip(headers, ["" if v is None else v for v in it])) for it in items],
            ensure_ascii=False, indent=2)
    # markdown
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for it in items:
        cells = [str("" if v is None else v).replace("|", "\\|") for v in it]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def export_hosts(db, fmt: str = "csv") -> str:
    services = db.list_services()
    fps = db.list_fingerprints()
    matches = db.list_matches()
    svc_c, fp_c = {}, {}
    for s in services:
        svc_c[s["host_id"]] = svc_c.get(s["host_id"], 0) + 1
    for f in fps:
        fp_c[f["host_id"]] = fp_c.get(f["host_id"], 0) + 1
    m_map = {}
    for m in matches:
        m_map.setdefault(m["host_id"], []).append(m)
    items = []
    for h in db.list_hosts():
        ms = m_map.get(h["id"], [])
        items.append((h["host"], h["ip"] or "", svc_c.get(h["id"], 0),
                      fp_c.get(h["id"], 0), len(ms),
                      sum(1 for m in ms if m["known_exploited"]),
                      f"{risk_level(host_risk(ms))} {host_risk(ms)}"))
    return _fmt_list(items, ["host", "ip", "services", "fingerprints",
                             "vulns", "kev", "risk"], fmt)


def export_matches(db, fmt: str = "csv") -> str:
    items = []
    for m in db.list_matches():
        kev = "[KEV]" if m["known_exploited"] else ""
        items.append((m["cve_id"], m["host_name"], m["severity"] or "",
                      m["cvss_score"] if m["cvss_score"] is not None else "",
                      m["match_level"], kev, m["matched_at"] or ""))
    return _fmt_list(items, ["cve_id", "host", "severity", "cvss", "match_level",
                             "kev", "matched_at"], fmt)


def export_checks(db, fmt: str = "csv") -> str:
    items = [(c["host_name"], c["check_name"], c["status"], c["detail"],
              c["checked_at"] or "") for c in db.list_checks()]
    return _fmt_list(items, ["host", "check", "status", "detail", "checked_at"], fmt)


def export_all(db, fmt: str = "csv", out: str = "") -> list[str]:
    """导出全部三类数据到目录，返回文件路径列表。fmt: csv/json/md。"""
    out = out or _out_dir()
    os.makedirs(out, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = []
    for name, fn in (("assets", export_hosts), ("vulns", export_matches),
                     ("checks", export_checks)):
        p = os.path.join(out, f"agent2_{name}_{ts}.{fmt}")
        with open(p, "w", encoding="utf-8-sig" if fmt == "csv" else "utf-8") as f:
            f.write(fn(db, fmt))
        paths.append(p)
    return paths

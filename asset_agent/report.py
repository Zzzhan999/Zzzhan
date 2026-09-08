"""HTML / Markdown 安全报告生成。"""

import html
import os
from datetime import datetime
from pathlib import Path

from .verify.risk import host_risk, risk_level

SEV_COLOR = {"CRITICAL": "#d93025", "HIGH": "#e8710a", "MEDIUM": "#f9ab00",
             "LOW": "#1a73e8", "NONE": "#80868b"}


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _sev_tag(sev: str) -> str:
    sev = (sev or "NONE").upper()
    return f'<span style="color:{SEV_COLOR.get(sev, "#80868b")};font-weight:700">{_esc(sev)}</span>'


def _fmt_evidence(ev: dict) -> str:
    if not isinstance(ev, dict):
        return ""
    if ev.get("via") == "cpe":
        c = ev.get("cpe", {})
        parts = [f"{c.get('vendor','?')}:{c.get('product','?')}"]
        if c.get("version") and c.get("version") != "*":
            parts.append(f"版本={c['version']}")
        for k, sym in (("vs", ">="), ("vs_ex", ">"), ("ve", "<="), ("ve_ex", "<")):
            if c.get(k):
                parts.append(f"{sym} {c[k]}")
        return "CPE: " + ", ".join(parts) + " ｜ " + _esc(ev.get("range_check", ""))
    if ev.get("via") == "product":
        return "受影响产品: " + _esc(ev.get("affected_product", ""))
    return _esc(str(ev))


def generate(db, out_dir: str = "", fmt: str = "html") -> str:
    """生成报告，返回文件路径。fmt: html / md。"""
    out_dir = out_dir or str(Path(__file__).resolve().parent.parent / "data" / "reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"agent2_report_{ts}.{fmt}")
    s = db.stats()
    hosts = db.list_hosts()
    matches = db.list_matches()
    checks = db.list_checks()
    findings = db.list_findings()
    services = db.list_services()

    # host -> 匹配/检查聚合
    host_match_map: dict[int, list] = {}
    for m in matches:
        host_match_map.setdefault(m["host_id"], []).append(m)
    host_check_map: dict[int, list] = {}
    for c in checks:
        host_check_map.setdefault(c["host_id"], []).append(c)
    host_find_map: dict[int, list] = {}
    for f in findings:
        host_find_map.setdefault(f["host_id"], []).append(f)
    host_svc_map: dict[int, list] = {}
    for sv in services:
        host_svc_map.setdefault(sv["host_id"], []).append(sv)

    rows = []
    for h in hosts:
        ms = host_match_map.get(h["id"], [])
        cs = host_check_map.get(h["id"], [])
        fs = host_find_map.get(h["id"], [])
        svs = host_svc_map.get(h["id"], [])
        risk = host_risk(ms)
        rows.append({
            "host": h, "svc": svs, "matches": ms, "checks": cs, "findings": fs,
            "risk": risk,
            "critical": sum(1 for m in ms if (m["severity"] or "").upper() == "CRITICAL"),
            "high": sum(1 for m in ms if (m["severity"] or "").upper() == "HIGH"),
            "kev": sum(1 for m in ms if m["known_exploited"]),
        })
    rows.sort(key=lambda r: -r["risk"])

    if fmt == "md":
        content = _render_md(s, rows)
    else:
        content = _render_html(s, rows)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _render_html(s: dict, rows: list[dict]) -> str:
    match_rows = []
    for r in rows:
        for m in r["matches"]:
            match_rows.append((r, m))
    check_rows = []
    for r in rows:
        for c in r["checks"]:
            check_rows.append((r, c))
    find_rows = []
    for r in rows:
        for f in r["findings"]:
            find_rows.append((r, f))

    def host_table():
        trs = []
        for r in rows:
            trs.append(
                f"<tr><td>{_esc(r['host']['host'])}</td>"
                f"<td>{_esc(r['host']['ip'] or '-')}</td>"
                f"<td>{len(r['svc'])}</td>"
                f"<td>{len(r['matches'])}</td>"
                f"<td>{r['critical']} / {r['high']}</td>"
                f"<td>{r['kev']}</td>"
                f"<td>{_sev_tag(risk_level(r['risk']))} {r['risk']}/10</td></tr>")
        return "\n".join(trs)

    def match_table():
        trs = []
        for r, m in match_rows:
            sev = (m["severity"] or "NONE").upper()
            kev = " [KEV]" if m["known_exploited"] else ""
            trs.append(
                f"<tr><td>{_esc(m['cve_id'])}{kev}</td>"
                f"<td>{_sev_tag(sev)}</td>"
                f"<td>{_esc(m['cvss_score'] if m['cvss_score'] is not None else '-')}</td>"
                f"<td>{_esc(r['host']['host'])}</td>"
                f"<td>{_esc(m['match_level'])}</td>"
                f"<td style='font-size:12px'>{_fmt_evidence(m['evidence'])}</td></tr>")
        return "\n".join(trs)

    def check_table():
        trs = []
        for r, c in check_rows:
            color = {"warning": "#e8710a", "ok": "#188038", "info": "#1a73e8"}.get(c["status"], "#80868b")
            trs.append(
                f"<tr><td>{_esc(r['host']['host'])}</td>"
                f"<td>{_esc(c['check_name'])}</td>"
                f"<td style='color:{color};font-weight:700'>{_esc(c['status'])}</td>"
                f"<td style='font-size:12px'>{_esc(c['detail'])}</td></tr>")
        return "\n".join(trs)

    def finding_table():
        trs = []
        for r, f in find_rows:
            sev = (f["severity"] or "INFO").upper()
            trs.append(
                f"<tr><td>{_esc(r['host']['host'])}</td>"
                f"<td>{_sev_tag(sev)}</td>"
                f"<td>{_esc(f['name'])}</td>"
                f"<td style='font-size:12px'>{_esc(f['evidence'])}</td>"
                f"<td style='font-size:12px'>{_esc(f['remediation'] or '-')}</td></tr>")
        return "\n".join(trs)

    body = f"""
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>Agent2 资产风险验证报告</title>
<style>
body{{font-family:'Microsoft YaHei',Arial,sans-serif;margin:24px;color:#202124}}
h1{{border-bottom:2px solid #1a73e8;padding-bottom:8px}}
h2{{margin-top:28px;color:#1a73e8}}
table{{border-collapse:collapse;width:100%;margin:8px 0 20px;font-size:13px}}
th,td{{border:1px solid #dadce0;padding:6px 10px;text-align:left}}
th{{background:#f1f3f4}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{border:1px solid #dadce0;border-radius:8px;padding:12px 18px;min-width:110px}}
.card b{{display:block;font-size:22px;color:#1a73e8}}
.note{{background:#e8f0fe;padding:10px 14px;border-radius:6px;font-size:12px;color:#174ea6}}
</style></head><body>
<h1>Agent2 资产风险验证报告</h1>
<p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ｜ 数据: 本地资产数据库</p>
<div class="cards">
<div class="card"><b>{s['hosts']}</b>发现主机</div>
<div class="card"><b>{s['services']}</b>开放服务</div>
<div class="card"><b>{s['fingerprints']}</b>指纹产品</div>
<div class="card"><b>{s['matches']}</b>匹配漏洞</div>
<div class="card"><b>{s['kev']}</b>KEV 已知利用</div>
<div class="card"><b>{s['findings']}</b>主动发现</div>
<div class="card"><b>{s['checks']}</b>安全检查项</div>
</div>
<p class="note">本报告仅用于自有/已授权资产的防御性评估。漏洞匹配基于指纹与 CPE 版本范围，
为证据链式验证；主动发现为只读探测结果，均不代表可利用性确认。</p>
<h2>一、资产风险总览</h2>
<table><tr><th>主机</th><th>IP</th><th>服务数</th><th>漏洞数</th>
<th>CRITICAL/HIGH</th><th>KEV</th><th>风险分</th></tr>
{host_table()}</table>
<h2>二、漏洞匹配明细</h2>
<table><tr><th>CVE</th><th>级别</th><th>CVSS</th><th>命中资产</th>
<th>匹配级别</th><th>验证证据</th></tr>
{match_table()}</table>
<h2>三、主动漏洞发现</h2>
<table><tr><th>资产</th><th>级别</th><th>漏洞</th><th>证据</th><th>修复建议</th></tr>
{finding_table()}</table>
<h2>四、安全检查结果</h2>
<table><tr><th>主机</th><th>检查项</th><th>状态</th><th>详情</th></tr>
{check_table()}</table>
<h2>五、处置建议</h2>
<ul>
<li>对 <b>KEV</b> 标记且版本命中的漏洞优先处置（已知被在野利用），建议 7 天内完成升级或缓解。</li>
<li>对 CRITICAL/HIGH 且版本命中的漏洞，升级到不受影响版本或启用临时缓解措施。</li>
<li>主动发现中的 HIGH 项（源码/密钥/备份泄露、Actuator 未授权、CORS 反射）应优先处置，多数为配置问题，可快速修复。</li>
<li>安全检查中的 warning 项（缺失安全响应头、暴露端点、TRACE、证书到期）应在加固阶段逐项修复。</li>
<li>资产版本未知（产品级命中）的条目，建议人工确认版本后再定处置优先级。</li>
</ul>
</body></html>"""
    return body


def _render_md(s: dict, rows: list[dict]) -> str:
    lines = ["# Agent2 资产风险验证报告", "",
             f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]
    lines += ["## 概览", "",
              f"- 发现主机: {s['hosts']} ｜ 开放服务: {s['services']} ｜ 指纹产品: {s['fingerprints']}",
              f"- 匹配漏洞: {s['matches']}（KEV: {s['kev']}） ｜ 主动发现: {s['findings']} ｜ 安全检查: {s['checks']} 项", "",
              "> 本报告仅用于自有/已授权资产的防御性评估；匹配为证据链式验证，不代表可利用性确认。", ""]
    lines += ["## 一、资产风险总览", "",
              "| 主机 | IP | 服务 | 漏洞 | C/H | KEV | 风险 |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        lines.append(f"| {r['host']['host']} | {r['host']['ip'] or '-'} | {len(r['svc'])} | "
                     f"{len(r['matches'])} | {r['critical']}/{r['high']} | {r['kev']} | "
                     f"{risk_level(r['risk'])} {r['risk']}/10 |")
    lines += ["", "## 二、漏洞匹配明细", "",
              "| CVE | 级别 | CVSS | 命中资产 | 级别 | 证据 |",
              "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        for m in r["matches"]:
            kev = " [KEV]" if m["known_exploited"] else ""
            lines.append(f"| {m['cve_id']}{kev} | {m['severity'] or 'N/A'} | "
                         f"{m['cvss_score'] if m['cvss_score'] is not None else '-'} | "
                         f"{r['host']['host']} | {m['match_level']} | "
                         f"{_fmt_evidence(m['evidence'])} |")
    lines += ["", "## 三、主动漏洞发现", "",
              "| 资产 | 级别 | 漏洞 | 证据 | 修复建议 |",
              "| --- | --- | --- | --- | --- |"]
    for r in rows:
        for f in r["findings"]:
            lines.append(f"| {r['host']['host']} | {f['severity'] or 'INFO'} | "
                         f"{f['name']} | {f['evidence']} | {f['remediation'] or '-'} |")
    lines += ["", "## 四、安全检查结果", "",
              "| 主机 | 检查项 | 状态 | 详情 |", "| --- | --- | --- | --- |"]
    for r in rows:
        for c in r["checks"]:
            lines.append(f"| {r['host']['host']} | {c['check_name']} | {c['status']} | {c['detail']} |")
    lines += ["", "## 五、处置建议", "",
              "1. KEV 标记且版本命中的漏洞优先处置，建议 7 天内升级/缓解。",
              "2. CRITICAL/HIGH 版本命中漏洞：升级到不受影响版本或启用临时缓解。",
              "3. 主动发现 HIGH 项（源码/密钥/备份泄露、Actuator 未授权、CORS 反射）优先处置，多数为配置问题。",
              "4. 安全 warning 项（响应头/暴露端点/TRACE/证书）在加固阶段逐项修复。",
              "5. 版本未知的产品级命中，先人工确认版本再定优先级。", ""]
    return "\n".join(lines)

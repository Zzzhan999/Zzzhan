"""告警推送（可选）：飞书机器人 / 通用 Webhook。

只推送**版本命中（exact）**且达到最低级别的漏洞，避免噪音。
"""

import json
import os
import urllib.request


def _post(url: str, payload: dict, timeout: float = 8.0) -> str:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "AssetAgent2/0.1",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")[:500]


def push_feishu(url: str, title: str, text: str) -> str:
    return _post(url, {"msg_type": "text", "content": {"text": f"{title}\n{text}"}})


def push_webhook(url: str, title: str, text: str) -> str:
    return _post(url, {"title": title, "text": text})


def push_findings(db, url: str, min_severity: str = "HIGH",
                  channel: str = "feishu", max_lines: int = 20) -> dict:
    """汇总库内 exact 命中且达到级别的漏洞并推送。"""
    matches = db.list_matches(min_severity=min_severity)
    exact = [m for m in matches if m.get("match_level") == "exact"]
    if not exact:
        return {"pushed": False, "reason": "没有达到条件的版本命中漏洞"}
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    exact.sort(key=lambda m: (m["cvss_score"] is None, -(m["cvss_score"] or 0),
                              sev_order.get((m["severity"] or "").upper(), 9)))
    lines = []
    for m in exact[:max_lines]:
        kev = " [KEV]" if m["known_exploited"] else ""
        lines.append(f"• {m['cve_id']}{kev} [{m['severity'] or 'N/A'}] "
                     f"CVSS={m['cvss_score'] if m['cvss_score'] is not None else '-'} "
                     f"命中 {m['host_name']} ({m['match_level']})")
    title = f"Agent2 漏洞验证告警：{len(exact)} 条版本命中（≥{min_severity}）"
    text = "\n".join(lines)
    if channel == "feishu":
        resp = push_feishu(url, title, text)
    else:
        resp = push_webhook(url, title, text)
    return {"pushed": True, "count": len(exact), "response": resp}

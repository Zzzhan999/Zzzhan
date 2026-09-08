"""子域名被动发现：DNS 解析 + 证书透明日志（crt.sh）。

仅使用公开数据（DNS、CT 日志），不向目标发送任何探测包。
"""

import json
import re
import socket
import urllib.request

UA = "Mozilla/5.0 (compatible; AssetAgent2/0.1; +security research on authorized assets)"

_NAME_RE = re.compile(r"^[a-z0-9*]([a-z0-9.-]*[a-z0-9])?$", re.I)


def normalize(name: str) -> str:
    return (name or "").strip().strip(".").lower()


def resolve(host: str, timeout: float = 5.0) -> list[str]:
    """解析域名/IP 的 A 记录，失败返回空列表。"""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        return []


def enumerate_ct(domain: str, timeout: float = 20.0) -> set[str]:
    """从 crt.sh（证书透明日志）被动收集子域名。失败时抛异常，由调用方降级。"""
    domain = normalize(domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = json.loads(r.read().decode("utf-8", "replace"))
    names: set[str] = set()
    for row in raw:
        for n in re.split(r"[\s,]+", row.get("name_value", "")):
            n = normalize(n).lstrip("*.")
            if not n or not _NAME_RE.match(n):
                continue
            if n == domain or n.endswith("." + domain):
                names.add(n)
    return names


def discover_subdomains(domain: str, use_ct: bool = True, resolve_names: bool = True,
                        ct_timeout: float = 20.0) -> dict:
    """完整子域名发现流程。

    返回: {"domain": ..., "names": [..], "resolved": {name: [ips]},
           "ct_error": str|None}
    """
    domain = normalize(domain)
    names: set[str] = {domain}
    ct_error = None
    if use_ct:
        try:
            names |= enumerate_ct(domain, timeout=ct_timeout)
        except Exception as e:  # crt.sh 不可用时不阻塞流程
            ct_error = f"{type(e).__name__}: {e}"
    resolved: dict[str, list[str]] = {}
    for n in sorted(names):
        if resolve_names:
            ips = resolve(n)
            if ips:
                resolved[n] = ips
        else:
            resolved[n] = []
    return {"domain": domain, "names": sorted(names), "resolved": resolved,
            "ct_error": ct_error}

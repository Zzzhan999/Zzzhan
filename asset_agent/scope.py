"""授权范围控制：agent2 所有发现/验证动作的强制边界。

只有出现在范围文件里的域名（含子域名）、IP、CIDR 才允许探测；
越界目标抛出 OutOfScopeError，任何入口不得绕过。
"""

import ipaddress
import json
import os
from pathlib import Path

DEFAULT_SCOPE = str(Path(__file__).resolve().parent.parent / "data" / "scope.json")
ROOT_SCOPE = str(Path(__file__).resolve().parent.parent / "scope.json")


class OutOfScopeError(Exception):
    """目标不在授权范围内。"""


def _norm_host(host: str) -> str:
    """规范化主机名：去掉协议前缀、路径/查询、端口、首尾点。"""
    h = (host or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    # 去掉路径 / 查询 / 锚点
    for sep in ("/", "?", "#"):
        if sep in h:
            h = h.split(sep, 1)[0]
    # 去掉端口（IPv6 字面量除外）
    if ":" in h and not h.startswith("["):
        try:
            ipaddress.ip_address(h)
        except ValueError:
            h = h.split(":", 1)[0]
    return h.strip(".")


class Scope:
    """从 JSON 范围文件加载域名/IP/CIDR 白名单。"""

    def __init__(self, path: str | None = None):
        self.path = path or ""
        self.domains: set[str] = set()
        self.ips: set[str] = set()
        self.cidrs: list = []
        if path:
            self.load(path)

    def load(self, path: str):
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        self.path = path
        self.domains = {_norm_host(d) for d in data.get("domains", []) if _norm_host(d)}
        self.ips = set()
        self.cidrs = []
        for ip in data.get("ips", []):
            ip = (ip or "").strip()
            if not ip:
                continue
            try:
                self.ips.add(str(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        for c in data.get("cidrs", []):
            c = (c or "").strip()
            if not c:
                continue
            try:
                self.cidrs.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    @property
    def empty(self) -> bool:
        return not (self.domains or self.ips or self.cidrs)

    def in_scope(self, host: str) -> bool:
        """判断 host（域名或 IP）是否在授权范围内。"""
        h = _norm_host(host)
        if not h:
            return False
        # 尝试按 IP 判断
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            addr = None
        if addr is not None:
            if str(addr) in self.ips:
                return True
            return any(addr in net for net in self.cidrs)
        # 按域名判断：精确或子域名
        if h in self.domains:
            return True
        return any(h.endswith("." + d) for d in self.domains)

    def ensure(self, host: str):
        if not self.in_scope(host):
            raise OutOfScopeError(
                f"目标不在授权范围内: {host}（请先编辑 {self.path or 'scope.json'} 加入该目标）")

    def describe(self) -> str:
        parts = []
        if self.domains:
            parts.append("域名: " + ", ".join(sorted(self.domains)))
        if self.ips:
            parts.append("IP: " + ", ".join(sorted(self.ips)))
        if self.cidrs:
            parts.append("CIDR: " + ", ".join(str(c) for c in self.cidrs))
        return "; ".join(parts) if parts else "(空)"


def load_default() -> Scope:
    """按优先级加载范围：环境变量 AGENT2_SCOPE > data/scope.json > ./scope.json。"""
    env = os.environ.get("AGENT2_SCOPE")
    for p in (env, DEFAULT_SCOPE, ROOT_SCOPE):
        if p and os.path.exists(p):
            try:
                return Scope(p)
            except Exception:
                continue
    return Scope()


SCOPE_TEMPLATE = {
    "note": ("只允许扫描你拥有或已获书面授权的资产。未经授权扫描他人资产在多数司法辖区属于违法行为"
             "（中国大陆适用《网络安全法》《刑法》第285条）。把待测域名/IP/CIDR 填入下面三项即可。"),
    "domains": ["example.com"],
    "ips": ["203.0.113.10"],
    "cidrs": ["198.51.100.0/24"],
}


def write_template(path: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(SCOPE_TEMPLATE, f, ensure_ascii=False, indent=2)
    return str(p)

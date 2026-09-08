"""非破坏性安全检查：只读 GET/OPTIONS 探测 + 响应头/TLS 证书分析。

范围仅限：安全响应头缺失、常见暴露面端点、TRACE 方法、TLS 证书有效期。
所有探测均为只读请求，不携带任何载荷，不做任何写入/利用动作。
"""

import datetime
import re
import ssl

from ..discovery.fingerprint import http_probe, tls_probe

SECURITY_HEADERS = [
    ("strict-transport-security", "HTTP 严格传输安全 (HSTS)"),
    ("x-content-type-options", "MIME 类型嗅探防护"),
    ("x-frame-options", "点击劫持防护 (X-Frame-Options)"),
    ("content-security-policy", "内容安全策略 (CSP)"),
    ("referrer-policy", "Referrer 策略"),
]

# (路径, 说明, 触发状态码, 附加正文判断)
EXPOSED_PATHS = [
    ("/actuator/env", "Spring Actuator 环境信息端点", {200}, "actuator"),
    ("/.git/HEAD", "Git 源码目录", {200}, "git"),
    ("/phpinfo.php", "PHP 探针", {200}, "phpinfo"),
    ("/server-status", "Apache server-status", {200}, "apache"),
    ("/.env", "环境变量文件（可能含密钥）", {200}, ""),
    ("/backup.zip", "备份压缩包", {200}, ""),
    ("/admin/", "管理后台入口", {200, 401, 403}, ""),
    ("/swagger-ui.html", "Swagger API 文档", {200}, "swagger"),
    ("/robots.txt", "robots.txt 爬虫协议", {200}, ""),
]


def check_security_headers(headers: dict) -> tuple[str, str]:
    """返回 (status, detail)。headers 为小写 key 字典。"""
    missing = [(h, name) for h, name in SECURITY_HEADERS if h not in headers]
    if not missing:
        return "ok", "已配置全部 5 项常用安全响应头"
    names = ", ".join(f"{h}({name})" for h, name in missing)
    return "warning", f"缺失安全响应头: {names}"


def check_cookie_flags(headers: dict) -> tuple[str, str]:
    """检查 Set-Cookie 是否缺少 Secure / HttpOnly / SameSite 标志。"""
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return "info", "未设置 Cookie，无需检查"
    cookies = set_cookie.split(",") if "," in set_cookie else [set_cookie]
    # 拆分多个 Set-Cookie 头（可能有多个同名头，dict 只保留一个，这里按逗号粗拆）
    missing = set()
    analyzed = 0
    for c in cookies:
        c = c.strip()
        if not c or "=" not in c:
            continue
        analyzed += 1
        low = c.lower()
        if "secure" not in low:
            missing.add("Secure")
        if "httponly" not in low:
            missing.add("HttpOnly")
        if "samesite" not in low:
            missing.add("SameSite")
    if not analyzed:
        return "info", "未设置 Cookie，无需检查"
    if not missing:
        return "ok", "Cookie 已设置 Secure/HttpOnly/SameSite 标志"
    return "warning", f"Cookie 缺少安全标志: {', '.join(sorted(missing))}"


def classify_exposed(path: str, status: int, body: str) -> tuple[str, str]:
    """对单个暴露面端点的探测结果分类，返回 (status, detail)。"""
    body_l = (body or "").lower()
    if status == 200:
        if path == "/.git/HEAD":
            if "ref:" in body_l or "git" in body_l:
                return ("warning", "Git 源码目录可能暴露（/.git/HEAD 返回 200）")
            return ("info", "路径可访问")
        if path == "/phpinfo.php":
            if "phpinfo" in body_l:
                return ("warning", "PHP 探针 phpinfo 暴露")
            return ("info", "路径可访问")
        if path == "/server-status":
            if "apache" in body_l:
                return ("warning", "Apache server-status 可公开访问")
            return ("info", "路径可访问")
        if path == "/actuator/env":
            return ("warning", "Spring Actuator 环境信息端点可公开访问（可能泄露配置/密钥）")
        if path == "/.env":
            return ("warning", "环境变量文件 /.env 可公开下载（可能泄露数据库密码/密钥）")
        if path == "/backup.zip":
            return ("warning", "备份文件 /backup.zip 可公开下载（可能泄露源码/数据）")
        if path == "/admin/":
            return ("info", "管理后台入口可访问（需确认访问控制是否生效）")
        if path == "/swagger-ui.html":
            if "swagger" in body_l:
                return ("warning", "Swagger API 文档公开可见")
            return ("info", "路径可访问")
        if path == "/robots.txt":
            snippet = re.sub(r"\s+", " ", body_l).strip()[:120]
            return ("info", f"robots.txt 内容: {snippet or '(空)'}")
        return ("info", f"{path} 返回 200")
    if status in (401, 403):
        return ("info", f"{path} 存在但需认证（HTTP {status}）")
    return ("info", f"{path} 返回 HTTP {status}，未发现暴露")


def run_exposed(host: str, port: int, is_https: bool, timeout: float) -> list[dict]:
    """对常见暴露面端点做只读 GET 探测。"""
    out = []
    for path, desc, codes, _kw in EXPOSED_PATHS:
        r = http_probe(host, port, timeout=timeout, path=path, is_https=is_https)
        if r is None:
            continue
        status, detail = classify_exposed(path, r["status"], r["body"])
        # 只上报 warning 级别发现 + 管理入口/robots 这类 info
        if status == "warning" or path in ("/admin/", "/robots.txt"):
            out.append({"name": "exposed:" + path.lstrip("/"), "desc": desc,
                        "status": status, "detail": detail})
    return out


def check_trace(host: str, port: int, is_https: bool, timeout: float) -> tuple[str, str] | None:
    """检查是否允许 TRACE 方法（跨站追踪）。只发 OPTIONS。"""
    import http.client
    cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    try:
        conn = cls(host, port, timeout=timeout)
        conn.request("OPTIONS", "/", headers={"Host": host, "Connection": "close"})
        resp = conn.getresponse()
        allow = (resp.getheader("Allow") or "").upper()
        conn.close()
        if "TRACE" in allow:
            return "warning", "服务器允许 TRACE 方法（存在跨站追踪风险）"
        return "ok", "TRACE 方法未启用"
    except Exception:
        return None


def check_tls_cert(host: str, port: int, timeout: float) -> tuple[str, str] | None:
    """TLS 证书有效期检查。"""
    info = tls_probe(host, port, timeout=timeout)
    if not info.get("not_after"):
        return None
    try:
        not_after = datetime.datetime.strptime(info["not_after"], "%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return None
    now = datetime.datetime.utcnow()
    remain = (not_after - now).days
    cn = info.get("cn_list") or []
    cn_txt = f"CN={cn[0]}" if cn else "CN=?"
    if remain < 0:
        return "warning", f"证书已过期 {abs(remain)} 天 ({cn_txt})"
    if remain <= 30:
        return "warning", f"证书 {remain} 天后到期 ({cn_txt})"
    return "ok", f"证书有效期剩余 {remain} 天 ({cn_txt})"


def run_checks(host: str, port: int, service: str, http: dict | None,
               is_https: bool, timeout: float) -> list[dict]:
    """对单个服务执行全部非破坏性检查，返回 [{name, status, detail}]。"""
    out: list[dict] = []
    if http is not None and http.get("headers"):
        status, detail = check_security_headers(http["headers"])
        out.append({"name": "security_headers", "status": status, "detail": detail})
        status, detail = check_cookie_flags(http["headers"])
        if status != "info":
            out.append({"name": "cookie_flags", "status": status, "detail": detail})
        out.extend(run_exposed(host, port, is_https, timeout))
        tr = check_trace(host, port, is_https, timeout)
        if tr:
            out.append({"name": "http_trace", "status": tr[0], "detail": tr[1]})
    if is_https:
        tc = check_tls_cert(host, port, timeout)
        if tc:
            out.append({"name": "tls_cert", "status": tc[0], "detail": tc[1]})
    return out

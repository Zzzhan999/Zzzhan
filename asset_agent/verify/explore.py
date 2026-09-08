"""主动漏洞检测引擎（只读、非破坏、无利用载荷）。

输入：授权范围内的主机 + 已发现的 HTTP(S) 服务。
输出：结构化 findings（id/name/severity/evidence/remediation）。

检测项全部使用标准安全评估手法，仅包含：
  - 只读 GET / OPTIONS 请求（不含任何注入、爆破、利用载荷）
  - 响应头 / 响应体 / TLS 证书的静态分析
  - 探测路径均为安全业界公认的暴露面端点

severity 分级：CRITICAL / HIGH / MEDIUM / LOW / INFO
"""

import datetime
import re

from ..discovery.fingerprint import http_probe, tls_probe

# (路径, 名称, 触发条件)
# path 在探测清单里，body 命中关键字视为确认（防止软 404 误报）
PROBE_PATHS = [
    ("/actuator", "Spring Boot Actuator", ("actuator", "status", "health")),
    ("/actuator/env", "Spring Actuator /env", ("java", "systemproperties", "server.ports", "{")),
    ("/actuator/health", "Spring Actuator /health", ("status",)),
    ("/actuator/mappings", "Spring Actuator /mappings", ("mappings",)),
    ("/.git/HEAD", "Git 源码泄露", ("ref:",)),
    ("/.git/config", "Git 配置泄露", ("repositoryformatversion",)),
    ("/.svn/entries", "SVN 源码泄露", ("dir",)),
    ("/.env", "环境变量文件泄露", ("=",)),
    ("/.env.backup", "环境变量备份泄露", ("=",)),
    ("/backup.zip", "备份压缩包泄露", ("pk",)),
    ("/backup.tar.gz", "备份压缩包泄露", ("",)),
    ("/db.sqlite", "SQLite 数据库泄露", ("",)),
    ("/db.sqlite3", "SQLite 数据库泄露", ("",)),
    ("/dump.sql", "数据库导出文件泄露", ("create table", "insert into")),
    ("/phpinfo.php", "PHP 探针泄露", ("phpinfo",)),
    ("/server-status", "Apache 状态页", ("apache", "server")),
    ("/server-info", "Apache 配置页", ("apache", "server")),
    ("/admin/", "管理后台", ()),
    ("/admin", "管理后台", ()),
    ("/manager/html", "Tomcat 管理界面", ("tomcat",)),
    ("/console", "管理控制台", ("console",)),
    ("/swagger-ui.html", "Swagger API 文档", ("swagger",)),
    ("/swagger-ui/", "Swagger API 文档", ("swagger",)),
    ("/api-docs", "OpenAPI 文档", ("openapi", "swagger")),
    ("/robots.txt", "robots.txt", ()),
]

# 非 HTTP 服务的风险端口 → 风险说明
DB_PORTS = {
    3306: ("MySQL", "MySQL 数据库端口对外开放"),
    5432: ("PostgreSQL", "PostgreSQL 数据库端口对外开放"),
    1433: ("MSSQL", "MSSQL 数据库端口对外开放"),
    27017: ("MongoDB", "MongoDB 端口对外开放（默认无认证风险高）"),
    6379: ("Redis", "Redis 端口对外开放（默认无认证风险高）"),
    9200: ("Elasticsearch", "Elasticsearch HTTP 端口对外开放"),
    11211: ("Memcached", "Memcached 端口对外开放"),
    61616: ("ActiveMQ", "ActiveMQ 端口对外开放"),
    7001: ("WebLogic", "WebLogic 管理端口对外开放"),
    4848: ("GlassFish", "GlassFish 管理端口对外开放"),
    2222: ("SSH 备选", "SSH 端口对外开放"),
}

REM = {
    "actuator": "关闭生产环境 Actuator 端点，或配置 Spring Security 鉴权并仅限内网访问",
    "git": "从 Web 根目录移除 .git 目录，并在服务器配置中禁止访问隐藏文件",
    "svn": "从 Web 根目录移除 .svn 目录",
    "env": "环境变量文件禁止放入 Web 可访问目录，密钥改用安全配置中心",
    "backup": "移除 Web 目录下的备份文件，备份应存放于不可 Web 访问的位置",
    "db": "数据库文件禁止放入 Web 可访问目录",
    "phpinfo": "移除生产环境的 phpinfo 探针文件",
    "apache_status": "限制 /server-status、/server-info 仅内网 IP 访问",
    "admin": "管理后台应启用强认证、限制来源 IP，并对未授权访问做拦截",
    "swagger": "生产环境关闭 API 文档或加访问鉴权",
    "dir_listing": "关闭 Web 服务器的目录列表（Apache Options -Indexes / Nginx autoindex off）",
    "cors": "配置 CORS 白名单，禁止反射任意 Origin（Access-Control-Allow-Origin 不回显来源）",
    "trace": "禁用 TRACE 方法（Nginx proxy 去除 / Apache TraceEnable Off）",
    "headers": "按需补齐安全响应头（HSTS/X-Content-Type-Options/X-Frame-Options/CSP/Referrer-Policy）",
    "cookie": "Set-Cookie 添加 Secure、HttpOnly、SameSite 标志",
    "version": "隐藏 Server / X-Powered-By 等版本信息头，避免为攻击者提供指纹",
    "tls": "更新/续期 TLS 证书，并确保部署完整证书链",
    "db_port": "数据库/中间件端口仅对内网开放，禁止暴露公网；如必须暴露则启用强认证与访问控制",
}


def _ver(sev: str, name: str, evidence: str, check: str,
         remediation: str = "") -> dict:
    return {"check_id": check, "name": name, "severity": sev,
            "evidence": evidence, "remediation": remediation or REM.get(check, "")}


def _looks_like_404(status: int, body: str) -> bool:
    """软 404 识别：状态 200 但正文是 404 页则视为不存在。"""
    if status != 200:
        return False
    b = (body or "").lower()
    hits = sum(1 for k in ("404 not found", "页面不存在", "无法找到",
                           "not found", "<title>404") if k in b)
    return hits >= 2


def probe_http(host: str, port: int, is_https: bool, timeout: float) -> list[dict]:
    """对 HTTP(S) 服务执行只读路径探测，返回 findings。"""
    out: list[dict] = []
    for path, name, keys in PROBE_PATHS:
        try:
            r = http_probe(host, port, timeout=timeout, path=path, is_https=is_https)
        except Exception:
            continue
        if r is None:
            continue
        status, body = r["status"], (r["body"] or "")
        body_l = body.lower()
        if _looks_like_404(status, body_l):
            continue
        # 分类判定
        if path.startswith("/actuator"):
            if status == 200 and (not keys or any(k in body_l for k in keys)):
                sev = "HIGH" if path in ("/actuator/env", "/actuator/mappings") else "MEDIUM"
                out.append(_ver(sev, f"{name} 未授权访问", f"GET {path} -> HTTP {status}，"
                                f"响应含敏感内容（{len(body)} 字节）", "actuator"))
        elif path in ("/.git/HEAD", "/.git/config"):
            if status == 200 and any(k in body_l for k in keys):
                out.append(_ver("HIGH", f"{name}（/ 根目录）", f"GET {path} -> HTTP {status}: "
                                f"{re.sub(r'\\s+', ' ', body[:80])}", "git"))
        elif path == "/.svn/entries":
            if status == 200 and any(k in body_l for k in keys):
                out.append(_ver("MEDIUM", "SVN 源码泄露", f"GET {path} -> HTTP {status}", "svn"))
        elif path in ("/.env", "/.env.backup"):
            if status == 200 and "=" in body:
                snippet = re.sub(r"[\r\n]+", " | ", body[:120])
                out.append(_ver("HIGH", f"{name}（可能含密钥）", f"GET {path} -> HTTP {status}: "
                                f"{snippet}", "env"))
        elif path in ("/backup.zip", "/backup.tar.gz", "/db.sqlite", "/db.sqlite3",
                      "/dump.sql"):
            if status == 200 and (not keys or any(k in body_l for k in keys)):
                out.append(_ver("HIGH", f"{name}（可下载）", f"GET {path} -> HTTP {status}，"
                                f"返回 {len(body)} 字节数据", "backup" if "backup" in path
                                else "db"))
        elif path == "/phpinfo.php":
            if status == 200 and "phpinfo" in body_l:
                out.append(_ver("MEDIUM", "PHP 探针 phpinfo 暴露",
                                f"GET {path} -> HTTP {status}", "phpinfo"))
        elif path in ("/server-status", "/server-info"):
            if status == 200 and any(k in body_l for k in keys):
                out.append(_ver("MEDIUM", "Apache 状态/配置页公开",
                                f"GET {path} -> HTTP {status}", "apache_status"))
        elif path in ("/admin/", "/admin"):
            if status in (200, 401, 403):
                sev = "MEDIUM" if status == 200 else "LOW"
                out.append(_ver(sev, "管理后台入口暴露", f"GET {path} -> HTTP {status}",
                                "admin"))
        elif path == "/manager/html":
            if status in (200, 401, 403):
                out.append(_ver("MEDIUM", "Tomcat 管理界面暴露",
                                f"GET {path} -> HTTP {status}", "admin"))
        elif path in ("/console",):
            if status in (200, 401, 403):
                out.append(_ver("MEDIUM", "管理控制台暴露", f"GET {path} -> HTTP {status}",
                                "admin"))
        elif "swagger" in path or path == "/api-docs":
            if status == 200 and any(k in body_l for k in keys):
                out.append(_ver("MEDIUM", "API 文档公开可见", f"GET {path} -> HTTP {status}",
                                "swagger"))
        elif path == "/robots.txt":
            if status == 200 and body.strip():
                disallow = [ln.split(":", 1)[1].strip() for ln in body.splitlines()
                            if ln.lower().startswith("disallow") and ln.split(":", 1)[1].strip()]
                if disallow:
                    out.append(_ver("INFO", "robots.txt 含敏感路径",
                                    f"GET {path} -> Disallow: {', '.join(disallow[:6])}",
                                    ""))
    return out


def check_cors(host: str, port: int, is_https: bool, timeout: float) -> dict | None:
    """CORS 配置检查：发送可疑 Origin，看 ACAO 是否反射。只读 GET。"""
    import http.client
    cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    try:
        conn = cls(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host, "Origin": "https://evil.example",
                                          "Connection": "close"})
        resp = conn.getresponse()
        acao = resp.getheader("Access-Control-Allow-Origin", "")
        acac = resp.getheader("Access-Control-Allow-Credentials", "").lower()
        conn.close()
        if not acao:
            return None
        if acao == "*":
            return _ver("LOW", "CORS 配置宽松（ACAO:*）",
                        "响应头 Access-Control-Allow-Origin: *", "cors")
        if "evil.example" in acao and acac == "true":
            return _ver("HIGH", "CORS 反射任意 Origin 且允许携带凭证",
                        "Origin: https://evil.example -> ACAO 反射且 Allow-Credentials: true",
                        "cors")
        if "evil.example" in acao:
            return _ver("MEDIUM", "CORS 反射任意 Origin",
                        "Origin: https://evil.example 被原样反射", "cors")
        return None
    except Exception:
        return None


def check_dir_listing(host: str, port: int, is_https: bool, timeout: float) -> dict | None:
    """目录列表检查：GET / 看是否返回 Index of。只读 GET。"""
    try:
        r = http_probe(host, port, timeout=timeout, path="/", is_https=is_https)
    except Exception:
        return None
    if r is None:
        return None
    body_l = (r["body"] or "").lower()
    if re.search(r"<title>index of[^<]*</title>", body_l) or body_l.startswith("index of /"):
        return _ver("MEDIUM", "Web 目录列表开启（信息泄露）",
                    "GET / 返回目录索引（Index of /）", "dir_listing")
    return None


def analyze_headers(headers: dict, body: str = "") -> list[dict]:
    """响应头静态分析：安全头缺失 / Cookie 标志 / 版本泄露。"""
    out: list[dict] = []
    h = headers or {}
    missing = [n for n in ("strict-transport-security", "x-content-type-options",
                           "x-frame-options", "content-security-policy",
                           "referrer-policy") if n not in h]
    if missing:
        out.append(_ver("LOW", "安全响应头缺失",
                        "缺失: " + ", ".join(missing), "headers"))
    sc = h.get("set-cookie", "")
    if sc:
        low = sc.lower()
        miss = [f for f in ("Secure", "HttpOnly", "SameSite") if f.lower() not in low]
        if miss:
            out.append(_ver("LOW", "Cookie 缺少安全标志",
                            f"Set-Cookie 缺少 {', '.join(miss)}", "cookie"))
    for k in ("server", "x-powered-by"):
        v = h.get(k, "")
        if v and re.search(r"\d+\.\d+", v):
            out.append(_ver("INFO", f"{k} 头泄露版本信息", f"{k}: {v[:60]}", "version"))
    return out


def check_tls_finding(host: str, port: int, timeout: float) -> dict | None:
    """TLS 证书有效期。"""
    try:
        info = tls_probe(host, port, timeout=timeout)
    except Exception:
        return None
    if not info.get("not_after"):
        return None
    try:
        na = datetime.datetime.strptime(info["not_after"], "%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return None
    remain = (na - datetime.datetime.utcnow()).days
    cn = (info.get("cn_list") or [None])[0]
    cn_txt = f"CN={cn}" if cn else "CN=?"
    if remain < 0:
        return _ver("MEDIUM", "TLS 证书已过期", f"证书 {abs(remain)} 天前过期 ({cn_txt})",
                    "tls")
    if remain <= 30:
        return _ver("LOW", "TLS 证书即将过期", f"证书 {remain} 天后到期 ({cn_txt})", "tls")
    return None


def scan_service(host: str, port: int, service: str, is_https: bool,
                 timeout: float, http: dict | None = None) -> list[dict]:
    """对单个服务执行全部主动检测，返回 findings。"""
    findings: list[dict] = []
    http = http or {}
    hdrs = (http.get("headers") or {}) if http else {}

    if hdrs:
        findings.extend(analyze_headers(hdrs))
    if is_https:
        t = check_tls_finding(host, port, timeout)
        if t:
            findings.append(t)

    probe_hit = probe_http(host, port, is_https, timeout)
    findings.extend(probe_hit)
    c = check_cors(host, port, is_https, timeout)
    if c:
        findings.append(c)
    d = check_dir_listing(host, port, is_https, timeout)
    if d:
        findings.append(d)

    # 去重：相同 check_id + evidence 前缀
    seen = set()
    uniq = []
    for f in findings:
        key = (f["check_id"], f["name"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq


def scan_db_port(port: int) -> dict | None:
    """数据库/中间件风险端口提示（只读判断，不连接）。"""
    info = DB_PORTS.get(port)
    if not info:
        return None
    name, desc = info
    return _ver("LOW" if name in ("SSH 备选",) else "MEDIUM",
                f"{name} 端口对外开放", f"端口 {port} 对外开放（{desc}）", "db_port")


def run_explore(db, timeout: float = 6.0, services=None) -> list[dict]:
    """对库内全部服务执行主动漏洞检测，写入 findings 表并返回。"""
    from ..discovery import fingerprint as fp_mod
    if services is None:
        services = db.list_services()
    host_map = {h["id"]: h for h in db.list_hosts()}
    all_findings: list[dict] = []
    for sv in services:
        h = host_map.get(sv["host_id"], {})
        target = h.get("ip") or h.get("host") or sv["ip"]
        is_https = sv["service"] in ("https", "https-alt", "ssl") or sv["port"] in (443, 8443)
        findings: list[dict] = []
        if is_https or sv["http_status"] is not None:
            # 重新做一次轻量探测（保证数据新鲜）
            try:
                probe = fp_mod.http_probe(target, sv["port"], timeout=timeout,
                                          is_https=is_https)
            except Exception:
                probe = None
            findings = scan_service(target, sv["port"], sv["service"], is_https,
                                    timeout, probe or {})
        else:
            dp = scan_db_port(sv["port"])
            if dp:
                findings = [dp]
        for f in findings:
            db.add_finding(sv["host_id"], sv["id"], f["check_id"], f["name"],
                           f["severity"], f["evidence"], f["remediation"])
        all_findings.extend(findings)
    return all_findings

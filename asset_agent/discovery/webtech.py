"""Web 技术栈识别：从响应头、页面标题/内容、Banner 中识别产品与版本。

产品名统一为 CPE 风格（vendor:product），与 agent1 漏洞库
affected_products / cpes_json 的词汇对齐（下划线归一化后可比）。
"""

import re

# ---- 响应头规则：Server / X-Powered-By / X-Generator / Set-Cookie ----
_HEADER_RULES = [
    # (产品, 厂商, 正则, 版本分组, 来源头)
    ("nginx", "nginx", r"\bnginx(?:/([\d.]+(?:-[a-z0-9.]+)?))?", 1, "server"),
    ("apache http server", "apache", r"\bApache(?:/([\d.]+))?", 1, "server"),
    ("microsoft iis", "microsoft", r"\bMicrosoft-IIS/([\d.]+)", 1, "server"),
    ("apache tomcat", "apache", r"\b(?:Apache-Coyote|Tomcat)(?:/([\d.]+))?", 1, "server"),
    ("openresty", "openresty", r"\bopenresty(?:/([\d.]+))?", 1, "server"),
    ("caddy", "caddy", r"\bCaddy(?:/([\d.]+))?", 1, "server"),
    ("lighttpd", "lighttpd", r"\blighttpd/([\d.]+)", 1, "server"),
    ("jetty", "eclipse", r"\bJetty\(([\d.]+)", 1, "server"),
    ("gunicorn", "gunicorn", r"\bgunicorn(?:/([\d.]+))?", 1, "server"),
    ("spring boot", "pivotal", r"\bSpring Boot(?:[^\d]*([\d.]+))?", 1, "server"),
    ("apache tomcat", "apache", r"\bApache-Coyote/([\d.]+)", 1, "server"),
    ("zabbix", "zabbix", r"\bZabbix(?:/([\d.]+))?", 1, "server"),
    ("gitlab", "gitlab", r"\bGitLab(?:/([\d.]+))?", 1, "server"),
    ("caddy", "caddy", r"\bCaddy(?:/([\d.]+))?", 1, "server"),
    ("php", "php", r"\bPHP/([\d.]+(?:\.[\d.]+)?)", 1, "x-powered-by"),
    ("microsoft asp.net", "microsoft", r"\bASP\.NET(?:/([\d.]+))?", 1, "x-powered-by"),
    ("wordpress", "wordpress", r"\bWordPress\s*[/ ]?([\d.]+)?", 1, "x-generator"),
    ("drupal", "drupal", r"\bDrupal\s*([\d.]+)?", 1, "x-generator"),
    ("joomla", "joomla", r"\bJoomla!?\s*([\d.]+)?", 1, "x-generator"),
    ("gitlab", "gitlab", r"\bGitLab", None, "x-gitlab-meta"),
]

_COOKIE_RULES = [
    ("php", "php", r"\bPHPSESSID\b", None, "cookie"),
    ("apache tomcat", "apache", r"\bJSESSIONID\b", None, "cookie"),
    ("microsoft asp.net", "microsoft", r"\bASP\.NET_SessionId\b", None, "cookie"),
    ("django", "djangoproject", r"\bdj[A-Za-z0-9_]+\b", None, "cookie"),
    ("laravel", "laravel", r"\bXSRF-TOKEN\b", None, "cookie"),
]

# ---- 页面内容规则 ----
_BODY_RULES = [
    ("wordpress", "wordpress", r'<meta\s+name="generator"\s+content="WordPress\s*([\d.]+)?"', 1),
    ("wordpress", "wordpress", r"/wp-content/", None),
    ("wordpress", "wordpress", r"/wp-json/", None),
    ("drupal", "drupal", r'<meta\s+name="generator"\s+content="Drupal\s*([\d.]+)?"', 1),
    ("joomla", "joomla", r"/media/system/js/", None),
    ("phpmyadmin", "phpmyadmin", r"phpMyAdmin", None),
    ("apache tomcat", "apache", r"/manager/html", None),
    ("jenkins", "jenkins", r"Jenkins", None),
    ("thinkphp", "thinkphp", r'<a[^>]*href="https?://www\.thinkphp\.cn[^"]*"[^>]*>ThinkPHP', None),
    ("thinkphp", "thinkphp", r"thinkphp", None),
    ("discuz", "discuz", r'Powered by Discuz!?\s*(X\d+(?:\.\d+)?)?', 1),
    ("zentao", "zentao", r"ZenTao|禅道", None),
    ("grafana", "grafana", r'<title>Grafana</title>', None),
    ("gitlab", "gitlab", r'<meta[^>]+content="GitLab(?:[^"]*)"', None),
    ("zabbix", "zabbix", r'<title>Zabbix[^<]*</title>', None),
    ("nacos", "nacos", r"Nacos", None),
    ("druid", "alibaba", r"Druid", None),
    ("swagger ui", "swagger", r'id="swagger-ui"', None),
    ("kong", "kong", r"Kong Gateway", None),
    ("minio", "minio", r"MinIO", None),
    ("django", "djangoproject", r"django\.core|CSRF verification failed", None),
    ("spring boot", "pivotal", r"Whitelabel Error Page", None),
    ("spring framework", "pivotal", r"Spring Framework", None),
]

# ---- Banner 规则（SSH/FTP/SMTP/数据库等非 HTTP 服务）----
_BANNER_RULES = [
    ("openssh", "openbsd", r"OpenSSH[_-]([\d.]+p?\d*)", 1),
    ("vsftpd", "vsftpd", r"vsFTPd\s*([\d.]+)?", 1),
    ("proftpd", "proftpd", r"ProFTPD\s*([\d.]+)?", 1),
    ("pure-ftpd", "pureftpd", r"Pure-FTPd", None),
    ("postfix", "postfix", r"ESMTP\s+Postfix", None),
    ("exim", "exim", r"Exim\s*([\d.]+)?", 1),
    ("microsoft smtp", "microsoft", r"Microsoft ESMTP", None),
    ("mysql", "mysql", r"mysql\s+Ver\s+[\d.]+\s+Distrib\s+([\d.]+)", 1),
    ("mysql", "mysql", r"Server version:\s*([\d.-]+)", 1),
    ("postgresql", "postgresql", r"PostgreSQL\s*([\d.]+)", 1),
    ("redis", "redis", r"redis_version:([\d.]+)", 1),
    ("mongodb", "mongodb", r"MongoDB\s*([\d.]+)?", 1),
    ("elasticsearch", "elasticsearch", r'"number"\s*:\s*"([\d.]+)"', 1),
    ("vsftpd", "vsftpd", r"vsFTPd", None),
    ("nginx", "nginx", r"nginx/([\d.]+)", 1),
    ("apache http server", "apache", r"Apache/([\d.]+)", 1),
    ("samba", "samba", r"Samba\s*([\d.]+)?", 1),
    ("memcached", "memcached", r"memcached", None),
    ("docker", "docker", r"Docker\s*([\d.]+)?", 1),
    ("zookeeper", "apache", r"ZooKeeper", None),
    ("kafka", "apache", r"kafka", None),
]


def _norm(s: str) -> str:
    return (s or "").lower().strip()


def _match_rules(header_value: str, rules) -> list[dict]:
    out = []
    for product, vendor, pattern, group, source in rules:
        if not header_value:
            continue
        m = re.search(pattern, header_value, re.I)
        if m:
            ver = ""
            if group is not None:
                try:
                    ver = m.group(group) or ""
                except IndexError:
                    ver = ""
            out.append({"product": product, "vendor": vendor, "version": ver,
                        "source": source})
    return out


def detect_http(headers: dict) -> list[dict]:
    """从 HTTP 响应头识别产品。headers 为小写 key 字典。"""
    out: list[dict] = []
    # 按来源头分组应用规则
    for hkey in ("server", "x-powered-by", "x-generator", "x-gitlab-meta"):
        hv = headers.get(hkey, "")
        if not hv:
            continue
        for item in _match_rules(hv, [r for r in _HEADER_RULES if r[4] == hkey]):
            out.append(item)
    hv = headers.get("set-cookie", "")
    for item in _match_rules(hv, _COOKIE_RULES):
        out.append(item)
    return out


def detect_body(body: str) -> list[dict]:
    """从页面内容识别产品。"""
    out = []
    for product, vendor, pattern, group in _BODY_RULES:
        m = re.search(pattern, body or "", re.I)
        if m:
            ver = m.group(group) if (group and m.lastindex and m.group(group)) else ""
            out.append({"product": product, "vendor": vendor, "version": ver,
                        "source": "body"})
    return out


def detect_banner(banner: str) -> list[dict]:
    """从 TCP banner 识别产品（SSH/FTP/SMTP/数据库等）。"""
    out = []
    for product, vendor, pattern, group in _BANNER_RULES:
        m = re.search(pattern, banner or "", re.I)
        if m:
            ver = ""
            if group is not None:
                try:
                    ver = m.group(group) or ""
                except IndexError:
                    ver = ""
            out.append({"product": product, "vendor": vendor, "version": ver,
                        "source": "banner"})
    return out


def dedupe(items: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for it in items:
        key = (_norm(it["product"]), _norm(it["version"]))
        if key not in seen:
            seen[key] = dict(it)
    return list(seen.values())


def detect_all(headers: dict | None = None, body: str = "",
               banner: str = "") -> list[dict]:
    """综合识别，去重后返回 [{product, vendor, version, source}]。"""
    items: list[dict] = []
    if headers:
        items += detect_http(headers)
    items += detect_body(body)
    items += detect_banner(banner)
    return dedupe(items)

"""服务指纹识别：Banner 抓取 + HTTP 响应头/标题 + TLS 证书信息。

全部为只读探测：不发送攻击载荷，不做破坏性操作。
"""

import http.client
import re
import socket
import ssl
import urllib.parse

UA = "Mozilla/5.0 (compatible; AssetAgent2/0.1; +security research on authorized assets)"

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def grab_banner(host: str, port: int, timeout: float = 5.0) -> str:
    """抓取服务 banner（被动读取，不主动发送内容）。"""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return ""
    s.settimeout(timeout)
    try:
        data = s.recv(4096)
        return data.decode("utf-8", "replace").strip()[:2000]
    except OSError:
        return ""
    finally:
        s.close()


def http_probe(host: str, port: int, timeout: float = 6.0, path: str = "/",
               is_https: bool = False) -> dict | None:
    """HTTP(S) GET 探测，返回状态/响应头/标题/正文片段。失败返回 None。"""
    path = path or "/"
    cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
    conn = None
    try:
        conn = cls(host, port, timeout=timeout)
        conn.request("GET", path, headers={
            "Host": host,
            "User-Agent": UA,
            "Accept": "*/*",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read(8192).decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        m = _TITLE_RE.search(body)
        return {
            "status": resp.status,
            "headers": headers,
            "title": m.group(1).strip()[:500] if m else "",
            "body": body[:4000],
        }
    except Exception:
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---- TLS 证书信息（最小 DER 解析，零第三方依赖）----

_UTCTIME_RE = re.compile(rb"[\x17\x18]\x0f([0-9]{12,15}Z)")
_CN_OID = b"\x06\x03\x55\x04\x03"


def _fmt_utc(s: str) -> str:
    """把 20260905120000Z / 260905120000Z 转成 YYYY-MM-DD HH:MM:SS UTC。"""
    s = s[:-1]  # 去掉 Z
    if len(s) == 12:  # UTCTime YYMMDDHHMMSS
        yy = int(s[:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        s = f"{year:04d}" + s[2:]
    if len(s) != 14:
        return s
    return f"{s[:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]} UTC"


def _extract_cert_info(der: bytes) -> dict:
    out = {"not_before": "", "not_after": "", "cn_list": []}
    if not der:
        return out
    times = []
    for m in _UTCTIME_RE.finditer(der):
        try:
            times.append(_fmt_utc(m.group(1).decode()))
        except Exception:
            continue
    if times:
        out["not_before"] = times[0]
        out["not_after"] = times[-1]
    idx = 0
    while True:
        i = der.find(_CN_OID, idx)
        if i < 0:
            break
        pos = i + len(_CN_OID)
        if pos + 1 >= len(der):
            break
        tag = der[pos]
        ln = der[pos + 1]
        if tag in (0x0C, 0x13) and 0 < ln < 128 and pos + 2 + ln <= len(der):
            try:
                out["cn_list"].append(der[pos + 2:pos + 2 + ln].decode("utf-8", "replace"))
            except Exception:
                pass
            idx = pos + 2 + ln
        else:
            idx = pos + 1
    return out


def tls_probe(host: str, port: int, timeout: float = 6.0) -> dict:
    """TLS 握手探测：版本、密码套件、证书有效期与 CN。"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            info = {"tls_version": s.version()}
            try:
                info["cipher"] = s.cipher()[0] if s.cipher() else ""
            except Exception:
                info["cipher"] = ""
            try:
                der = s.getpeercert(binary_form=True) or b""
                info.update(_extract_cert_info(der))
            except Exception:
                pass
            return info
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def fingerprint_service(host: str, port: int, service: str = "",
                        timeout: float = 6.0) -> dict:
    """对单个开放端口做完整指纹，返回统一结构。"""
    fp = {"port": port, "service": service or "", "banner": "",
          "http": None, "tls": None}
    fp["banner"] = grab_banner(host, port, timeout=timeout)

    # HTTP/HTTPS 探测（端口常见服务为 http/https 或 banner 像 HTTP）
    banner_l = fp["banner"].lower()
    is_https = service in ("https", "https-alt", "ssl", "rdp") or port in (443, 8443)
    looks_http = service in ("http", "http-proxy", "http-alt", "ajp") or \
        banner_l.startswith("http/") or ("<!doctype" in banner_l or "<html" in banner_l)
    if is_https or looks_http or not service:
        fp["http"] = http_probe(host, port, timeout=timeout, is_https=is_https)
    if is_https:
        fp["tls"] = tls_probe(host, port, timeout=timeout)
    return fp

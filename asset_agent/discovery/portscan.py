"""TCP 端口扫描（connect 式，多线程）。

仅做 TCP 连接探测，不发送任何攻击载荷。用于对**已授权**资产建立
开放端口清单。扫描强度默认保守（低并发 + 短超时）。
"""

import concurrent.futures
import socket

# 常见端口 -> 猜测服务名（用于报告展示，最终以指纹为准）
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 514: "syslog", 587: "smtp",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker",
    3000: "http", 3128: "squid", 3306: "mysql", 3389: "rdp", 4369: "rabbitmq",
    5000: "http", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    7001: "weblogic", 8000: "http", 8009: "ajp", 8080: "http", 8081: "http",
    8088: "http", 8443: "https", 8888: "http", 9000: "http", 9090: "http",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq", 27017: "mongodb", 5601: "kibana", 6379: "redis",
}


def guess_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "")


def parse_ports(spec: str) -> list[int]:
    """解析端口串："80,443,8000-8100" -> 去重排序的端口列表。"""
    if not spec:
        raise ValueError("端口参数为空")
    ports: set[int] = set()
    for part in str(spec).replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"非法端口范围: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 0 < p <= 65535:
                raise ValueError(f"非法端口: {part}")
            ports.add(p)
    if not ports:
        raise ValueError("端口参数为空")
    return sorted(ports)


def _try_connect(host: str, port: int, timeout: float) -> int | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return port
    except OSError:
        return None
    finally:
        s.close()


def scan_host(host: str, ports: list[int], timeout: float = 2.0,
              workers: int = 200) -> list[dict]:
    """扫描单台主机，返回 [{"port":.., "service":..}]（开放端口）。"""
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_try_connect, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            p = futs[fut]
            try:
                if fut.result() is not None:
                    results.append({"port": p, "service": guess_service(p)})
            except Exception:
                continue
    results.sort(key=lambda d: d["port"])
    return results


def scan_hosts(hosts: list[str], ports: list[int], timeout: float = 2.0,
               workers: int = 200) -> dict[str, list[dict]]:
    """扫描多台主机，返回 {host: [{"port":.., "service":..}]}。"""
    out: dict[str, list[dict]] = {}
    for h in hosts:
        try:
            out[h] = scan_host(h, ports, timeout=timeout, workers=workers)
        except OSError as e:
            out[h] = []
            out[h + ":error"] = [{"error": str(e)}]
    return out

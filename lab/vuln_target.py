"""实操演示靶机：本地模拟一个存在多处配置漏洞的 Web 服务 + 模拟 Redis 端口。

仅监听 127.0.0.1 回环地址，用于演示 agent2 的 scan 自动扫描。
"""

import http.server
import socket
import threading


class VulnWeb(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path
        body = b""
        if p == "/.git/HEAD":
            body = b"ref: refs/heads/main\n"
        elif p == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n\t[remote \"origin\"]\n"
        elif p == "/actuator/env":
            body = b'{"systemProperties":{"java.version":"17.0.8"},"spring.datasource.url":"jdbc:mysql://db.internal:3306/prod"}'
        elif p == "/actuator/health":
            body = b'{"status":"UP","components":{"db":{"status":"UP"}}}'
        elif p == "/actuator/mappings":
            body = b'{"contexts":{"application":{"mappings":{"dispatcherServlets":{"DispatcherServlet":["/api/user","/admin/*"]}}}}}'
        elif p == "/.env":
            body = b"APP_ENV=production\nDB_PASSWORD=Prod!2026@Secret\nAPI_KEY=sk-live-9f8a7b6c"
        elif p == "/backup.zip":
            body = b"PK\x03\x04" + b"\x00" * 200 + b"backup of /var/www/html"
        elif p == "/phpinfo.php":
            body = b"<title>phpinfo()</title><h1>PHP Version 8.1.2</h1><table><tr><td>allow_url_include</td><td>Off</td></tr></table>"
        elif p == "/admin/":
            body = b"<html><head><title>Admin Dashboard</title></head><body>login form</body></html>"
        elif p == "/swagger-ui.html":
            body = b'<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>'
        elif p == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin/\nDisallow: /api/internal\nDisallow: /.git/"
        elif p == "/":
            body = b"<html><head><title>Index of /</title></head><body><h1>Index of /</h1><a href=\"/.git/\">.git/</a></body></html>"
        else:
            body = b"<html><head><title>404 Not Found</title></head><body>Not Found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def start_redis_fake(port=6379):
    """模拟 Redis：返回带版本号的 banner，仅监听回环。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(5)

    def handle(c):
        try:
            c.sendall(b"-ERR unknown command\r\n")
        finally:
            c.close()

    def loop():
        while True:
            try:
                conn, _ = s.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except OSError:
                break
    threading.Thread(target=loop, daemon=True).start()
    return s


if __name__ == "__main__":
    web = http.server.ThreadingHTTPServer(("127.0.0.1", 8101), VulnWeb)
    redis = start_redis_fake(6379)
    print("[靶机] 漏洞 Web 服务: http://127.0.0.1:8101")
    print("[靶机] 模拟 Redis 端口: 127.0.0.1:6379")
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        web.server_close()
        redis.close()

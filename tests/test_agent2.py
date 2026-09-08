"""AssetAgent2 单元测试。

运行: python -m unittest discover -s tests -v
覆盖：范围控制、端口解析、版本比较/范围、CPE 匹配、指纹识别、
DB CRUD、风险评分、报告生成、暴露面分类。
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asset_agent import db as db_mod
from asset_agent import export as export_mod
from asset_agent.discovery import portscan, webtech
from asset_agent.scope import Scope, OutOfScopeError
from asset_agent.verify import matcher, risk
from asset_agent.verify.checks import (
    check_security_headers, check_cookie_flags, classify_exposed,
)
from asset_agent.verify import explore


class TestScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"domains": ["example.com", "corp.cn"],
                   "ips": ["203.0.113.10"],
                   "cidrs": ["198.51.100.0/24"]}, self.tmp)
        self.tmp.close()
        self.scope = Scope(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_domain_in(self):
        self.assertTrue(self.scope.in_scope("example.com"))
        self.assertTrue(self.scope.in_scope("www.example.com"))
        self.assertTrue(self.scope.in_scope("a.b.example.com"))
        self.assertTrue(self.scope.in_scope("CORP.CN"))

    def test_domain_out(self):
        self.assertFalse(self.scope.in_scope("example.org"))
        self.assertFalse(self.scope.in_scope("notexample.com"))
        self.assertFalse(self.scope.in_scope("example.com.evil.net"))

    def test_ip_and_cidr(self):
        self.assertTrue(self.scope.in_scope("203.0.113.10"))
        self.assertTrue(self.scope.in_scope("198.51.100.7"))
        self.assertFalse(self.scope.in_scope("203.0.113.11"))
        self.assertFalse(self.scope.in_scope("198.51.101.7"))

    def test_port_stripped(self):
        self.assertTrue(self.scope.in_scope("example.com:443"))
        self.assertTrue(self.scope.in_scope("https://www.example.com/"))

    def test_ensure_raises(self):
        with self.assertRaises(OutOfScopeError):
            self.scope.ensure("evil.com")


class TestPortParse(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(portscan.parse_ports("80,443"), [80, 443])

    def test_range(self):
        self.assertEqual(portscan.parse_ports("8000-8002"), [8000, 8001, 8002])

    def test_mixed_dedupe(self):
        self.assertEqual(portscan.parse_ports("80,80,443,8000-8001"), [80, 443, 8000, 8001])

    def test_invalid(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("70000")
        with self.assertRaises(ValueError):
            portscan.parse_ports("abc")

    def test_guess_service(self):
        self.assertEqual(portscan.guess_service(22), "ssh")
        self.assertEqual(portscan.guess_service(3306), "mysql")
        self.assertEqual(portscan.guess_service(9999), "")


class TestVersion(unittest.TestCase):
    def test_cmp(self):
        a = matcher._parse_version("1.24.0")
        b = matcher._parse_version("2.0.1")
        self.assertEqual(matcher._cmp_version(a, b), -1)
        self.assertEqual(matcher._cmp_version(b, a), 1)
        self.assertEqual(matcher._cmp_version(a, matcher._parse_version("1.24.0")), 0)

    def test_range(self):
        d = {"version": "*", "vs": "1.0", "ve": "1.5", "vs_ex": "", "ve_ex": ""}
        self.assertTrue(matcher._version_in_range("1.2", d))
        self.assertFalse(matcher._version_in_range("1.6", d))
        self.assertTrue(matcher._version_in_range("1.5", d))  # <= ve

    def test_range_excluding(self):
        d = {"version": "*", "vs": "", "ve": "", "vs_ex": "1.0", "ve_ex": "1.5"}
        self.assertTrue(matcher._version_in_range("1.2", d))
        self.assertFalse(matcher._version_in_range("1.0", d))
        self.assertFalse(matcher._version_in_range("1.5", d))

    def test_exact_version(self):
        d = {"version": "7.2.0", "vs": "", "ve": "", "vs_ex": "", "ve_ex": ""}
        self.assertTrue(matcher._version_in_range("7.2.0", d))
        self.assertFalse(matcher._version_in_range("7.2.1", d))


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.vuln_db = os.path.join(self.tmpdir, "vulns.db")
        conn = sqlite3.connect(self.vuln_db)
        conn.execute("""CREATE TABLE vulnerabilities (
            cve_id TEXT, summary TEXT, summary_cn TEXT, published TEXT,
            last_modified TEXT, severity TEXT, cvss_score REAL, cvss_vector TEXT,
            attack_vector TEXT, exploitability TEXT, cwe_id TEXT,
            known_exploited INTEGER, affected_products TEXT, references_json TEXT,
            cpes_json TEXT, sources_json TEXT, fetched_at TEXT)""")
        # CVE-1: nginx 1.0 - 1.24 受影响
        conn.execute(
            "INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CVE-2026-0001", "nginx range vuln", "", "", "", "HIGH", 8.1, "", "", "",
             "CWE-20", 1,
             '["nginx:nginx"]', "[]",
             json.dumps([{"vendor": "nginx", "product": "nginx", "version": "*",
                          "vs": "1.0", "ve": "1.24", "vs_ex": "", "ve_ex": ""}]),
             '["NVD"]', ""))
        # CVE-2: apache http server 2.4.0 - 2.4.49
        conn.execute(
            "INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CVE-2026-0002", "apache path traversal", "", "", "", "CRITICAL", 9.8, "", "", "",
             "CWE-22", 0,
             '["apache:http server"]', "[]",
             json.dumps([{"vendor": "apache", "product": "http_server", "version": "*",
                          "vs": "2.4.0", "ve": "2.4.49", "vs_ex": "", "ve_ex": ""}]),
             '["NVD"]', ""))
        # CVE-3: openssh < 9.8 (仅 affected_products，无 CPE)
        conn.execute(
            "INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("CVE-2026-0003", "openssh regreSSHion", "", "", "", "HIGH", 8.0, "", "", "",
             "CWE-78", 1,
             '["openbsd:openssh"]', "[]", "[]", '["NVD"]', ""))
        conn.commit()
        conn.close()
        self.reader = matcher.VulnDBReader(self.vuln_db)

    def tearDown(self):
        self.reader.close()

    def test_exact_match(self):
        hits = matcher.match_fingerprint(self.reader, "nginx", "1.18.0", "nginx")
        self.assertEqual([h["cve_id"] for h in hits], ["CVE-2026-0001"])
        self.assertEqual(hits[0]["match_level"], "exact")
        self.assertTrue(hits[0]["known_exploited"])

    def test_out_of_range(self):
        hits = matcher.match_fingerprint(self.reader, "nginx", "1.25.0", "nginx")
        self.assertEqual(hits, [])

    def test_alias_underscore(self):
        hits = matcher.match_fingerprint(self.reader, "apache http server", "2.4.49", "apache")
        self.assertEqual([h["cve_id"] for h in hits], ["CVE-2026-0002"])
        self.assertEqual(hits[0]["match_level"], "exact")

    def test_product_only_no_cpe(self):
        hits = matcher.match_fingerprint(self.reader, "openssh", "9.6p1", "openbsd")
        self.assertEqual([h["cve_id"] for h in hits], ["CVE-2026-0003"])
        self.assertEqual(hits[0]["match_level"], "product")

    def test_no_match(self):
        self.assertEqual(matcher.match_fingerprint(self.reader, "redis", "7.0"), [])

    def test_vuln_db_readonly(self):
        """匹配过程不得写 agent1 的库（mode=ro 打开即验证）。"""
        hits = matcher.match_fingerprint(self.reader, "nginx", "1.18.0", "nginx")
        self.assertTrue(hits)
        conn = sqlite3.connect(self.vuln_db)
        n = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        conn.close()
        self.assertEqual(n, 3)


class TestWebtech(unittest.TestCase):
    def test_server_nginx(self):
        items = webtech.detect_all(
            headers={"server": "nginx/1.24.0"}, body="", banner="")
        self.assertTrue(any(i["product"] == "nginx" and i["version"] == "1.24.0"
                            for i in items))

    def test_apache_and_php(self):
        items = webtech.detect_all(
            headers={"server": "Apache/2.4.58 (Ubuntu)",
                     "x-powered-by": "PHP/8.2.12"},
            body="", banner="")
        prods = {i["product"]: i["version"] for i in items}
        self.assertEqual(prods.get("apache http server"), "2.4.58")
        self.assertEqual(prods.get("php"), "8.2.12")

    def test_wordpress_body(self):
        items = webtech.detect_all(headers={"server": "nginx"},
                                   body='<meta name="generator" content="WordPress 6.5.1">',
                                   banner="")
        self.assertTrue(any(i["product"] == "wordpress" and i["version"] == "6.5.1"
                            for i in items))

    def test_ssh_banner(self):
        items = webtech.detect_all(banner="SSH-2.0-OpenSSH_9.6p1 Debian")
        self.assertTrue(any(i["product"] == "openssh" and i["version"] == "9.6p1"
                            for i in items))

    def test_spring_boot(self):
        items = webtech.detect_all(
            headers={"server": "Spring Boot"},
            body="Whitelabel Error Page", banner="")
        self.assertTrue(any(i["product"] == "spring boot" for i in items))

    def test_gitlab_header(self):
        items = webtech.detect_all(
            headers={"server": "nginx", "x-gitlab-meta": "GitLab 16.11.1"}, body="")
        self.assertTrue(any(i["product"] == "gitlab" for i in items))

    def test_thinkphp_body(self):
        items = webtech.detect_all(
            headers={"server": "nginx"},
            body='<a href="http://www.thinkphp.cn">ThinkPHP</a>', banner="")
        self.assertTrue(any(i["product"] == "thinkphp" for i in items))

    def test_django_cookie(self):
        items = webtech.detect_all(
            headers={"server": "nginx", "set-cookie": "dj4x9abc=1; Path=/"}, body="")
        self.assertTrue(any(i["product"] == "django" for i in items))

    def test_discuz(self):
        items = webtech.detect_all(
            headers={"server": "nginx"},
            body='Powered by Discuz! X3.5', banner="")
        self.assertTrue(any(i["product"] == "discuz" and i["version"] == "X3.5"
                            for i in items))

    def test_dedupe(self):
        items = webtech.detect_all(headers={"server": "nginx/1.24.0"},
                                   body="/wp-content/",
                                   banner="")
        nginx = [i for i in items if i["product"] == "nginx"]
        self.assertEqual(len(nginx), 1)


class TestChecks(unittest.TestCase):
    def test_security_headers_missing(self):
        status, detail = check_security_headers({"server": "nginx"})
        self.assertEqual(status, "warning")
        self.assertIn("strict-transport-security", detail)

    def test_security_headers_ok(self):
        h = {k: "x" for k, _ in [
            ("strict-transport-security", ""), ("x-content-type-options", ""),
            ("x-frame-options", ""), ("content-security-policy", ""),
            ("referrer-policy", "")]}
        status, _ = check_security_headers(h)
        self.assertEqual(status, "ok")

    def test_classify_git_exposed(self):
        status, detail = classify_exposed("/.git/HEAD", 200, "ref: refs/heads/main")
        self.assertEqual(status, "warning")
        self.assertIn("Git", detail)

    def test_classify_git_not_exposed(self):
        """200 但内容不是 git 时必须是普通 info，detail 必须为字符串（回归：曾出现嵌套元组）。"""
        status, detail = classify_exposed("/.git/HEAD", 200, "<html>index</html>")
        self.assertEqual(status, "info")
        self.assertIsInstance(detail, str)

    def test_classify_phpinfo_false_positive(self):
        status, detail = classify_exposed("/phpinfo.php", 200, "<html>app</html>")
        self.assertEqual(status, "info")
        self.assertIsInstance(detail, str)

    def test_classify_actuator(self):
        status, _ = classify_exposed("/actuator/env", 200, "{spring}")
        self.assertEqual(status, "warning")

    def test_classify_denied(self):
        status, _ = classify_exposed("/admin/", 401, "Unauthorized")
        self.assertEqual(status, "info")

    def test_classify_404(self):
        status, _ = classify_exposed("/.git/HEAD", 404, "not found")
        self.assertEqual(status, "info")

    def test_classify_env_exposed(self):
        status, detail = classify_exposed("/.env", 200, "DB_PASSWORD=secret")
        self.assertEqual(status, "warning")
        self.assertIn(".env", detail)

    def test_classify_backup_exposed(self):
        status, _ = classify_exposed("/backup.zip", 200, "PK\x03\x04")
        self.assertEqual(status, "warning")

    def test_cookie_flags_ok(self):
        status, _ = check_cookie_flags(
            {"set-cookie": "sid=1; Secure; HttpOnly; SameSite=Lax"})
        self.assertEqual(status, "ok")

    def test_cookie_flags_missing(self):
        status, detail = check_cookie_flags({"set-cookie": "sid=1"})
        self.assertEqual(status, "warning")
        self.assertIn("Secure", detail)
        self.assertIn("HttpOnly", detail)

    def test_cookie_flags_none(self):
        status, _ = check_cookie_flags({"server": "nginx"})
        self.assertEqual(status, "info")


class TestDb(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(), "assets.db")
        self.db = db_mod.Database(self.tmp)

    def tearDown(self):
        self.db.close()

    def test_host_upsert_dedupe(self):
        a = self.db.upsert_host("www.example.com", ip="1.2.3.4")
        b = self.db.upsert_host("www.example.com", ip="1.2.3.4")
        self.assertEqual(a, b)
        self.assertEqual(len(self.db.list_hosts()), 1)

    def test_service_and_fingerprint(self):
        hid = self.db.upsert_host("x.example.com")
        sid = self.db.upsert_service(hid, "1.2.3.4", 80, service="http",
                                     tech=[{"product": "nginx", "version": "1.24"}])
        self.db.upsert_fingerprint(hid, sid, "nginx", "1.24", "nginx", 1.0, "header")
        svc = self.db.list_services()
        self.assertEqual(svc[0]["tech"][0]["product"], "nginx")
        fps = self.db.list_fingerprints()
        self.assertEqual(fps[0]["product"], "nginx")

    def test_match_and_risk(self):
        hid = self.db.upsert_host("x.example.com")
        self.db.upsert_match(hid, "CVE-2026-0001", "HIGH", 8.1, True, "exact",
                             {"via": "cpe"})
        ms = self.db.list_matches()
        self.assertEqual(len(ms), 1)
        self.assertEqual(risk.host_risk(ms), 10.0)  # 8.1 + 2 KEV = 10

    def test_check_store(self):
        hid = self.db.upsert_host("x.example.com")
        self.db.add_check(hid, None, "security_headers", "warning", "缺失 HSTS")
        cs = self.db.list_checks()
        self.assertEqual(cs[0]["status"], "warning")


class TestRisk(unittest.TestCase):
    def test_scores(self):
        self.assertEqual(risk.risk_score("CRITICAL", 9.8, False), 10.0)
        self.assertEqual(risk.risk_score("HIGH", 8.1, True), 10.0)
        self.assertEqual(risk.risk_score("MEDIUM", None, False), 6.0)
        self.assertEqual(risk.risk_score("LOW", 5.0, False), 5.0)
        self.assertEqual(risk.risk_level(9.0), "CRITICAL")
        self.assertEqual(risk.risk_level(7.0), "HIGH")
        self.assertEqual(risk.risk_level(0.0), "NONE")


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = db_mod.Database(os.path.join(self.tmp, "assets.db"))
        hid = self.db.upsert_host("www.example.com", ip="1.2.3.4")
        self.db.upsert_fingerprint(hid, None, "nginx", "1.24.0", "nginx", 1.0, "header")
        self.db.upsert_match(hid, "CVE-2026-0001", "HIGH", 8.1, True, "exact",
                             {"via": "cpe", "cpe": {"vendor": "nginx", "product": "nginx"}})
        self.db.add_check(hid, None, "security_headers", "warning", "缺失 HSTS")

    def tearDown(self):
        self.db.close()

    def test_generate_html(self):
        from asset_agent import report
        p = report.generate(self.db, out_dir=self.tmp, fmt="html")
        with open(p, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("CVE-2026-0001", content)
        self.assertIn("www.example.com", content)
        self.assertIn("security_headers", content)
        self.assertIn("主动漏洞发现", content)

    def test_generate_md(self):
        from asset_agent import report
        p = report.generate(self.db, out_dir=self.tmp, fmt="md")
        with open(p, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("CVE-2026-0001", content)
        self.assertIn("## 五、处置建议", content)


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(), "assets.db")
        self.db = db_mod.Database(self.tmp)

    def tearDown(self):
        self.db.close()

    def test_save_and_list(self):
        sid = self.db.capture_snapshot(source="test")
        snaps = self.db.list_snapshots()
        self.assertEqual(len(snaps), 1)
        self.assertEqual(snaps[0]["id"], sid)
        self.assertEqual(snaps[0]["source"], "test")

    def test_diff_added(self):
        base = self.db.capture_snapshot(source="base")
        hid = self.db.upsert_host("new.example.com", ip="1.2.3.4")
        self.db.upsert_service(hid, "1.2.3.4", 80, service="http")
        self.db.upsert_fingerprint(hid, None, "nginx", "1.24", "nginx", 1.0, "header")
        d = self.db.diff_snapshots(base)
        added_hosts = {x[0] for x in d["diff"]["hosts"]["added"]}
        self.assertIn("new.example.com", added_hosts)
        added_svc = {x for x in d["diff"]["services"]["added"]}
        self.assertIn(("new.example.com", 80, "http"), added_svc)

    def test_diff_removed_and_delete(self):
        hid = self.db.upsert_host("gone.example.com")
        self.db.upsert_fingerprint(hid, None, "nginx", "1.24", "nginx", 1.0, "header")
        base = self.db.capture_snapshot(source="base")
        with self.db._lock:
            self.db.conn.execute("DELETE FROM hosts WHERE id=?", (hid,))
            self.db.conn.commit()
        d = self.db.diff_snapshots(base)
        removed_hosts = {x[0] for x in d["diff"]["hosts"]["removed"]}
        self.assertIn("gone.example.com", removed_hosts)
        self.assertTrue(self.db.delete_snapshot(base))
        self.assertFalse(self.db.delete_snapshot(99999))


class TestExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = db_mod.Database(os.path.join(self.tmp, "assets.db"))
        hid = self.db.upsert_host("www.example.com", ip="1.2.3.4")
        self.db.upsert_fingerprint(hid, None, "nginx", "1.24.0", "nginx", 1.0, "header")
        self.db.upsert_match(hid, "CVE-2026-0001", "HIGH", 8.1, True, "exact",
                             {"via": "cpe"})
        self.db.add_check(hid, None, "security_headers", "warning", "缺失 HSTS")

    def tearDown(self):
        self.db.close()

    def test_csv(self):
        s = export_mod.export_hosts(self.db, "csv")
        self.assertIn("www.example.com", s)
        self.assertIn("CVE-2026-0001", export_mod.export_matches(self.db, "csv"))
        self.assertIn("security_headers", export_mod.export_checks(self.db, "csv"))

    def test_json(self):
        import json as _json
        data = _json.loads(export_mod.export_matches(self.db, "json"))
        self.assertEqual(data[0]["cve_id"], "CVE-2026-0001")

    def test_md(self):
        s = export_mod.export_hosts(self.db, "md")
        self.assertIn("| host |", s)

    def test_export_all_files(self):
        paths = export_mod.export_all(self.db, fmt="csv", out=self.tmp)
        self.assertEqual(len(paths), 3)
        for p in paths:
            self.assertTrue(os.path.exists(p))


class TestWebui(unittest.TestCase):
    def test_serve_structure(self):
        """webui 模块可导入，且 serve 函数存在（避免 import 级错误）。"""
        from asset_agent import webui
        self.assertTrue(callable(webui.serve))


class _VulnServer:
    """本地模拟脆弱服务：.git 泄露 / Actuator 未授权 / 无安全头 / 目录列表。"""

    def __init__(self):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                p = self.path
                body = b""
                if p == "/.git/HEAD":
                    body = b"ref: refs/heads/main\n"
                elif p == "/.git/config":
                    body = b"[core]\n\trepositoryformatversion = 0\n"
                elif p == "/actuator/env":
                    body = b'{"systemProperties":{"java.version":"17"}}'
                elif p == "/.env":
                    body = b"DB_PASSWORD=super-secret\nAPI_KEY=abc123"
                elif p == "/backup.zip":
                    body = b"PK\x03\x04backup data"
                elif p == "/robots.txt":
                    body = b"User-agent: *\nDisallow: /admin/\nDisallow: /secret"
                elif p == "/admin/":
                    body = b"<title>Admin</title>"
                elif p == "/":
                    body = b"<html><head><title>Index of /</title></head><body>index</body></html>"
                else:
                    body = b"<html><title>404 Not Found</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "nginx/1.24.0")
                self.send_header("Set-Cookie", "sid=abc123")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestExplore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = db_mod.Database(os.path.join(self.tmp, "assets.db"))
        self.srv = _VulnServer()
        self.hid = self.db.upsert_host("127.0.0.1", ip="127.0.0.1")
        self.db.upsert_service(self.hid, "127.0.0.1", self.srv.port,
                               service="http", http_status=200)

    def tearDown(self):
        self.srv.close()
        self.db.close()

    def test_git_leak(self):
        findings = explore.probe_http("127.0.0.1", self.srv.port, False, 2.0)
        names = {f["name"] for f in findings}
        self.assertTrue(any("Git 源码泄露" in n for n in names))
        self.assertIn("环境变量文件泄露（可能含密钥）", names)

    def test_actuator_unauth(self):
        findings = explore.probe_http("127.0.0.1", self.srv.port, False, 2.0)
        f = next((x for x in findings if x["check_id"] == "actuator"), None)
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "HIGH")

    def test_cors_star(self):
        f = explore.check_cors("127.0.0.1", self.srv.port, False, 2.0)
        self.assertIsNotNone(f)
        self.assertEqual(f["check_id"], "cors")

    def test_dir_listing(self):
        f = explore.check_dir_listing("127.0.0.1", self.srv.port, False, 2.0)
        self.assertIsNotNone(f)
        self.assertEqual(f["check_id"], "dir_listing")

    def test_headers_missing(self):
        hdrs = {"server": "nginx/1.24.0", "set-cookie": "sid=abc123"}
        out = explore.analyze_headers(hdrs)
        ids = {f["check_id"] for f in out}
        self.assertIn("headers", ids)
        self.assertIn("cookie", ids)
        self.assertIn("version", ids)

    def test_run_explore_writes_db(self):
        findings = explore.run_explore(self.db, timeout=2.0)
        rows = self.db.list_findings()
        self.assertGreaterEqual(len(rows), 4)
        self.assertEqual(len(findings), len(rows))
        self.assertEqual(rows[0]["host_name"], "127.0.0.1")

    def test_db_port_hint(self):
        f = explore.scan_db_port(6379)
        self.assertIsNotNone(f)
        self.assertIn("Redis", f["name"])
        self.assertIsNone(explore.scan_db_port(80))

    def test_findings_filter(self):
        explore.run_explore(self.db, timeout=2.0)
        high = self.db.list_findings(min_severity="HIGH")
        self.assertTrue(all(f["severity"] in ("HIGH", "CRITICAL") for f in high))


class TestScheduler(unittest.TestCase):
    """调度器：cron/interval 解析 + 任务 CRUD 持久化。"""

    def test_cron_star(self):
        from asset_agent.scheduler import CronExpr
        from datetime import datetime
        e = CronExpr("* * * * *")
        nxt = e.next_run(datetime(2026, 9, 7, 12, 30, 0))
        self.assertEqual(nxt, datetime(2026, 9, 7, 12, 31, 0))

    def test_cron_daily_2am(self):
        from asset_agent.scheduler import CronExpr
        from datetime import datetime
        e = CronExpr("0 2 * * *")
        nxt = e.next_run(datetime(2026, 9, 7, 12, 30, 0))
        self.assertEqual(nxt, datetime(2026, 9, 8, 2, 0, 0))

    def test_cron_every_15min(self):
        from asset_agent.scheduler import CronExpr
        from datetime import datetime
        e = CronExpr("*/15 * * * *")
        nxt = e.next_run(datetime(2026, 9, 7, 12, 30, 0))
        self.assertEqual(nxt, datetime(2026, 9, 7, 12, 45, 0))

    def test_cron_weekday(self):
        from asset_agent.scheduler import CronExpr
        from datetime import datetime
        # 2026-09-07 是周一
        e = CronExpr("0 9 * * 1-5")
        nxt = e.next_run(datetime(2026, 9, 7, 12, 30, 0))
        self.assertEqual(nxt, datetime(2026, 9, 8, 9, 0, 0))
        # 周一到周五，周六(12日)应跳过到周一(14日)
        e2 = CronExpr("0 9 * * 1")
        nxt2 = e2.next_run(datetime(2026, 9, 11, 12, 30, 0))  # 周五
        self.assertEqual(nxt2, datetime(2026, 9, 14, 9, 0, 0))

    def test_cron_invalid(self):
        from asset_agent.scheduler import CronExpr
        with self.assertRaises(ValueError):
            CronExpr("0 2 * *")  # 只有 4 个字段
        with self.assertRaises(ValueError):
            CronExpr("61 * * * *")  # 分钟越界

    def test_interval(self):
        from asset_agent.scheduler import parse_interval, compute_next
        from datetime import datetime, timedelta
        base = datetime(2026, 9, 7, 12, 30, 0)
        self.assertEqual(parse_interval("interval:30m"), timedelta(minutes=30))
        self.assertEqual(parse_interval("interval:6h"), timedelta(hours=6))
        self.assertEqual(compute_next("interval:6h", base), base + timedelta(hours=6))
        with self.assertRaises(ValueError):
            parse_interval("interval:xyz")

    def test_jobs_crud_and_persist(self):
        from asset_agent.scheduler import Scheduler
        tmp = tempfile.mkdtemp()
        jobs_file = os.path.join(tmp, "jobs.json")
        s = Scheduler(jobs_file=jobs_file)
        self.assertEqual(s.list_jobs(), [])
        s.add_job("每日扫描", ["example.com"], "0 2 * * *",
                  ports="80,443", enabled=True)
        s.add_job("每周扫描", ["203.0.113.10"], "interval:168h", enabled=False)
        jobs = s.list_jobs()
        self.assertEqual(len(jobs), 2)
        self.assertTrue(jobs[0]["next_run"])
        self.assertFalse(jobs[1]["enabled"])
        # 重复名字拒绝
        with self.assertRaises(ValueError):
            s.add_job("每日扫描", ["a.com"], "0 3 * * *")
        # 非法周期拒绝
        with self.assertRaises(ValueError):
            s.add_job("坏任务", ["a.com"], "not-a-schedule")
        # 持久化：新实例恢复
        s2 = Scheduler(jobs_file=jobs_file)
        self.assertEqual(len(s2.list_jobs()), 2)
        self.assertTrue(any(j["name"] == "每日扫描" for j in s2.list_jobs()))
        # 启停与删除
        s2.set_enabled("每周扫描", True)
        self.assertTrue(s2.get_job("每周扫描")["enabled"])
        self.assertTrue(s2.remove_job("每日扫描"))
        self.assertFalse(s2.remove_job("不存在的任务"))
        self.assertEqual(len(s2.list_jobs()), 1)

    def test_trigger_unknown_job(self):
        from asset_agent.scheduler import Scheduler
        s = Scheduler(jobs_file=os.path.join(tempfile.mkdtemp(), "jobs.json"))
        with self.assertRaises(ValueError):
            s.trigger("不存在")


class TestServerOps(unittest.TestCase):
    """服务器模式：认证 + 任务 API。"""

    def _start(self, token=None, jobs=None):
        import urllib.request
        import http.server
        from asset_agent import webui, scheduler as sched_mod
        jobs_file = jobs or os.path.join(tempfile.mkdtemp(), "jobs.json")
        sched = sched_mod.Scheduler(jobs_file=jobs_file)
        webui._STATE["token"] = token
        webui._STATE["scheduler"] = sched
        webui._STATE["db_path"] = None
        webui._STATE["started"] = None
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), webui.Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self._srv, self._sched = srv, sched
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def _req(self, url, method="GET", body=None, token=None):
        import urllib.request
        import json as _json
        req = urllib.request.Request(url, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        data = _json.dumps(body).encode() if body is not None else None
        try:
            with urllib.request.urlopen(req, data) as r:
                return r.status, _json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, _json.loads(e.read().decode("utf-8"))

    def tearDown(self):
        if getattr(self, "_srv", None):
            self._srv.shutdown()
            self._srv.server_close()
        if getattr(self, "_sched", None):
            self._sched.stop()

    def test_auth_required(self):
        base = self._start(token="secret-token-123")
        code, _ = self._req(base + "/api/jobs")
        self.assertEqual(code, 401)
        code, _ = self._req(base + "/api/jobs", token="wrong")
        self.assertEqual(code, 401)
        code, body = self._req(base + "/api/jobs", token="secret-token-123")
        self.assertEqual(code, 200)
        self.assertIsInstance(body, list)

    def test_auth_optional_local(self):
        base = self._start(token=None)
        code, body = self._req(base + "/api/jobs")
        self.assertEqual(code, 200)
        self.assertEqual(body, [])

    def test_jobs_api_full_flow(self):
        base = self._start(token="tok")
        # 创建
        code, body = self._req(base + "/api/jobs", "POST",
                               {"name": "测试任务", "targets": ["example.com"],
                                "schedule": "0 2 * * *", "ports": "80,443"},
                               token="tok")
        self.assertEqual(code, 200)
        self.assertEqual(body["job"]["name"], "测试任务")
        # 非法周期
        code, body = self._req(base + "/api/jobs", "POST",
                               {"name": "坏", "targets": ["a.com"],
                                "schedule": "bad"}, token="tok")
        self.assertEqual(code, 400)
        # 立即运行（异步，目标 example.com 不在范围会被拒绝，但任务状态会被记录）
        q = urllib.parse.quote("测试任务")
        code, body = self._req(base + "/api/jobs/run?id=" + q, "POST", token="tok")
        self.assertEqual(code, 200)
        # 列表
        code, body = self._req(base + "/api/jobs", token="tok")
        self.assertEqual(code, 200)
        self.assertEqual(len(body), 1)
        # 启停
        code, _ = self._req(base + "/api/jobs/enable?id=" + q + "&enabled=0", "POST", token="tok")
        self.assertEqual(code, 200)
        self.assertFalse(self._sched.get_job("测试任务")["enabled"])
        # 删除
        code, _ = self._req(base + "/api/jobs?id=" + q, "DELETE", token="tok")
        self.assertEqual(code, 200)
        self.assertEqual(self._sched.list_jobs(), [])
        # 删除不存在
        code, _ = self._req(base + "/api/jobs?id=" + urllib.parse.quote("不存在"),
                            "DELETE", token="tok")
        self.assertEqual(code, 404)

    def test_status_api(self):
        from datetime import datetime
        base = self._start(token="tok")
        # 模拟真实服务启动状态（datetime 对象也应可序列化）
        from asset_agent import webui
        webui._STATE["started"] = datetime.now()
        code, body = self._req(base + "/api/status", token="tok")
        self.assertEqual(code, 200)
        self.assertEqual(body["service"], "agent2")
        self.assertTrue(body["scheduler"])
        self.assertIn("uptime_seconds", body)
        self.assertTrue(body["started"])


if __name__ == "__main__":
    unittest.main()

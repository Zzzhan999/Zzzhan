"""Web 仪表盘服务（纯标准库，零依赖，离线可用）。

本地模式：
  浏览器访问 http://127.0.0.1:8000 查看资产发现 + 漏洞验证结果。

服务器模式（python main.py serve）：
  支持 Bearer Token 认证、任务管理（创建/启停/立即运行/删除）、服务状态。

API：
  GET  /                           前端页面
  GET  /api/stats                  统计概览
  GET  /api/hosts                  资产清单（含聚合风险）
  GET  /api/hosts?id=N             单个资产详情（服务/指纹/匹配/检查）
  GET  /api/matches                全部漏洞匹配
  GET  /api/checks                 全部安全检查结果
  GET  /api/scans                  扫描日志
  GET  /api/snapshots              快照列表
  GET  /api/snapshot/diff?from=N&to=M  快照差异（to 缺省=当前状态）
  GET  /api/jobs                   定时任务列表
  GET  /api/status                 服务状态（运行时长/任务数/队列）
  POST /api/snapshot               保存快照
  POST /api/report                 生成 HTML 报告
  POST /api/export                 导出 CSV
  POST /api/jobs                   创建定时任务 {name, targets, schedule, ports,...}
  POST /api/jobs/run?id=N          立即运行任务
  POST /api/jobs/enable?id=N&enabled=0|1  启用/停用任务
  DELETE /api/jobs?id=N            删除任务

认证：配置 token 后，所有 /api/* 与页面请求需带
  Authorization: Bearer <token>   或  ?token=<token>
"""

import json
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .db import Database
from .verify.risk import host_risk, risk_level

WEBUI_DIR = Path(__file__).resolve().parent.parent / "webui"

# 服务级共享状态（serve() 启动时注入）
_STATE = {"token": None, "scheduler": None, "db_path": None,
          "vuln_db": None, "started": None}


class Handler(BaseHTTPRequestHandler):
    server_version = "AssetAgent2/0.2"

    # ---------- 认证 ----------
    def _check_auth(self) -> bool:
        token = _STATE["token"]
        if not token:
            return True
        if self.headers.get("Authorization") == f"Bearer {token}":
            return True
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if q.get("token", [""])[0] == token:
            return True
        self._send_json({"error": "unauthorized"}, 401)
        return False

    # ---------- helpers ----------
    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            return {}

    def _db(self) -> Database:
        return Database(_STATE["db_path"])

    # ---------- data helpers ----------
    def _hosts_summary(self, db) -> list[dict]:
        services = db.list_services()
        fps = db.list_fingerprints()
        matches = db.list_matches()
        svc_c, fp_c, m_map = {}, {}, {}
        for s in services:
            svc_c[s["host_id"]] = svc_c.get(s["host_id"], 0) + 1
        for f in fps:
            fp_c[f["host_id"]] = fp_c.get(f["host_id"], 0) + 1
        for m in matches:
            m_map.setdefault(m["host_id"], []).append(m)
        out = []
        for h in db.list_hosts():
            ms = m_map.get(h["id"], [])
            out.append({
                "id": h["id"], "host": h["host"], "ip": h["ip"] or "",
                "services": svc_c.get(h["id"], 0), "fingerprints": fp_c.get(h["id"], 0),
                "vulns": len(ms), "kev": sum(1 for m in ms if m["known_exploited"]),
                "critical": sum(1 for m in ms if (m["severity"] or "").upper() == "CRITICAL"),
                "high": sum(1 for m in ms if (m["severity"] or "").upper() == "HIGH"),
                "risk": host_risk(ms), "risk_level": risk_level(host_risk(ms)),
            })
        out.sort(key=lambda x: -x["risk"])
        return out

    # ---------- GET ----------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        # 页面本身放行（不含敏感数据），数据全部走 /api/*（强制认证）
        if path in ("/", "/index.html"):
            self._serve_index()
            return
        if not self._check_auth():
            return
        try:
            if path in ("/", "/index.html"):
                self._serve_index()
            elif path == "/api/stats":
                self._serve_stats()
            elif path == "/api/hosts":
                if query.get("id"):
                    self._serve_host_detail(int(query["id"][0]))
                else:
                    self._serve_hosts()
            elif path == "/api/matches":
                self._serve_matches()
            elif path == "/api/findings":
                self._serve_findings()
            elif path == "/api/checks":
                self._serve_checks()
            elif path == "/api/scans":
                self._serve_scans()
            elif path == "/api/snapshots":
                self._serve_snapshots()
            elif path == "/api/snapshot/diff":
                self._serve_snapshot_diff(query)
            elif path == "/api/jobs":
                self._serve_jobs()
            elif path == "/api/status":
                self._serve_status()
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_POST(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/snapshot":
                self._create_snapshot()
            elif parsed.path == "/api/report":
                self._generate_report()
            elif parsed.path == "/api/export":
                self._export()
            elif parsed.path == "/api/jobs":
                self._create_job()
            elif parsed.path == "/api/jobs/run":
                self._run_job_now()
            elif parsed.path == "/api/jobs/enable":
                self._set_job_enabled()
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def do_DELETE(self):
        if not self._check_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/jobs":
                self._delete_job()
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _serve_index(self):
        p = WEBUI_DIR / "index.html"
        if not p.exists():
            self._send(404, b"index.html not found", "text/plain")
            return
        self._send(200, p.read_bytes(), "text/html; charset=utf-8")

    def _serve_stats(self):
        db = self._db()
        s = db.stats()
        hosts = self._hosts_summary(db)
        s["risky_hosts"] = sum(1 for h in hosts if h["risk"] > 0)
        s["high_risk_hosts"] = sum(1 for h in hosts if h["risk"] >= 7)
        s["top_risk"] = hosts[:1][0]["risk"] if hosts else 0
        db.close()
        self._send_json(s)

    def _serve_hosts(self):
        db = self._db()
        self._send_json(self._hosts_summary(db))
        db.close()

    def _serve_host_detail(self, host_id: int):
        db = self._db()
        h = db.get_host(host_id)
        if not h:
            db.close()
            self._send_json({"error": "host not found"}, 404)
            return
        services = [s for s in db.list_services() if s["host_id"] == host_id]
        fps = [f for f in db.list_fingerprints() if f["host_id"] == host_id]
        ms = [m for m in db.list_matches() if m["host_id"] == host_id]
        fs = [f for f in db.list_findings() if f["host_id"] == host_id]
        cs = [c for c in db.list_checks() if c["host_id"] == host_id]
        for m in ms:
            try:
                ev = json.loads(m.get("evidence") or "{}")
            except Exception:
                ev = {}
            m["evidence"] = ev
        db.close()
        self._send_json({"host": h, "services": services, "fingerprints": fps,
                         "matches": ms, "findings": fs, "checks": cs})

    def _serve_matches(self):
        db = self._db()
        ms = db.list_matches()
        for m in ms:
            try:
                m["evidence"] = json.loads(m.get("evidence") or "{}")
            except Exception:
                m["evidence"] = {}
        db.close()
        self._send_json(ms)

    def _serve_findings(self):
        db = self._db()
        self._send_json(db.list_findings())
        db.close()

    def _serve_checks(self):
        db = self._db()
        self._send_json(db.list_checks())
        db.close()

    def _serve_scans(self):
        db = self._db()
        with db._lock:
            rows = [dict(r) for r in db.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()]
        db.close()
        self._send_json(rows)

    def _serve_snapshots(self):
        db = self._db()
        self._send_json(db.list_snapshots())
        db.close()

    def _serve_snapshot_diff(self, query):
        try:
            from_id = int((query.get("from") or [""])[0])
        except ValueError:
            self._send_json({"error": "缺少 from 参数"}, 400)
            return
        to_raw = (query.get("to") or [None])[0]
        to_id = int(to_raw) if to_raw not in (None, "", "null") else None
        db = self._db()
        try:
            d = db.diff_snapshots(from_id, to_id)
        except ValueError as e:
            db.close()
            self._send_json({"error": str(e)}, 400)
            return
        db.close()
        self._send_json(d)

    # ---------- jobs & status ----------
    def _scheduler(self):
        s = _STATE["scheduler"]
        if s is None:
            raise RuntimeError("调度器未启用（请用 python main.py serve 启动）")
        return s

    def _serve_jobs(self):
        self._send_json(self._scheduler().list_jobs())

    def _serve_status(self):
        from datetime import datetime
        s = _STATE["scheduler"]
        running = []
        if s is not None:
            with s._lock:
                running = [n for n, r in s._running.items() if r]
        self._send_json({
            "service": "agent2",
            "version": "0.2",
            "started": _STATE["started"].isoformat(timespec="seconds")
            if _STATE["started"] else None,
            "uptime_seconds": round(
                (datetime.now() - _STATE["started"]).total_seconds(), 1)
            if _STATE["started"] else None,
            "scheduler": s is not None,
            "jobs": len(s.list_jobs()) if s else 0,
            "running": running,
        })

    def _create_job(self):
        body = self._read_json()
        name = (body.get("name") or "").strip()
        targets = body.get("targets") or []
        if isinstance(targets, str):
            targets = [t for t in targets.replace("\n", ",").split(",") if t.strip()]
        schedule = (body.get("schedule") or "").strip()
        if not name or not targets or not schedule:
            self._send_json({"error": "缺少 name / targets / schedule"}, 400)
            return
        try:
            job = self._scheduler().add_job(
                name=name, targets=targets, schedule=schedule,
                ports=body.get("ports") or "80,443,8080,8443,22",
                timeout=float(body.get("timeout") or 6.0),
                workers=int(body.get("workers") or 200),
                enabled=bool(body.get("enabled", True)),
                min_severity=body.get("min_severity") or "HIGH",
                notify_url=body.get("notify_url") or "")
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        self._send_json({"ok": True, "job": job})

    def _run_job_now(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = (q.get("id") or [""])[0]
        if not name:
            self._send_json({"error": "缺少 id（任务名）参数"}, 400)
            return
        try:
            self._scheduler().trigger(name)
        except ValueError as e:
            self._send_json({"error": str(e)}, 404)
            return
        self._send_json({"ok": True, "triggered": name})

    def _set_job_enabled(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = (q.get("id") or [""])[0]
        enabled = (q.get("enabled") or ["1"])[0] in ("1", "true", "on")
        if not name:
            self._send_json({"error": "缺少 id 参数"}, 400)
            return
        if not self._scheduler().set_enabled(name, enabled):
            self._send_json({"error": f"任务不存在: {name}"}, 404)
            return
        self._send_json({"ok": True, "enabled": enabled})

    def _delete_job(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = (q.get("id") or [""])[0]
        if not name:
            self._send_json({"error": "缺少 id 参数"}, 400)
            return
        if not self._scheduler().remove_job(name):
            self._send_json({"error": f"任务不存在: {name}"}, 404)
            return
        self._send_json({"ok": True, "deleted": name})

    # ---------- POST ----------
    def _create_snapshot(self):
        db = self._db()
        sid = db.capture_snapshot(source="web")
        db.close()
        self._send_json({"id": sid, "ok": True})

    def _generate_report(self):
        from . import report
        db = self._db()
        path = report.generate(db, fmt="html")
        db.close()
        self._send_json({"ok": True, "path": path,
                         "name": Path(path).name})

    def _export(self):
        from . import export as export_mod
        db = self._db()
        paths = export_mod.export_all(db, fmt="csv")
        db.close()
        self._send_json({"ok": True, "paths": paths})

    def log_message(self, fmt, *args):
        pass  # 静默访问日志


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True,
          token: str | None = None, scheduler=None, db_path: str | None = None,
          vuln_db: str | None = None):
    from datetime import datetime
    _STATE["token"] = token
    _STATE["scheduler"] = scheduler
    _STATE["db_path"] = db_path
    _STATE["vuln_db"] = vuln_db
    _STATE["started"] = datetime.now()
    srv = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"Agent2 Web 服务: {url}")
    if token:
        print(f"认证: Bearer Token 已启用（API 需带 Authorization: Bearer <token>）")
    if scheduler:
        print(f"调度器: 已加载 {len(scheduler.list_jobs())} 个定时任务")
        scheduler.start()
    print("按 Ctrl+C 停止")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        if scheduler:
            scheduler.stop()
        srv.server_close()

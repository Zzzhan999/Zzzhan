"""SQLite 数据访问层：管理发现的资产（主机/服务/指纹）、漏洞匹配与检查结果。

与 agent1 的关系：agent2 的库（data/assets.db）只保存**发现与验证结果**；
漏洞情报本体由 agent1 的 data/vulns.db 持有，agent2 以只读方式读取。
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

DEFAULT_DB = str(Path(__file__).resolve().parent.parent / "data" / "assets.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL UNIQUE,      -- 域名或 IP
    ip         TEXT DEFAULT '',           -- 解析出的 IP（域名时）
    host_type  TEXT DEFAULT 'host',       -- domain / ip
    source     TEXT DEFAULT '',           -- 发现来源: scope/subdomains/ports/...
    first_seen TEXT,
    last_seen  TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    ip          TEXT DEFAULT '',
    port        INTEGER NOT NULL,
    proto       TEXT DEFAULT 'tcp',
    service     TEXT DEFAULT '',          -- 端口猜测服务名
    banner      TEXT DEFAULT '',
    http_status INTEGER,
    http_title  TEXT DEFAULT '',
    http_server TEXT DEFAULT '',
    tech_json   TEXT DEFAULT '[]',        -- webtech 识别出的产品
    tls_json    TEXT DEFAULT '',
    status      TEXT DEFAULT 'open',
    first_seen  TEXT,
    last_seen   TEXT,
    UNIQUE(host_id, ip, port, proto)
);

CREATE TABLE IF NOT EXISTS fingerprints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    service_id  INTEGER,
    product     TEXT NOT NULL,            -- 规范化产品名（对齐 CPE 词汇）
    version     TEXT DEFAULT '',
    vendor      TEXT DEFAULT '',
    confidence  REAL DEFAULT 1.0,
    source      TEXT DEFAULT '',          -- header/banner/meta/path/cert
    UNIQUE(host_id, product, version)
);

CREATE TABLE IF NOT EXISTS vuln_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL,
    service_id      INTEGER,
    fingerprint_id  INTEGER,
    cve_id          TEXT NOT NULL,
    severity        TEXT,
    cvss_score      REAL,
    known_exploited INTEGER DEFAULT 0,
    match_level     TEXT DEFAULT 'product',  -- exact=版本命中 / product=产品级命中
    evidence        TEXT DEFAULT '',          -- 匹配证据（CPE/版本范围），JSON
    matched_at      TEXT,
    UNIQUE(host_id, cve_id)
);

CREATE TABLE IF NOT EXISTS checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    service_id  INTEGER,
    check_name  TEXT NOT NULL,
    status      TEXT DEFAULT 'info',      -- ok / warning / info
    detail      TEXT DEFAULT '',
    checked_at  TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL,
    service_id  INTEGER,
    check_id    TEXT,                     -- 检测项标识，如 actuator / git / cors
    name        TEXT,                     -- 漏洞名称
    severity    TEXT,                     -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    evidence    TEXT,                     -- 证据（URL/响应片段）
    remediation TEXT,                     -- 修复建议
    found_at    TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT,                     -- subdomains/ports/fingerprint/match/checks/run
    target      TEXT DEFAULT '',
    started_at  TEXT,
    finished_at TEXT,
    status      TEXT DEFAULT 'ok',
    detail      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT DEFAULT 'full',      -- full=全量快照
    taken_at    TEXT,
    source      TEXT DEFAULT '',          -- 触发来源: run/手动
    data_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_fp_host ON fingerprints(host_id);
CREATE INDEX IF NOT EXISTS idx_matches_host ON vuln_matches(host_id);
CREATE INDEX IF NOT EXISTS idx_checks_host ON checks(host_id);
"""


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Database:
    """agent2 本地数据库访问封装（线程安全）。"""

    def __init__(self, path: str | None = None):
        if path is None:
            path = os.environ.get("AGENT2_DB") or DEFAULT_DB
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self):
        with self._lock:
            self.conn.close()

    # ---------- hosts ----------
    def upsert_host(self, host: str, ip: str = "", host_type: str = "host",
                    source: str = "") -> int:
        """按 host 去重写入主机，返回 id。"""
        ts = now()
        with self._lock:
            cur = self.conn.execute(
                "SELECT id, ip FROM hosts WHERE host = ?", (host,))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE hosts SET ip=?, host_type=?, last_seen=? WHERE id=?",
                    (ip or row["ip"], host_type, ts, row["id"]))
                self.conn.commit()
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO hosts(host, ip, host_type, source, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?)", (host, ip, host_type, source, ts, ts))
            self.conn.commit()
            return cur.lastrowid

    def list_hosts(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM hosts ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def get_host(self, host_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
            return dict(row) if row else None

    # ---------- services ----------
    def upsert_service(self, host_id: int, ip: str, port: int, proto: str = "tcp",
                       service: str = "", banner: str = "", http_status: int | None = None,
                       http_title: str = "", http_server: str = "",
                       tech: list | None = None, tls: dict | None = None) -> int:
        ts = now()
        tech_json = json.dumps(tech or [], ensure_ascii=False)
        tls_json = json.dumps(tls or {}, ensure_ascii=False)
        with self._lock:
            cur = self.conn.execute(
                "SELECT id FROM services WHERE host_id=? AND ip=? AND port=? AND proto=?",
                (host_id, ip, port, proto))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE services SET service=?, banner=?, http_status=?, http_title=?, "
                    "http_server=?, tech_json=?, tls_json=?, status=?, last_seen=? WHERE id=?",
                    (service, banner[:4000], http_status, http_title[:500], http_server,
                     tech_json, tls_json, "open", ts, row["id"]))
                self.conn.commit()
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO services(host_id, ip, port, proto, service, banner, http_status, "
                "http_title, http_server, tech_json, tls_json, status, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (host_id, ip, port, proto, service, banner[:4000], http_status,
                 http_title[:500], http_server, tech_json, tls_json, "open", ts, ts))
            self.conn.commit()
            return cur.lastrowid

    def list_services(self, host_id: int | None = None) -> list[dict]:
        q = "SELECT * FROM services"
        params = ()
        if host_id is not None:
            q += " WHERE host_id = ?"
            params = (host_id,)
        q += " ORDER BY host_id, port"
        with self._lock:
            rows = self.conn.execute(q, params).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["tech"] = json.loads(d.pop("tech_json") or "[]")
                if d.get("tls_json"):
                    try:
                        d["tls"] = json.loads(d["tls_json"])
                    except Exception:
                        d["tls"] = {}
                else:
                    d["tls"] = {}
                out.append(d)
            return out

    def get_service(self, service_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
            return dict(row) if row else None

    # ---------- fingerprints ----------
    def upsert_fingerprint(self, host_id: int, service_id: int | None, product: str,
                           version: str = "", vendor: str = "", confidence: float = 1.0,
                           source: str = "") -> int:
        with self._lock:
            cur = self.conn.execute(
                "SELECT id FROM fingerprints WHERE host_id=? AND product=? AND version=?",
                (host_id, product, version))
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE fingerprints SET service_id=?, vendor=?, confidence=?, source=? "
                    "WHERE id=?",
                    (service_id, vendor, confidence, source, row["id"]))
                self.conn.commit()
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO fingerprints(host_id, service_id, product, version, vendor, "
                "confidence, source) VALUES (?,?,?,?,?,?,?)",
                (host_id, service_id, product, version, vendor, confidence, source))
            self.conn.commit()
            return cur.lastrowid

    def list_fingerprints(self, host_id: int | None = None) -> list[dict]:
        q = "SELECT * FROM fingerprints"
        params = ()
        if host_id is not None:
            q += " WHERE host_id = ?"
            params = (host_id,)
        q += " ORDER BY id"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def clear_fingerprints(self, host_id: int | None = None) -> int:
        if host_id is not None:
            with self._lock:
                n = self.conn.execute(
                    "DELETE FROM fingerprints WHERE host_id=?", (host_id,)).rowcount
                self.conn.commit()
                return n
        with self._lock:
            n = self.conn.execute("DELETE FROM fingerprints").rowcount
            self.conn.commit()
            return n

    # ---------- vuln matches ----------
    def upsert_match(self, host_id: int, cve_id: str, severity: str | None,
                     cvss: float | None, known_exploited: bool, match_level: str,
                     evidence: dict, service_id: int | None = None,
                     fingerprint_id: int | None = None) -> int:
        ts = now()
        with self._lock:
            cur = self.conn.execute(
                "SELECT id FROM vuln_matches WHERE host_id=? AND cve_id=?",
                (host_id, cve_id))
            row = cur.fetchone()
            ev = json.dumps(evidence, ensure_ascii=False)
            if row:
                self.conn.execute(
                    "UPDATE vuln_matches SET severity=?, cvss_score=?, known_exploited=?, "
                    "match_level=?, evidence=?, service_id=?, fingerprint_id=?, matched_at=? "
                    "WHERE id=?",
                    (severity, cvss, int(known_exploited), match_level, ev,
                     service_id, fingerprint_id, ts, row["id"]))
                self.conn.commit()
                return row["id"]
            cur = self.conn.execute(
                "INSERT INTO vuln_matches(host_id, service_id, fingerprint_id, cve_id, "
                "severity, cvss_score, known_exploited, match_level, evidence, matched_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (host_id, service_id, fingerprint_id, cve_id, severity, cvss,
                 int(known_exploited), match_level, ev, ts))
            self.conn.commit()
            return cur.lastrowid

    def list_matches(self, host_id: int | None = None,
                     min_severity: str | None = None) -> list[dict]:
        q = ("SELECT m.*, h.host AS host_name FROM vuln_matches m "
             "JOIN hosts h ON h.id = m.host_id")
        where, params = [], []
        if host_id is not None:
            where.append("m.host_id = ?")
            params.append(host_id)
        if min_severity:
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            where.append("m.severity IN (%s)" % ",".join(
                "?" for _ in range(order[min_severity.upper()] + 1)))
            params += list(order)[:order[min_severity.upper()] + 1]
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY m.cvss_score DESC"
        with self._lock:
            rows = self.conn.execute(q, params).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["evidence"] = json.loads(d.get("evidence") or "{}")
                except Exception:
                    d["evidence"] = {}
                out.append(d)
            return out

    def clear_matches(self, host_id: int | None = None) -> int:
        if host_id is not None:
            with self._lock:
                n = self.conn.execute(
                    "DELETE FROM vuln_matches WHERE host_id=?", (host_id,)).rowcount
                self.conn.commit()
                return n
        with self._lock:
            n = self.conn.execute("DELETE FROM vuln_matches").rowcount
            self.conn.commit()
            return n

    # ---------- checks ----------
    def add_check(self, host_id: int, service_id: int | None, check_name: str,
                  status: str, detail: str):
        ts = now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO checks(host_id, service_id, check_name, status, detail, "
                "checked_at) VALUES (?,?,?,?,?,?)",
                (host_id, service_id, check_name, status, detail[:2000], ts))
            self.conn.commit()

    def list_checks(self, host_id: int | None = None) -> list[dict]:
        q = ("SELECT c.*, h.host AS host_name FROM checks c "
             "JOIN hosts h ON h.id = c.host_id")
        params = ()
        if host_id is not None:
            q += " WHERE c.host_id = ?"
            params = (host_id,)
        q += " ORDER BY c.id DESC"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    # ---------- findings ----------
    def add_finding(self, host_id: int, service_id: int | None, check_id: str,
                    name: str, severity: str, evidence: str, remediation: str = ""):
        ts = now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO findings(host_id, service_id, check_id, name, severity, "
                "evidence, remediation, found_at) VALUES (?,?,?,?,?,?,?,?)",
                (host_id, service_id, check_id, name[:200], severity,
                 evidence[:2000], remediation[:2000], ts))
            self.conn.commit()

    def list_findings(self, host_id: int | None = None,
                      min_severity: str | None = None) -> list[dict]:
        q = ("SELECT f.*, h.host AS host_name FROM findings f "
             "JOIN hosts h ON h.id = f.host_id")
        params: list = []
        cond = []
        if host_id is not None:
            cond.append("f.host_id = ?")
            params.append(host_id)
        if min_severity:
            rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            cond.append("CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                        "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END >= ?")
            params.append(rank.get(min_severity.upper(), 0))
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 " \
             "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.id DESC"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def delete_findings(self, host_id: int | None = None) -> int:
        q = "DELETE FROM findings"
        params: list = []
        if host_id is not None:
            q += " WHERE host_id = ?"
            params.append(host_id)
        with self._lock:
            cur = self.conn.execute(q, params)
            self.conn.commit()
            return cur.rowcount

    # ---------- scans log ----------
    def log_scan(self, kind: str, target: str, detail: str = "",
                 status: str = "ok") -> int:
        ts = now()
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO scans(kind, target, started_at, finished_at, status, detail) "
                "VALUES (?,?,?,?,?,?)", (kind, target, ts, ts, status, detail[:2000]))
            self.conn.commit()
            return cur.lastrowid

    # ---------- snapshots ----------
    def _current_data(self) -> dict:
        """抓取当前全量状态（不落库）。"""
        hosts = self.list_hosts()
        services = self.list_services()
        fps = self.list_fingerprints()
        matches = self.list_matches()
        host_name = {h["id"]: h["host"] for h in hosts}
        return {
            "hosts": [{"host": h["host"], "ip": h["ip"]} for h in hosts],
            "services": [{"host": host_name.get(s["host_id"], "?"), "port": s["port"],
                          "service": s["service"] or ""} for s in services],
            "fingerprints": [{"host": host_name.get(f["host_id"], "?"),
                              "product": f["product"], "version": f["version"] or ""}
                             for f in fps],
            "matches": [{"host": m["host_name"], "cve_id": m["cve_id"],
                         "severity": m["severity"] or "", "match_level": m["match_level"],
                         "cvss_score": m["cvss_score"]} for m in matches],
        }

    def capture_snapshot(self, source: str = "") -> int:
        """抓取当前全量状态存为快照，返回快照 id。"""
        data = self._current_data()
        ts = now()
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO snapshots(kind, taken_at, source, data_json) "
                "VALUES (?,?,?,?)",
                ("full", ts, source, json.dumps(data, ensure_ascii=False)))
            self.conn.commit()
            return cur.lastrowid

    def list_snapshots(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, kind, taken_at, source, LENGTH(data_json) AS size "
                "FROM snapshots ORDER BY id").fetchall()
            return [dict(r) for r in rows]

    def get_snapshot(self, snap_id: int) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM snapshots WHERE id = ?", (snap_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["data"] = json.loads(d.pop("data_json") or "{}")
            except Exception:
                d["data"] = {}
            return d

    def delete_snapshot(self, snap_id: int) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM snapshots WHERE id = ?", (snap_id,))
            self.conn.commit()
            return cur.rowcount > 0

    def _snapshot_set(self, data: dict, key: str) -> set:
        out = set()
        for item in data.get(key, []):
            if key == "hosts":
                out.add((item.get("host"), item.get("ip", "")))
            elif key == "services":
                out.add((item.get("host"), item.get("port"), item.get("service", "")))
            elif key == "fingerprints":
                out.add((item.get("host"), item.get("product"), item.get("version", "")))
            elif key == "matches":
                out.add((item.get("host"), item.get("cve_id"),
                         item.get("severity", ""), item.get("match_level", "")))
        return out

    def diff_snapshots(self, from_id: int, to_id: int | None = None) -> dict:
        """对比两个快照（to_id 为空时对比当前状态），返回差异。"""
        a = self.get_snapshot(from_id)
        if not a:
            raise ValueError(f"快照不存在: {from_id}")
        if to_id is not None:
            b = self.get_snapshot(to_id)
            if not b:
                raise ValueError(f"快照不存在: {to_id}")
            b_data, to_time = b["data"], b["taken_at"]
        else:
            b_data, to_time = self._current_data(), "当前状态"
        diff = {}
        for key in ("hosts", "services", "fingerprints", "matches"):
            set_a = self._snapshot_set(a["data"], key)
            set_b = self._snapshot_set(b_data, key)
            diff[key] = {
                "added": sorted(set_b - set_a),
                "removed": sorted(set_a - set_b),
            }
        return {"from": from_id, "to": to_id, "from_time": a["taken_at"],
                "to_time": to_time, "diff": diff}

    # ---------- stats ----------
    def stats(self) -> dict:
        with self._lock:
            hosts = self.conn.execute("SELECT COUNT(*) c FROM hosts").fetchone()["c"]
            services = self.conn.execute("SELECT COUNT(*) c FROM services").fetchone()["c"]
            fps = self.conn.execute("SELECT COUNT(*) c FROM fingerprints").fetchone()["c"]
            matches = self.conn.execute("SELECT COUNT(*) c FROM vuln_matches").fetchone()["c"]
            kev = self.conn.execute(
                "SELECT COUNT(*) c FROM vuln_matches WHERE known_exploited=1").fetchone()["c"]
            checks = self.conn.execute("SELECT COUNT(*) c FROM checks").fetchone()["c"]
            findings = self.conn.execute(
                "SELECT COUNT(*) c FROM findings").fetchone()["c"]
            finding_sev = {s: self.conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE severity=?",
                (s,)).fetchone()["c"] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            by_sev = {s: self.conn.execute(
                "SELECT COUNT(*) c FROM vuln_matches WHERE severity=?",
                (s,)).fetchone()["c"] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            return {"hosts": hosts, "services": services, "fingerprints": fps,
                    "matches": matches, "kev": kev, "checks": checks,
                    "findings": findings, "by_finding_severity": finding_sev,
                    "by_severity": by_sev}

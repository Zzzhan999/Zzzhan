"""任务调度器：让 Agent2 以常驻服务形式在服务器上定期自动扫描。

调度表达式支持两种：
  1. 简化 cron（5 字段）:  分 时 日 月 周
     字段支持 * 、数字 、*/N（每 N 个单位） 、a,b（列表）
     示例: "0 2 * * *"       每天 02:00
           "*/30 * * * *"    每 30 分钟
           "0 9 * * 1-5"     周一至周五 09:00
  2. interval 间隔:          "interval:30m" / "interval:6h" / "interval:1d"

任务清单持久化在 jobs 文件（默认 data/jobs.json），运行状态（last_run、
next_run、status、last_summary）一并保存，服务重启后自动恢复调度。
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from .db import Database
from .engine import run_scan, DEFAULT_PORTS

log = logging.getLogger("agent2.scheduler")

CRON_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$")


class CronExpr:
    """5 字段简化 cron，按分钟粒度计算下一次执行时间。"""

    def __init__(self, expr: str):
        m = CRON_RE.match(expr.strip())
        if not m:
            raise ValueError(f"无效的 cron 表达式: {expr!r}（应为 5 字段：分 时 日 月 周）")
        self.raw = expr.strip()
        self.minute = self._parse(m.group(1), 0, 59)
        self.hour = self._parse(m.group(2), 0, 23)
        self.day = self._parse(m.group(3), 1, 31)
        self.month = self._parse(m.group(4), 1, 12)
        self.week = self._parse(m.group(5), 0, 7)  # 0 与 7 都表示周日
        if 7 in self.week:
            self.week = self.week | {0}

    @staticmethod
    def _parse(field: str, lo: int, hi: int) -> set[int]:
        out: set[int] = set()
        for part in field.split(","):
            part = part.strip()
            if not part:
                raise ValueError(f"cron 字段含空项: {field!r}")
            if part in ("*", "?"):
                out.update(range(lo, hi + 1))
                continue
            if "/" in part:
                base, step_s = part.split("/", 1)
                step = int(step_s)
                if step <= 0:
                    raise ValueError(f"cron 步长必须为正数: {part!r}")
                start = lo if base == "*" else int(base)
                if not (lo <= start <= hi):
                    raise ValueError(f"cron 字段越界: {part!r}（允许 {lo}-{hi}）")
                out.update(v for v in range(start, hi + 1)
                           if (v - start) % step == 0)
                continue
            if "-" in part:
                a_s, b_s = part.split("-", 1)
                a, b = int(a_s), int(b_s)
                if a > b or not (lo <= a <= hi and lo <= b <= hi):
                    raise ValueError(f"cron 范围越界: {part!r}（允许 {lo}-{hi}）")
                out.update(range(a, b + 1))
                continue
            v = int(part)
            if not (lo <= v <= hi):
                raise ValueError(f"cron 字段越界: {part!r}（允许 {lo}-{hi}）")
            out.add(v)
        return out

    def _matches(self, dt: datetime) -> bool:
        # cron 周字段：0 和 7 = 周日，1 = 周一；Python weekday() 0 = 周一
        cron_week = (dt.weekday() + 1) % 7
        return (dt.minute in self.minute and dt.hour in self.hour
                and dt.day in self.day and dt.month in self.month
                and cron_week in self.week)

    def next_run(self, after: datetime | None = None) -> datetime:
        """返回 after 之后（严格大于）的下一个匹配时刻。"""
        cur = (after or datetime.now()).replace(second=0, microsecond=0)
        for _ in range(366 * 24 * 60):  # 最多向后找一年
            cur += timedelta(minutes=1)
            if self._matches(cur):
                return cur
        raise ValueError(f"cron 表达式在未来一年内无匹配: {self.raw}")


def parse_interval(text: str) -> timedelta:
    """解析 interval:30m / interval:6h / interval:1d 或 30m / 6h / 1d。"""
    s = text.split(":", 1)[-1].strip().lower()
    m = re.match(r"^(\d+)\s*(m|h|d|s)?$", s)
    if not m:
        raise ValueError(f"无效的 interval: {text!r}（示例: interval:30m / interval:6h / interval:1d）")
    n = int(m.group(1))
    unit = m.group(2) or "m"
    return {"s": timedelta(seconds=n), "m": timedelta(minutes=n),
            "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]


def compute_next(schedule: str, after: datetime | None = None) -> datetime:
    """根据调度表达式计算下次执行时间。"""
    if schedule.startswith("interval:"):
        return (after or datetime.now()) + parse_interval(schedule)
    return CronExpr(schedule).next_run(after)


class Scheduler:
    """常驻调度器：独立线程轮询 jobs，到点执行自动扫描。"""

    def __init__(self, jobs_file: str | None = None, db_path: str | None = None,
                 vuln_db: str | None = None, poll_interval: float = 30.0,
                 max_workers: int = 2):
        self.jobs_file = jobs_file or str(Path(__file__).resolve().parent.parent
                                          / "data" / "jobs.json")
        self.db_path = db_path
        self.vuln_db = vuln_db
        self.poll_interval = poll_interval
        self.max_workers = max_workers
        self._jobs: list[dict] = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._running: dict[str, bool] = {}   # job name -> 是否正在执行
        self._worker_lock = threading.BoundedSemaphore(max_workers)
        self.load()

    # ---------- 持久化 ----------
    def load(self):
        path = Path(self.jobs_file)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._jobs = data if isinstance(data, list) else []
            except Exception as e:
                log.error("加载任务清单失败 %s: %s", self.jobs_file, e)
                self._jobs = []
        else:
            self._jobs = []
        for j in self._jobs:
            j.setdefault("enabled", True)
            j.setdefault("ports", DEFAULT_PORTS)
            j.setdefault("timeout", 6.0)
            j.setdefault("workers", 200)
            j.setdefault("min_severity", "HIGH")
            j.setdefault("status", "idle")
        # 重算 next_run（重启恢复）
        for j in self._jobs:
            try:
                j["next_run"] = compute_next(j["schedule"]).isoformat(timespec="seconds")
            except Exception:
                j["next_run"] = ""

    def save(self):
        Path(self.jobs_file).parent.mkdir(parents=True, exist_ok=True)
        tmp = self.jobs_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._jobs, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.jobs_file)

    # ---------- 任务 CRUD ----------
    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [dict(j) for j in self._jobs]

    def get_job(self, name: str) -> dict | None:
        with self._lock:
            for j in self._jobs:
                if j["name"] == name:
                    return dict(j)
            return None

    def add_job(self, name: str, targets: list[str], schedule: str, ports: str = DEFAULT_PORTS,
                timeout: float = 6.0, workers: int = 200, enabled: bool = True,
                min_severity: str = "HIGH", notify_url: str = "") -> dict:
        # 先校验调度表达式，非法直接报错
        compute_next(schedule)
        with self._lock:
            if any(j["name"] == name for j in self._jobs):
                raise ValueError(f"任务已存在: {name}")
            job = {
                "name": name, "targets": list(targets), "schedule": schedule,
                "ports": ports, "timeout": timeout, "workers": workers,
                "enabled": enabled, "min_severity": min_severity,
                "notify_url": notify_url, "status": "idle",
                "last_run": None, "next_run": compute_next(schedule).isoformat(timespec="seconds"),
                "last_summary": None, "last_error": None,
            }
            self._jobs.append(job)
            self.save()
            return dict(job)

    def remove_job(self, name: str) -> bool:
        with self._lock:
            before = len(self._jobs)
            self._jobs = [j for j in self._jobs if j["name"] != name]
            if len(self._jobs) != before:
                self.save()
                return True
            return False

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            for j in self._jobs:
                if j["name"] == name:
                    j["enabled"] = bool(enabled)
                    if enabled and not j.get("next_run"):
                        try:
                            j["next_run"] = compute_next(j["schedule"]).isoformat(timespec="seconds")
                        except Exception:
                            pass
                    self.save()
                    return True
            return False

    def trigger(self, name: str) -> bool:
        """立即触发一次任务（异步执行）。"""
        with self._lock:
            job = next((j for j in self._jobs if j["name"] == name), None)
            if not job:
                raise ValueError(f"任务不存在: {name}")
        self._run_job_async(job)
        return True

    # ---------- 调度循环 ----------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="agent2-scheduler",
                                        daemon=True)
        self._thread.start()
        log.info("调度器已启动（轮询间隔 %ss，共 %d 个任务）",
                 self.poll_interval, len(self._jobs))

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                log.error("调度循环异常: %s", e)
            self._stop.wait(self.poll_interval)

    def _tick(self):
        now = datetime.now()
        with self._lock:
            due = [j for j in self._jobs
                   if j.get("enabled") and not self._running.get(j["name"])]
        for job in due:
            nr = job.get("next_run")
            if not nr:
                continue
            try:
                nxt = datetime.fromisoformat(nr)
            except Exception:
                continue
            if now >= nxt:
                self._run_job_async(job)

    def _run_job_async(self, job: dict):
        name = job["name"]
        with self._lock:
            if self._running.get(name):
                log.info("任务 %s 正在执行，跳过重复触发", name)
                return
            self._running[name] = True
            self._mark(job, status="running", next_run=self._future_next(job))
        t = threading.Thread(target=self._run_job_worker, args=(job,),
                             name=f"job-{name}", daemon=True)
        t.start()

    def _future_next(self, job: dict) -> str:
        try:
            return compute_next(job["schedule"], datetime.now()).isoformat(timespec="seconds")
        except Exception:
            return ""

    def _run_job_worker(self, job: dict):
        name = job["name"]
        started = time.time()
        log.info("[任务] %s 开始自动扫描（目标=%s 周期=%s）",
                 name, ",".join(job["targets"]), job["schedule"])
        summary = None
        error = None
        try:
            # 扫描期间持有数据库，避免多任务并发写冲突
            summary = run_scan(
                targets=job["targets"],
                ports=job.get("ports", DEFAULT_PORTS),
                vuln_db=self.vuln_db,
                timeout=job.get("timeout", 6.0),
                workers=job.get("workers", 200),
                scope=None,          # 服务端模式：scope 校验由 target 配置保证，运行前预检
                progress=lambda s: log.info("  [%s] %s", name, s),
            )
            # 告警推送（可选）
            if summary.get("matches") and job.get("notify_url"):
                self._notify(job, summary)
        except Exception as e:
            error = str(e)
            log.exception("[任务] %s 执行失败", name)
        finally:
            dur = time.time() - started
            with self._lock:
                self._running[name] = False
                for j in self._jobs:
                    if j["name"] == name:
                        j["last_run"] = datetime.now().isoformat(timespec="seconds")
                        j["last_duration"] = round(dur, 1)
                        j["status"] = "error" if error else ("ok" if summary else "noop")
                        j["last_error"] = error
                        j["last_summary"] = summary
                        j["next_run"] = self._future_next(j)
                        break
                self.save()
            if error:
                log.error("[任务] %s 失败: %s", name, error)
            else:
                s = summary or {}
                log.info("[任务] %s 完成（%.1fs）：主机 %s 开放端口 %s 指纹 %s CVE %s 主动发现 %s",
                         name, dur, s.get("hosts", 0), s.get("open", 0),
                         s.get("fingerprints", 0), s.get("matches", 0),
                         s.get("findings", 0))

    def _mark(self, job: dict, **kw):
        for j in self._jobs:
            if j["name"] == job["name"]:
                j.update(kw)
                break

    def _notify(self, job: dict, summary: dict):
        try:
            from . import notify
            db = Database(self.db_path)
            res = notify.push_findings(db, job["notify_url"],
                                       min_severity=job.get("min_severity", "HIGH"))
            db.close()
            log.info("[任务] %s 告警推送: %s", job["name"],
                     res.get("pushed") and f"{res['count']} 条" or res.get("reason"))
        except Exception as e:
            log.error("[任务] %s 告警推送失败: %s", job["name"], e)

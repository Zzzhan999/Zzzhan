#!/usr/bin/env python3
"""AssetAgent2 CLI 入口 —— 资产自动发现 + 漏洞验证。

用法示例：
  python main.py scope init                       # 生成授权范围模板（data/scope.json）
  python main.py scope show                       # 查看当前授权范围
  python main.py discover subdomains --domain example.com
  python main.py discover ports --host example.com --ports "80,443,8000-8100"
  python main.py discover ports --hosts hosts.txt --ports "80,443,8080,8443"
  python main.py discover fingerprint
  python main.py assets list
  python main.py verify match --vuln-db ../data/vulns.db
  python main.py verify checks
  python main.py verify run --vuln-db ../data/vulns.db
  python main.py run --domain example.com --vuln-db ../data/vulns.db   # 一键全流程
  python main.py report --format html
  python main.py notify push --url <飞书机器人地址>
  python main.py serve --host 0.0.0.0 --port 8000 --token <TOKEN>   # 服务器常驻模式（含定时任务）

红线：只允许扫描授权范围（scope.json）内的资产；验证仅做指纹/版本比对与只读探测。
"""

import argparse
import sys
from pathlib import Path

from asset_agent.db import Database
from asset_agent.scope import load_default, write_template, OutOfScopeError

DEFAULT_PORTS = "80,443,22,21,8080,8443,8000,8888,3306,6379,5432,27017,9200,7001,3389,445,1433"


def _load_scope():
    s = load_default()
    if s.empty:
        print("[!] 未配置授权范围。请先运行: python main.py scope init")
        print("    然后把 scope.json 里的 example.com 换成你自己的资产。")
        sys.exit(2)
    return s


def _open_db(args):
    return Database(getattr(args, "db", None))


# agent2 自身根目录（本文件位于 agent2/main.py）
BASE_DIR = Path(__file__).resolve().parent


def _vuln_db_path(args) -> str:
    p = getattr(args, "vuln_db", None)
    if p:
        return p
    # agent1 的漏洞库默认在项目根 data/vulns.db
    return str(BASE_DIR.parent / "data" / "vulns.db")


def _read_hosts_file(path: str) -> list[str]:
    out = []
    for line in open(path, "r", encoding="utf-8-sig"):
        h = line.strip()
        if h and not h.startswith("#"):
            out.append(h)
    return out


# ---------------- scope ----------------
def cmd_scope_init(args):
    path = args.file or str(BASE_DIR / "data" / "scope.json")
    write_template(path)
    print(f"已生成授权范围模板: {path}")
    print("请把 example.com / 示例 IP 替换为你拥有或已获授权的资产。")


def cmd_scope_show(args):
    s = load_default()
    if s.empty:
        print("当前授权范围: (空) —— 运行 'python main.py scope init' 生成模板")
        return
    print(f"范围文件: {s.path}")
    print(f"当前授权范围: {s.describe()}")


# ---------------- discover ----------------
def cmd_discover_subdomains(args):
    from asset_agent.discovery import subdomains as sd
    scope = _load_scope()
    scope.ensure(args.domain)
    db = _open_db(args)
    print(f"对 {args.domain} 做子域名发现（被动: DNS + 证书透明日志）...")
    res = sd.discover_subdomains(args.domain, use_ct=not args.no_ct,
                                 resolve_names=not args.no_resolve)
    stored = 0
    print(f"\n共发现 {len(res['names'])} 个域名:")
    for n in res["names"]:
        ips = res["resolved"].get(n, [])
        ip_txt = ",".join(ips) if ips else "(未解析)"
        db.upsert_host(n, ip=ips[0] if ips else "", host_type="domain", source="subdomains")
        stored += 1
        print(f"  {n:<40} {ip_txt}")
    if res.get("ct_error"):
        print(f"\n[!] crt.sh 证书透明日志不可用（{res['ct_error']}），已降级为纯 DNS 发现")
    db.log_scan("subdomains", args.domain, f"names={len(res['names'])}")
    print(f"\n已入库 {stored} 个主机。下一步: python main.py discover ports --hosts ...")


def cmd_discover_ports(args):
    from asset_agent.discovery import portscan as ps
    scope = _load_scope()
    db = _open_db(args)
    if args.host:
        hosts = [args.host]
    elif args.hosts:
        hosts = _read_hosts_file(args.hosts)
    else:
        hosts = [h["host"] for h in db.list_hosts()]
    if not hosts:
        print("没有待扫描主机。先 discover subdomains，或用 --host / --hosts 指定。")
        return
    ports = ps.parse_ports(args.ports)
    print(f"扫描 {len(hosts)} 台主机 × {len(ports)} 个端口 "
          f"(timeout={args.timeout}s, workers={args.workers}) ...")
    total_open = 0
    for h in hosts:
        try:
            scope.ensure(h)
        except OutOfScopeError as e:
            print(f"  [跳过] {e}")
            continue
        hid = db.upsert_host(h, source="ports")
        rec = db.get_host(hid) or {}
        ip = rec.get("ip") or h
        opens = ps.scan_host(h, ports, timeout=args.timeout, workers=args.workers)
        for o in opens:
            db.upsert_service(hid, ip=ip, port=o["port"], service=o["service"])
        total_open += len(opens)
        line = ", ".join(f"{o['port']}/{o['service'] or '?'}" for o in opens)
        print(f"  {h:<40} 开放 {len(opens)} 个端口: {line or '-'}")
    db.log_scan("ports", ",".join(hosts)[:200], f"open={total_open}")
    print(f"\n共发现开放端口 {total_open} 个。下一步: python main.py discover fingerprint")


def cmd_discover_fingerprint(args):
    from asset_agent.discovery import fingerprint as fp_mod, webtech
    db = _open_db(args)
    services = db.list_services()
    if args.host:
        services = [s for s in services if s["host_id"] == _host_id_by_name(db, args.host)]
    if not services:
        print("没有服务可做指纹。先运行 discover ports。")
        return
    host_map = {h["id"]: h for h in db.list_hosts()}
    print(f"对 {len(services)} 个开放服务做指纹识别 (timeout={args.timeout}s) ...")
    n_fp = 0
    for sv in services:
        h = host_map.get(sv["host_id"], {})
        target = h.get("ip") or h.get("host") or sv["ip"]
        if not target:
            continue
        try:
            fp = fp_mod.fingerprint_service(target, sv["port"], sv["service"],
                                            timeout=args.timeout)
        except Exception as e:
            print(f"  [!] {target}:{sv['port']} 指纹失败: {e}")
            continue
        http = fp["http"] or {}
        tech = webtech.detect_all(headers=http.get("headers"), body=http.get("body", ""),
                                  banner=fp["banner"])
        db.upsert_service(sv["host_id"], ip=sv["ip"], port=sv["port"],
                          service=fp["service"] or sv["service"],
                          banner=fp["banner"], http_status=http.get("status"),
                          http_title=http.get("title", ""),
                          http_server=(http.get("headers") or {}).get("server", ""),
                          tech=tech, tls=fp["tls"])
        for t in tech:
            db.upsert_fingerprint(sv["host_id"], sv["id"], product=t["product"],
                                  version=t["version"], vendor=t["vendor"],
                                  confidence=1.0, source=t["source"])
            n_fp += 1
        title = http.get("title", "")
        server = (http.get("headers") or {}).get("server", "")
        det = ", ".join(f"{t['product']} {t['version']}".strip() for t in tech) or "-"
        print(f"  {target}:{sv['port']}  [{fp['service'] or '?'}] "
              f"server={server or '-'} title={title[:30] or '-'} tech={det}")
    db.log_scan("fingerprint", "", f"services={len(services)}, fingerprints={n_fp}")
    print(f"\n完成，共识别 {n_fp} 个产品指纹。下一步: python main.py verify run")


def _host_id_by_name(db, name: str) -> int:
    for h in db.list_hosts():
        if h["host"] == name:
            return h["id"]
    print(f"主机不存在: {name}")
    sys.exit(2)


# ---------------- assets ----------------
def cmd_assets_list(args):
    from asset_agent.verify.risk import host_risk, risk_level
    db = _open_db(args)
    hosts = db.list_hosts()
    if not hosts:
        print("暂无资产。先运行 discover subdomains / ports。")
        return
    services = db.list_services()
    fps = db.list_fingerprints()
    matches = db.list_matches()
    svc_map, fp_map, m_map = {}, {}, {}
    for s in services:
        svc_map.setdefault(s["host_id"], 0)
        svc_map[s["host_id"]] += 1
    for f in fps:
        fp_map.setdefault(f["host_id"], 0)
        fp_map[f["host_id"]] += 1
    for m in matches:
        m_map.setdefault(m["host_id"], []).append(m)
    print(f"共 {len(hosts)} 个资产:\n")
    print(f"{'主机':<40}{'IP':<16}{'服务':<5}{'指纹':<5}{'漏洞':<5}{'KEV':<5} 风险")
    for h in hosts:
        ms = m_map.get(h["id"], [])
        risk = host_risk(ms)
        kev = sum(1 for m in ms if m["known_exploited"])
        print(f"{h['host']:<40}{(h['ip'] or '-'):<16}"
              f"{svc_map.get(h['id'], 0):<5}{fp_map.get(h['id'], 0):<5}"
              f"{len(ms):<5}{kev:<5} {risk_level(risk)}({risk}/10)")


# ---------------- verify ----------------
def cmd_verify_match(args):
    from asset_agent.verify import matcher
    db = _open_db(args)
    fps = db.list_fingerprints()
    if not fps:
        print("库内没有指纹。先运行 discover fingerprint。")
        return
    path = _vuln_db_path(args)
    try:
        reader = matcher.VulnDBReader(path)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)
    try:
        print(f"漏洞库: {path}（共 {reader.count()} 条 CVE，只读匹配）")
        print(f"对 {len(fps)} 个指纹做产品/版本匹配 ...")
        res = matcher.run_matching(db, reader)
        st = db.stats()
        print(f"\n匹配完成: 指纹 {res['fingerprints']} 个 -> 命中 {res['matches']} 条")
        print(f"库内累计: 漏洞匹配 {st['matches']} 条（CRITICAL {st['by_severity']['CRITICAL']}, "
              f"HIGH {st['by_severity']['HIGH']}, KEV {st['kev']}）")
    finally:
        reader.close()


def cmd_verify_checks(args):
    from asset_agent.verify import checks as chk
    db = _open_db(args)
    services = db.list_services()
    if args.host:
        hid = _host_id_by_name(db, args.host)
        services = [s for s in services if s["host_id"] == hid]
    targets = [s for s in services if s["http_status"] is not None
               or s["service"] in ("https", "https-alt", "ssl")]
    if not targets:
        print("没有 HTTP(S) 服务可检查。先运行 discover fingerprint。")
        return
    host_map = {h["id"]: h for h in db.list_hosts()}
    print(f"对 {len(targets)} 个 HTTP(S) 服务做非破坏性安全检查 (timeout={args.timeout}s) ...")
    n = 0
    for sv in targets:
        h = host_map.get(sv["host_id"], {})
        target = h.get("ip") or h.get("host") or sv["ip"]
        is_https = sv["service"] in ("https", "https-alt", "ssl") or sv["port"] in (443, 8443)
        http = {"headers": None}
        # 重新做一次轻量 HTTP 探测用于检查（保证数据新鲜）
        from asset_agent.discovery.fingerprint import http_probe
        probe = http_probe(target, sv["port"], timeout=args.timeout, is_https=is_https)
        if probe:
            http = probe
        results = chk.run_checks(target, sv["port"], sv["service"], http,
                                 is_https, timeout=args.timeout)
        for r in results:
            db.add_check(sv["host_id"], sv["id"], r["name"], r["status"], r["detail"])
            n += 1
            flag = {"warning": "!", "ok": "+", "info": " "}[r["status"]]
            print(f"  [{flag}] {target}:{sv['port']}  {r['name']:<22} {r['detail'][:80]}")
    db.log_scan("checks", "", f"findings={n}")
    print(f"\n完成，共记录 {n} 条检查结果。")


def cmd_verify_explore(args):
    """主动漏洞检测（只读、非破坏）。"""
    from asset_agent.verify import explore
    db = _open_db(args)
    services = db.list_services()
    if args.host:
        hid = _host_id_by_name(db, args.host)
        services = [s for s in services if s["host_id"] == hid]
    if not services:
        print("没有服务可检测。先运行 discover ports / fingerprint。")
        return
    print(f"对 {len(services)} 个服务做主动漏洞检测 (timeout={args.timeout}s) ...")
    findings = explore.run_explore(db, timeout=args.timeout, services=services)
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))
    for f in findings:
        flag = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[ ]",
                "INFO": "[i]"}.get(f["severity"], "[?]")
        print(f"  {flag} [{f['severity']:<8}] {f['name']}  {f['evidence'][:90]}")
    db.log_scan("explore", "", f"findings={len(findings)}")
    print(f"\n完成，共发现 {len(findings)} 个问题。")


def cmd_verify_run(args):
    cmd_verify_match(args)
    print()
    cmd_verify_checks(args)


# ---------------- run / report / notify ----------------
def cmd_run(args):
    from asset_agent.discovery import subdomains as sd
    from asset_agent.discovery import portscan as ps
    from asset_agent.discovery import fingerprint as fp_mod, webtech
    from asset_agent.verify import matcher, checks as chk
    scope = _load_scope()
    db = _open_db(args)
    domain = args.domain
    scope.ensure(domain)
    print(f"===== Agent2 一键流水线: {domain} =====")

    print("\n[1/6] 子域名发现 ...")
    sd_res = sd.discover_subdomains(domain, use_ct=not args.no_ct)
    targets = []
    for n in sd_res["names"]:
        ips = sd_res["resolved"].get(n, [])
        db.upsert_host(n, ip=ips[0] if ips else "", host_type="domain", source="subdomains")
        targets.append((n, ips[0] if ips else n))
    print(f"  发现 {len(sd_res['names'])} 个域名")

    print("\n[2/6] 端口扫描 ...")
    ports = ps.parse_ports(args.ports)
    open_map = {}
    for name, ip in targets:
        try:
            scope.ensure(name)
        except OutOfScopeError:
            continue
        hid = db.upsert_host(name, source="ports")
        opens = ps.scan_host(ip, ports, timeout=args.timeout, workers=args.workers)
        for o in opens:
            db.upsert_service(hid, ip=ip, port=o["port"], service=o["service"])
        open_map[hid] = opens
    n_open = sum(len(v) for v in open_map.values())
    print(f"  共开放 {n_open} 个端口")

    print("\n[3/6] 服务指纹识别 ...")
    n_fp = 0
    for sv in db.list_services():
        h = db.get_host(sv["host_id"]) or {}
        target = h.get("ip") or h.get("host") or sv["ip"]
        try:
            fp = fp_mod.fingerprint_service(target, sv["port"], sv["service"],
                                            timeout=args.timeout)
        except Exception:
            continue
        http = fp["http"] or {}
        tech = webtech.detect_all(headers=http.get("headers"), body=http.get("body", ""),
                                  banner=fp["banner"])
        db.upsert_service(sv["host_id"], ip=sv["ip"], port=sv["port"],
                          service=fp["service"] or sv["service"], banner=fp["banner"],
                          http_status=http.get("status"), http_title=http.get("title", ""),
                          http_server=(http.get("headers") or {}).get("server", ""),
                          tech=tech, tls=fp["tls"])
        for t in tech:
            db.upsert_fingerprint(sv["host_id"], sv["id"], t["product"], t["version"],
                                  t["vendor"], 1.0, t["source"])
            n_fp += 1
    print(f"  识别 {n_fp} 个产品指纹")

    print("\n[4/6] 漏洞匹配（只读 agent1 漏洞库）...")
    path = _vuln_db_path(args)
    try:
        reader = matcher.VulnDBReader(path)
        m_res = matcher.run_matching(db, reader)
        print(f"  漏洞库 {reader.count()} 条 CVE -> 命中 {m_res['matches']} 条")
        reader.close()
    except FileNotFoundError as e:
        print(f"  [!] {e}（跳过匹配，报告不含漏洞明细）")

    print("\n[5/6] 非破坏性安全检查 ...")
    n_chk = 0
    for sv in db.list_services():
        if sv["http_status"] is None and sv["service"] not in ("https", "https-alt", "ssl"):
            continue
        h = db.get_host(sv["host_id"]) or {}
        target = h.get("ip") or h.get("host") or sv["ip"]
        is_https = sv["service"] in ("https", "https-alt", "ssl") or sv["port"] in (443, 8443)
        probe = fp_mod.http_probe(target, sv["port"], timeout=args.timeout, is_https=is_https)
        results = chk.run_checks(target, sv["port"], sv["service"], probe or {"headers": None},
                                 is_https, timeout=args.timeout)
        for r in results:
            db.add_check(sv["host_id"], sv["id"], r["name"], r["status"], r["detail"])
            n_chk += 1
    print(f"  记录 {n_chk} 条检查结果")

    print("\n[6/6] 生成报告并保存快照 ...")
    path = _gen_report(db, "html")
    print(f"  报告: {path}")
    snap_id = db.capture_snapshot(source=f"run:{domain}")
    print(f"  快照已保存: #{snap_id}（用 python main.py snapshot diff --from 上次ID 查看变化）")
    db.log_scan("run", domain, f"subdomains={len(sd_res['names'])}, open={n_open}, "
                               f"fingerprints={n_fp}, checks={n_chk}, snapshot={snap_id}")
    print("\n===== 流水线完成 =====")
    print("下一步: python main.py assets list / python main.py report --format md")


def cmd_scan(args):
    """自动扫描：给一个测试范围（域名/IP/文件），agent 自动找漏洞并出报告。"""
    from asset_agent import engine
    scope = _load_scope()
    db = _open_db(args)

    if args.targets:
        targets = engine.read_hosts_file(args.targets)
    elif args.target:
        targets = [args.target]
    else:
        print("请用 --target <域名/IP> 或 --targets <文件> 指定测试范围。")
        sys.exit(2)
    print(f"===== Agent2 自动扫描: {len(targets)} 个目标 =====")

    summary = engine.run_scan(
        targets=targets,
        ports=args.ports,
        vuln_db=_vuln_db_path(args) if _vuln_db_path(args) else None,
        timeout=args.timeout,
        workers=args.workers,
        no_ct=args.no_ct,
        scope=scope,
        db=db,
        progress=print,
    )

    # ---- 结论摘要 ----
    print("\n===== 扫描完成 =====")
    st = db.stats()
    print(f"主机 {summary['hosts']} | 开放端口 {summary['open']} | 指纹 {summary['fingerprints']} | "
          f"CVE 匹配 {summary['matches']} | 主动发现 {summary['findings']} | 安全检查 {summary['checks']}")
    if summary.get("rejected"):
        print(f"[拒绝] 越界目标 {len(summary['rejected'])} 个: {', '.join(summary['rejected'])}")
    if summary.get("notice"):
        for n in summary["notice"]:
            print(f"[提示] {n}")
    if summary.get("findings"):
        from asset_agent.verify import explore
        print("高风险问题:")
        for f in db.list_findings(min_severity="HIGH"):
            print(f"  - [{f['severity']}] {f['name']}: {f['evidence'][:80]}")
    if summary.get("report"):
        print(f"完整报告: {summary['report']}")
    print("下一步: python main.py web（浏览器看仪表盘）/ python main.py export")


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _looks_like_domain(s: str) -> bool:
    return "." in s and not s.startswith(("http://", "https://"))


def _gen_report(db, fmt: str):
    from asset_agent import report
    return report.generate(db, fmt=fmt)


def cmd_report(args):
    db = _open_db(args)
    path = _gen_report(db, args.format)
    print(f"报告已生成: {path}")


def cmd_export(args):
    from asset_agent import export as export_mod
    db = _open_db(args)
    paths = export_mod.export_all(db, fmt=args.format, out=args.output)
    print(f"已导出 {len(paths)} 个文件:")
    for p in paths:
        print(f"  {p}")


def cmd_snapshot(args):
    db = _open_db(args)
    if args.action == "save":
        sid = db.capture_snapshot(source="cli")
        print(f"已保存快照 #{sid}")
    elif args.action == "list":
        snaps = db.list_snapshots()
        if not snaps:
            print("暂无快照。运行 run 流水线或 snapshot save 保存。")
            return
        print(f"共 {len(snaps)} 个快照:")
        for s in snaps:
            print(f"  #{s['id']:<4} {s['taken_at']}  {s['source'] or '手动'}  "
                  f"{s['size']}B")
    elif args.action == "diff":
        if not args.from_id:
            print("请用 --from <快照ID> 指定对比基准，可用 --to 指定另一个快照（缺省对比当前状态）。")
            return
        try:
            d = db.diff_snapshots(args.from_id, args.to_id)
        except ValueError as e:
            print(f"[!] {e}")
            return
        print(f"对比: 快照 #{d['from']} ({d['from_time']}) -> "
              f"{'快照 #%d' % d['to'] + ' (' + d['to_time'] + ')' if d['to'] else d['to_time']}")
        for key, label in (("hosts", "主机"), ("services", "服务"),
                           ("fingerprints", "指纹"), ("matches", "漏洞")):
            added, removed = d["diff"][key]["added"], d["diff"][key]["removed"]
            if not added and not removed:
                continue
            print(f"[{label}]")
            for it in added:
                print(f"  + {', '.join(str(x) for x in it)}")
            for it in removed:
                print(f"  - {', '.join(str(x) for x in it)}")
        total_a = sum(len(d["diff"][k]["added"]) for k in d["diff"])
        total_r = sum(len(d["diff"][k]["removed"]) for k in d["diff"])
        if total_a == 0 and total_r == 0:
            print("两个时点之间没有任何变化。")
    elif args.action == "delete":
        if not args.from_id:
            print("请用 --from <快照ID> 指定要删除的快照。")
            return
        ok = db.delete_snapshot(args.from_id)
        print("已删除快照" if ok else "快照不存在")


def cmd_notify_push(args):
    from asset_agent import notify
    db = _open_db(args)
    if not args.url:
        print("请用 --url 指定飞书机器人 Webhook 或通用 Webhook 地址。")
        sys.exit(2)
    res = notify.push_findings(db, args.url, min_severity=args.min_severity,
                               channel=args.channel)
    if res["pushed"]:
        print(f"已推送 {res['count']} 条版本命中漏洞（≥{args.min_severity}）")
        print(f"通道响应: {res['response'][:200]}")
    else:
        print(f"未推送: {res['reason']}")


def cmd_web(args):
    from asset_agent.webui import serve
    serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def cmd_serve(args):
    """服务器常驻模式：Web 服务 + 定时任务调度 + 认证 + 日志。"""
    import logging
    from logging.handlers import RotatingFileHandler
    from asset_agent.scheduler import Scheduler

    # 日志：控制台 + 滚动文件
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    handlers = [logging.StreamHandler()]
    try:
        handlers.append(RotatingFileHandler(
            log_dir / "agent2.log", maxBytes=5 * 1024 * 1024, backupCount=5,
            encoding="utf-8"))
    except Exception as e:
        print(f"[!] 日志文件不可用({e})，仅输出到控制台")
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=handlers)
    log = logging.getLogger("agent2")

    # 授权范围（服务模式允许空范围启动，调度时越界目标会被拒绝）
    from asset_agent.scope import load_default
    scope = load_default()
    if scope.empty:
        log.warning("授权范围为空！调度任务中的越界目标将被拒绝（请先 python main.py scope init）")

    # 调度器
    scheduler = Scheduler(jobs_file=args.jobs, db_path=args.db,
                          vuln_db=args.vuln_db or None,
                          poll_interval=args.poll)
    n_jobs = len(scheduler.list_jobs())
    log.info("已加载 %d 个定时任务（%s）", n_jobs, args.jobs)

    # Web 服务（含认证与任务 API）
    from asset_agent.webui import serve
    print(f"[Agent2 服务器模式] 监听 {args.host}:{args.port}")
    print(f"  Token 认证: {'已启用' if args.token else '未启用（仅限本机/受信网络使用！）'}")
    print(f"  定时任务: {n_jobs} 个 | 漏洞库: {args.vuln_db or '(未指定，跳过 CVE 匹配)'}")
    serve(host=args.host, port=args.port, open_browser=False,
          token=args.token, scheduler=scheduler, db_path=args.db,
          vuln_db=args.vuln_db)


# ---------------- parser ----------------
def build_parser():
    p = argparse.ArgumentParser(prog="agent2", description="资产自动发现 + 漏洞验证 Agent",
                                epilog="红线: 仅扫描授权范围(scope.json)内的资产，验证仅做只读探测")
    p.add_argument("--db", help="agent2 数据库路径（默认 data/assets.db）")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scope", help="授权范围管理")
    sp.add_argument("action", choices=["init", "show"])
    sp.add_argument("--file", help="模板输出路径（init 用）")

    sp = sub.add_parser("discover", help="资产发现")
    sp.add_argument("action", choices=["subdomains", "ports", "fingerprint"])
    sp.add_argument("--domain", help="目标域名（subdomains）")
    sp.add_argument("--no-ct", action="store_true", help="跳过证书透明日志枚举")
    sp.add_argument("--no-resolve", action="store_true", help="不做 DNS 解析")
    sp.add_argument("--host", help="单台主机（ports/fingerprint）")
    sp.add_argument("--hosts", help="主机列表文件（ports）")
    sp.add_argument("--ports", default=DEFAULT_PORTS, help="端口列表，如 80,443,8000-8100")
    sp.add_argument("--timeout", type=float, default=2.0, help="连接超时秒数")
    sp.add_argument("--workers", type=int, default=200, help="端口扫描并发数")

    sub.add_parser("assets", help="资产清单").add_argument("action", choices=["list"])

    sp = sub.add_parser("verify", help="漏洞验证")
    sp.add_argument("action", choices=["match", "explore", "checks", "run"])
    sp.add_argument("--vuln-db", help="agent1 漏洞库路径（默认 ../data/vulns.db）")
    sp.add_argument("--host", help="只处理指定主机")
    sp.add_argument("--timeout", type=float, default=6.0, help="HTTP/TLS 探测超时")

    sp = sub.add_parser("run", help="一键流水线: 子域名->端口->指纹->匹配->检查->报告")
    sp.add_argument("--domain", required=True, help="目标域名（须在授权范围内）")
    sp.add_argument("--ports", default=DEFAULT_PORTS)
    sp.add_argument("--vuln-db", help="agent1 漏洞库路径")
    sp.add_argument("--no-ct", action="store_true")
    sp.add_argument("--timeout", type=float, default=2.0)
    sp.add_argument("--workers", type=int, default=200, help="端口扫描并发数")

    sp = sub.add_parser("scan", help="自动扫描: 给测试范围, agent 自动找漏洞并出报告")
    sp.add_argument("--target", help="目标域名/IP（须在授权范围内）")
    sp.add_argument("--targets", help="目标列表文件（每行一个域名/IP）")
    sp.add_argument("--ports", default=DEFAULT_PORTS)
    sp.add_argument("--vuln-db", help="agent1 漏洞库路径")
    sp.add_argument("--no-ct", action="store_true", help="跳过证书透明日志")
    sp.add_argument("--timeout", type=float, default=2.0, help="连接超时秒数")
    sp.add_argument("--workers", type=int, default=200, help="端口扫描并发数")

    sp = sub.add_parser("report", help="生成报告")
    sp.add_argument("--format", choices=["html", "md"], default="html")

    sp = sub.add_parser("export", help="导出资产/漏洞/检查结果")
    sp.add_argument("--format", choices=["csv", "json", "md"], default="csv")
    sp.add_argument("--output", help="输出目录（默认 data/exports）")

    sp = sub.add_parser("snapshot", help="状态快照与差异对比")
    sp.add_argument("action", choices=["save", "list", "diff", "delete"])
    sp.add_argument("--from", dest="from_id", type=int, help="基准快照 ID")
    sp.add_argument("--to", dest="to_id", type=int, help="对比快照 ID（缺省=当前状态）")

    sp = sub.add_parser("web", help="启动本地 Web 仪表盘")
    sp.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    sp.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    sp.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")

    sp = sub.add_parser("serve", help="服务器常驻模式：Web 服务 + 定时扫描 + 认证 + 日志")
    sp.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    sp.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    sp.add_argument("--token", default="", help="Bearer Token 认证（建议 32+ 位随机串）")
    sp.add_argument("--jobs", default=str(BASE_DIR / "data" / "jobs.json"),
                    help="定时任务清单文件（默认 data/jobs.json）")
    sp.add_argument("--vuln-db", help="agent1 漏洞库路径（默认 ../data/vulns.db）")
    sp.add_argument("--poll", type=float, default=30.0, help="调度轮询间隔秒数")
    sp.add_argument("--log-dir", default=str(BASE_DIR / "data" / "logs"),
                    help="日志目录（默认 data/logs）")
    sp.add_argument("--log-level", default="info",
                    choices=["debug", "info", "warning", "error"],
                    help="日志级别（默认 info）")

    sp = sub.add_parser("notify", help="告警推送")
    sp.add_argument("action", choices=["push"])
    sp.add_argument("--url", help="飞书机器人 Webhook 或通用 Webhook 地址")
    sp.add_argument("--channel", choices=["feishu", "webhook"], default="feishu")
    sp.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default="HIGH")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scope":
            {"init": cmd_scope_init, "show": cmd_scope_show}[args.action](args)
        elif args.command == "discover":
            {"subdomains": cmd_discover_subdomains, "ports": cmd_discover_ports,
             "fingerprint": cmd_discover_fingerprint}[args.action](args)
        elif args.command == "assets":
            cmd_assets_list(args)
        elif args.command == "verify":
            {"match": cmd_verify_match, "explore": cmd_verify_explore,
             "checks": cmd_verify_checks, "run": cmd_verify_run}[args.action](args)
        elif args.command == "run":
            cmd_run(args)
        elif args.command == "scan":
            cmd_scan(args)
        elif args.command == "report":
            cmd_report(args)
        elif args.command == "export":
            cmd_export(args)
        elif args.command == "snapshot":
            cmd_snapshot(args)
        elif args.command == "web":
            cmd_web(args)
        elif args.command == "serve":
            cmd_serve(args)
        elif args.command == "notify":
            cmd_notify_push(args)
    except OutOfScopeError as e:
        print(f"[拒绝] {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()

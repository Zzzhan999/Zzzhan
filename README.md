# Agent2 — 资产自动发现 + 漏洞验证

与 `../vuln_agent`（agent1，漏洞情报收集 + 资产风险监测）配套的 **agent2**：对**已授权**的资产做自动发现，并基于指纹 + CPE 版本范围与 agent1 的漏洞库做**非破坏性、证据链式**的漏洞验证。

**纯 Python 标准库实现，零第三方依赖**，Python 3.10+ 即可运行（与 agent1 一致）。

> 用途定位：自有/已授权资产的防御性资产盘点和漏洞验证。只读探测，不包含任何利用、暴力破解或破坏性操作。

---

## 安全红线（设计内建，不可绕过）

1. **授权范围强制**：所有发现/验证动作先通过 `data/scope.json` 白名单检查（域名/子域名/IP/CIDR），越界目标直接拒绝。
2. **验证 = 证据链 + 只读探测**：版本级结论来自指纹（banner/响应头/TLS 证书）→ CPE 版本范围比对；主动漏洞检测仅做只读 GET/OPTIONS 与响应分析，**不含任何攻击载荷、爆破或利用动作**。
3. **只读 agent1 漏洞库**：以 `mode=ro` 打开 `../data/vulns.db`，绝不写入。
4. **只扫描自己拥有或已获书面授权的资产**：未经授权扫描在多数司法辖区违法（中国大陆适用《网络安全法》《刑法》第 285 条）。

---

## 快速开始（自动扫描模式 ⭐）

给一个**测试范围**（域名 / IP / 列表文件），agent 自动完成：范围校验 → 子域名展开 → 端口扫描 → 指纹识别 → 漏洞库匹配 → **主动漏洞检测** → 安全检查 → 报告。

```bash
cd D:\ku\VScode\漏洞收集agent\agent2

# 0. 一次性准备：生成授权范围并编辑（把示例换成你的资产）
python main.py scope init
#    编辑 data/scope.json，例如 {"domains":["你的域名"], "ips":["x.x.x.x"]}

# 1. 自动扫描一个域名（含其子域名）
python main.py scan --target your-domain.com --vuln-db ..\data\vulns.db

# 2. 自动扫描一个 IP / 主机（跳过子域名展开）
python main.py scan --target 10.0.0.5

# 3. 批量扫描一个文件里的多个目标（每行一个域名/IP）
python main.py scan --targets hosts.txt

# 4. 浏览器看结果
python main.py web
```

扫描完成后会自动生成 HTML 报告（`data/reports/`）并保存快照，终端会直接打印高风险问题清单。

分步执行（进阶）：

```bash
# 子域名被动发现（DNS + crt.sh 证书透明日志，不发探测包）
python main.py discover subdomains --domain your-domain.com

# 端口扫描（TCP connect，多线程）
python main.py discover ports --host www.your-domain.com --ports "80,443,8000-8100"
python main.py discover ports --hosts hosts.txt --ports "80,443,8080,8443"

# 服务指纹识别（banner / HTTP 头 / 标题 / TLS 证书）
python main.py discover fingerprint

# 查看资产清单与风险
python main.py assets list

# 漏洞匹配（只读 agent1 漏洞库）
python main.py verify match --vuln-db ..\data\vulns.db

# 主动漏洞检测（只读、非破坏）
python main.py verify explore

# 非破坏性安全检查（响应头 / 暴露端点 / TRACE / TLS 证书有效期）
python main.py verify checks

# 生成报告（html 可浏览器打印 PDF；md 纯文本）
python main.py report --format html
python main.py report --format md
```

---

## 功能总览

| 阶段 | 能力 | 入口 | 说明 |
| --- | --- | --- | --- |
| 资产发现 | 子域名枚举 | `discover subdomains` | DNS 解析 + crt.sh 证书透明日志（被动） |
| 资产发现 | 端口扫描 | `discover ports` | TCP connect 多线程，范围/超时/并发可调 |
| 资产发现 | 服务指纹 | `discover fingerprint` | Banner / HTTP 响应头 / 页面标题 / TLS 证书 |
| 资产发现 | 技术栈识别 | （指纹内置） | nginx/apache/iis/tomcat/wordpress/php/openssh 等 CPE 词汇对齐 |
| 漏洞验证 | 漏洞库匹配 | `verify match` | 指纹 → CPE/受影响产品 → 版本范围 → exact/product 结论 |
| 漏洞验证 | 主动漏洞检测 | `verify explore` / `scan` | 只读探测：Actuator 未授权、源码/密钥/备份泄露、目录列表、CORS 配置错误、管理后台暴露、数据库端口开放等 |
| 漏洞验证 | 安全检查 | `verify checks` | 安全响应头缺失、常见暴露端点、TRACE、证书有效期（只读 GET） |
| 风险评分 | 0-10 分 | `assets list` | 级别权重 + CVSS + KEV 加权（与 agent1 口径一致） |
| 报告 | HTML / Markdown | `report` | 资产风险总览、漏洞明细（含匹配证据）、检查结果、处置建议 |
| 告警 | 飞书/Webhook | `notify push` | 只推送 exact（版本命中）且达到级别的漏洞 |
| Web 仪表盘 | 浏览器访问 | `web` | 概览/资产/漏洞/检查/快照差异 5 个视图，无需依赖 |
| 导出 | CSV / JSON / MD | `export` | 资产清单、漏洞匹配、检查结果一键导出 |
| 快照差异 | 状态对比 | `snapshot` | 两次时点之间的主机/服务/指纹/漏洞增删对比 |

---

## 漏洞验证的判定规则（重要）

匹配是**证据链式验证**，结论分级：

| 匹配级别 | 含义 | 处置建议 |
| --- | --- | --- |
| `exact` | 指纹版本落在 CPE 版本/范围内（或版本精确相等） | 高可信，优先处置 |
| `product` | 产品命中但无版本信息 / CVE 无 CPE 版本数据 | 保守标记，**先人工确认版本**再定优先级 |

判定细节：
- CPE 列表包含该产品时：任一 CPE 满足版本范围 → 命中；所有 CPE 都排除该版本 → **判为不适用**（不回退产品级，避免误报）。
- CVE 完全没有 CPE 数据时：回退到 `affected_products` 产品级匹配（如 CVE-2012-1823 只有 `PHP:PHP`，对任意 PHP 版本都只标 product）。
- 产品名做下划线归一化 + 别名对齐（`http_server` ↔ `apache http server`），并禁止反向包含误配（如 `nginx` 不会误配 `NGINX JavaScript` 模块的 CVE）。

> 结论不代表可利用性确认。`exact` 表示"版本证据链闭合"，实际可利用性需结合资产部署形态判断。

---

## 安全检查项（全部非破坏性）

| 检查项 | 说明 | 触发 warning |
| --- | --- | --- |
| `security_headers` | HSTS / X-Content-Type-Options / X-Frame-Options / CSP / Referrer-Policy | 任一缺失 |
| `cookie_flags` | Set-Cookie 是否缺少 Secure / HttpOnly / SameSite | 任一缺失（无 Cookie 时跳过） |
| `exposed:...` | `/actuator/env` `/.git/HEAD` `/phpinfo.php` `/server-status` `/admin/` `/swagger-ui.html` `/robots.txt` `/.env` `/backup.zip` | 管理端点/源码/密钥文件/备份公开可见 |
| `http_trace` | 服务器是否允许 TRACE 方法（跨站追踪） | 允许 |
| `tls_cert` | TLS 证书有效期（剩余 ≤30 天 / 已过期） | 临近/过期 |

所有探测均为只读 GET/OPTIONS/TLS 握手，不携带任何载荷。

---

## 主动漏洞检测项（scan / verify explore）

全部为只读、非破坏性检测，无利用载荷、无爆破、无写入：

| 检测项 | 漏洞 | 级别 |
| --- | --- | --- |
| `actuator` | Spring Boot Actuator 端点未授权访问（/env、/mappings、/health 等） | HIGH/MEDIUM |
| `git` / `svn` | .git / .svn 源码版本库泄露 | HIGH/MEDIUM |
| `env` | /.env 环境变量文件泄露（密钥） | HIGH |
| `backup` / `db` | 备份包 / 数据库文件可下载（/backup.zip、/dump.sql 等） | HIGH |
| `dir_listing` | Web 目录列表开启（Index of /） | MEDIUM |
| `cors` | CORS 配置错误（反射任意 Origin / 允许携带凭证） | HIGH/MEDIUM/LOW |
| `admin` | 管理后台 / Tomcat 管理界面暴露 | MEDIUM |
| `phpinfo` | PHP 探针暴露 | MEDIUM |
| `swagger` | API 文档公开可见 | MEDIUM |
| `db_port` | 数据库/中间件端口对外开放（3306/6379/9200 等） | MEDIUM |
| `headers` / `cookie` | 安全响应头缺失 / Cookie 缺安全标志 | LOW |
| `version` | Server/X-Powered-By 泄露版本信息 | INFO |
| `tls` | TLS 证书过期/即将到期 | MEDIUM/LOW |
| `robots` | robots.txt 泄露敏感路径 | INFO |

每条发现都带**证据**（URL + 响应片段）与**修复建议**，入库 `findings` 表，报告与 Web 仪表盘均可查看。

## Web 仪表盘

```bash
python main.py web
# 浏览器自动打开 http://127.0.0.1:8000
```

- 纯标准库 `http.server`，无前端构建、无外部依赖，离线可用。
- 视图：**概览**（统计 + 扫描日志 + 生成报告/导出/保存快照）、**资产**（含单资产详情：服务/指纹/漏洞/检查）、**漏洞**、**检查**、**任务**（定时任务管理，服务器模式）、**快照差异**（选两个时点对比增删）。
- 只监听 `127.0.0.1`（默认），如需局域网访问自行用 `--host` 指定并确保网络可信。

## 服务器部署与运营（⭐ 常驻模式）

`serve` 命令把 Agent2 变成**长期运行的服务**：Web 仪表盘 + 定时自动扫描 + Token 认证 + 滚动日志，适合部署到服务器上持续运营。

```bash
# 本地先体验（Windows 也支持）
python main.py serve --host 127.0.0.1 --port 8000 --token "换成一个长随机串" \
    --vuln-db ..\data\vulns.db --jobs data\jobs.json
```

启动后：
- 浏览器打开 `http://127.0.0.1:8000/?token=你的Token`（页面放行，**API 全部要求 Bearer Token**）
- 未带 Token 访问 `/api/*` 返回 401；前端页面登录后自动携带 Token（存 localStorage）

**定时任务（jobs）**：任务清单存在 `data/jobs.json`，调度表达式支持两种：
- 简化 cron（5 字段）：`0 2 * * *`（每天 02:00）、`*/30 * * * *`（每 30 分钟）、`0 9 * * 1-5`（工作日 09:00）
- interval 间隔：`interval:30m` / `interval:6h` / `interval:1d`

```bash
python main.py serve --jobs data\jobs.json --poll 30
```

任务可以在 Web「任务」页创建/启停/立即运行/删除，也可直接编辑 jobs.json（参考 `jobs.example.json`）。每次执行自动：范围校验 → 目标展开 → 端口 → 指纹 → 漏洞库匹配 → 主动检测 → 安全检查 → 报告 + 快照，并记录 `last_run/last_summary/状态`。

**认证说明**：服务器对外暴露务必设置 `--token`（32+ 位随机串），否则任何能访问端口的人都能调 API。

### 部署到 Linux 服务器

**方式一：Docker（推荐）**

```bash
cd deploy
# 1. 编辑 docker-compose.yml：改 AGENT2_TOKEN、vulns.db 挂载路径
docker compose up -d --build
docker compose logs -f agent2
```

**方式二：systemd 直接部署**

```bash
sudo bash deploy/install.sh
# 脚本自动：建 agent2 用户 → 拷贝代码到 /opt/agent2 → 生成 Token（/etc/agent2/env）
#           → 安装并启动 agent2.service
sudo cat /etc/agent2/env          # 查看访问 Token
systemctl status agent2           # 查看服务状态
journalctl -u agent2 -f           # 查看运行日志
```

部署后必做：
1. 编辑 `/opt/agent2/data/scope.json` 填入**书面授权资产**（法律红线，越界目标会被拒绝）
2. 编辑 `/opt/agent2/data/jobs.json` 按需启用定时任务
3. 确认漏洞库路径（`AGENT2_VULN_DB`）指向 agent1 的 vulns.db

### 服务 API（认证后）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 服务状态（运行时长/任务数/队列） |
| GET | `/api/jobs` | 任务列表 |
| POST | `/api/jobs` | 创建任务 `{name, targets[], schedule, ports}` |
| POST | `/api/jobs/run?id=<名>` | 立即运行 |
| POST | `/api/jobs/enable?id=<名>&enabled=0\|1` | 启停 |
| DELETE | `/api/jobs?id=<名>` | 删除 |

---

## 快照差异

`run` 一键流水线结束会自动保存一个全量快照；可随时手动对比任意两次时点，用于回答"这轮扫描相比上次多了/少了什么"：

```bash
python main.py snapshot list                # 查看所有快照
python main.py snapshot diff --from 3       # 快照#3 vs 当前状态
python main.py snapshot diff --from 3 --to 5  # 快照#3 vs 快照#5
```

对比维度：主机（host+IP）、服务（host+port+service）、指纹（host+product+version）、漏洞（host+CVE+severity+match_level），各自输出新增 `+` / 消失 `-`。

---

## 授权范围（scope.json）

```json
{
  "note": "只允许扫描你拥有或已获书面授权的资产……",
  "domains": ["example.com"],        // 含其全部子域名
  "ips": ["203.0.113.10"],
  "cidrs": ["198.51.100.0/24"]
}
```

- 加载优先级：环境变量 `AGENT2_SCOPE` > `data/scope.json` > `./scope.json`
- 范围为空时所有发现命令拒绝执行；越界目标按主机跳过并提示。
- `scope.example.json` 是提交到版本库的模板副本（`data/` 已在 `.gitignore` 中）。

---

## 与 agent1 的关系

```
agent1 (vuln_agent)                    agent2 (agent2)
──────────────────                    ─────────────────────
NVD/CISA KEV/CVE.org/GHSA   ──►  data/vulns.db  ──(只读)──►  verify match（指纹→CPE→结论）
漏洞情报库 / 资产风险监测                      资产自动发现：子域名/端口/指纹/技术栈
                                              verify checks：非破坏性安全检查
                                              report：证据链式验证报告
```

- agent2 的库 `data/assets.db` 只保存**发现与验证结果**（主机/服务/指纹/匹配/检查）。
- `verify match` 默认找 `../data/vulns.db`，可用 `--vuln-db` 指定；漏洞库不存在时提示先跑 agent1 的 `python main.py sync`。
- 数据流闭环：agent1 持续同步漏洞 → agent2 发现资产并验证 → 报告/告警。

---

## 命令参考

| 命令 | 说明 |
| --- | --- |
| `scope init` / `scope show` | 生成/查看授权范围 |
| `discover subdomains --domain X` | 子域名被动发现（`--no-ct` 跳过证书日志） |
| `discover ports --host X --ports "80,443,8000-8100"` | 端口扫描（`--hosts` 支持文件列表） |
| `discover fingerprint` | 服务指纹 + 技术栈识别 |
| `assets list` | 资产清单与风险评分 |
| `verify match --vuln-db PATH` | 漏洞库匹配（只读） |
| `verify checks` | 非破坏性安全检查 |
| `verify run` | 匹配 + 检查 |
| `run --domain X` | 一键全流程（发现→扫描→指纹→匹配→检查→报告） |
| `scan --target X / --targets FILE` | **自动扫描**：给测试范围，agent 自动找漏洞并出报告 |
| `report --format html\|md` | 生成报告 |
| `export --format csv\|json\|md [--output DIR]` | 导出资产/漏洞/检查结果 |
| `snapshot save\|list\|diff\|delete [--from N] [--to N]` | 状态快照与差异对比 |
| `web [--host H] [--port P] [--no-browser]` | 启动本地 Web 仪表盘 |
| `notify push --url WEBHOOK` | 推送版本命中漏洞告警（飞书/Webhook） |

通用参数：`--db`（agent2 数据库路径）、`--timeout`、`--workers`。

---

## 项目结构

```
agent2/
├── main.py                    # CLI 入口
├── scope.example.json         # 授权范围模板（入库）
├── .gitignore
├── data/                      # 运行时生成（不入库）
│   ├── scope.json             # 授权范围（用户编辑）
│   ├── assets.db              # 发现/验证结果库
│   ├── reports/               # 生成的报告
│   └── exports/               # 导出文件
├── webui/
│   └── index.html             # Web 仪表盘前端（单文件）
├── asset_agent/
│   ├── db.py                  # SQLite：主机/服务/指纹/匹配/检查/扫描日志/快照
│   ├── scope.py               # 授权范围解析与强制检查
│   ├── webui.py               # 本地 Web 仪表盘（http.server + JSON API）
│   ├── export.py              # 导出 CSV/JSON/Markdown
│   ├── discovery/
│   │   ├── subdomains.py      # DNS + crt.sh 子域名发现（被动）
│   │   ├── portscan.py        # TCP connect 多线程端口扫描
│   │   ├── fingerprint.py     # Banner/HTTP/TLS 证书指纹
│   │   └── webtech.py         # Web 技术栈识别（CPE 词汇对齐）
│   ├── verify/
│   │   ├── matcher.py         # 只读匹配 agent1 漏洞库（产品/版本级）
│   │   ├── explore.py         # 主动漏洞检测（只读、非破坏）
│   │   ├── checks.py          # 非破坏性安全检查
│   │   └── risk.py            # 风险评分（与 agent1 同口径）
│   ├── report.py              # HTML/Markdown 报告
│   └── notify.py              # 飞书/Webhook 告警
└── tests/
    └── test_agent2.py         # 单元测试（66 项）
```

---

## 测试

```bash
cd D:\ku\VScode\漏洞收集agent\agent2
python -m unittest discover -s tests -v
```

覆盖：授权范围判定（域名/IP/CIDR/越界拒绝）、端口串解析、版本比较与范围判断、
CPE 匹配（精确/别名/排除/回退）、旧格式 CPE 兼容、Web 技术栈识别（含
spring boot/gitlab/thinkphp/django/discuz 等扩展规则）、暴露面分类（含 /.env、
/backup.zip）、Cookie 安全标志、主动漏洞检测（本地模拟脆弱服务端到端）、
DB CRUD（含快照保存/差异/删除）、导出、风险评分、报告生成、Web 模块导入。

---

## 扩展方向

- **新增主动检测项**：在 `asset_agent/verify/explore.py` 的 `PROBE_PATHS` / 检测函数中追加路径与判定规则即可。
- **新增指纹规则**：在 `asset_agent/discovery/webtech.py` 的 `_HEADER_RULES` / `_BODY_RULES` / `_BANNER_RULES` / `_COOKIE_RULES` 中追加正则即可。
- **新增安全检查**：在 `asset_agent/verify/checks.py` 增加纯函数检查项，并入 `run_checks`。
- **新增仪表盘视图**：`webui.py` 增加 API 路由 + `webui/index.html` 增加标签页即可。
- **对接 agent1 告警**：`notify.py` 目前只推 exact 命中；可扩展为同时推送主动发现的高危项。
- **定时扫描**：可用系统计划任务/`doubao-cron-scheduler` 定时执行 `scan` 并推送报告。

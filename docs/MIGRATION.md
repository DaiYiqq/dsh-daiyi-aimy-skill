# 迁移与升级对照 · 上游 `aimy-sikll` v2.0.0 → 本插件 v3.0.0

> 本文回答三个问题：上游的哪些 Python 模块被移植了？哪些没移植、为什么？原来的 CLI 命令现在怎么用？
>
> 先读结论：**本插件只继承上游的「检测」能力，不继承「武器化」能力。** 上游 `tools/` 下 34 个 `.py` 文件（33 个功能模块 + 空的 `__init__.py`）中，13 个直接移植、1 个重写、4 个合并进别的模块、2 个部分吸收、1 个被技能替换、12 个明确不移植；另有 1 个 `__init__.py` 无对应物。

## 0. 两条产品线的差别

| 维度 | 上游 `aimy-sikll` v2.0.0 | 本插件 `dsh-daiyi-aimy-skill` v3.0.0 |
|---|---|---|
| 形态 | Python CLI（`python main.py <子命令>`） | DeepSeek Harness 的 Cordis 插件（ESM，宿主内常驻） |
| 调用者 | 人，或能执行 shell 的 Agent | 宿主的模型调用 `aimy_*` 工具；技能提供 playbook |
| 输出 | 终端 `print(json.dumps(...))` | 工具结构化返回值 + `aimy_report` 的 Markdown / JSON / SARIF |
| 授权 | 无内置范围概念，输入目标即探测 | deny-by-default，目标必须先经 `aimy_scope` 登记 |
| 运行时依赖 | `requests` 等第三方库 | **零第三方依赖**，只用 `node:` 内置模块 |
| 并发 | `ThreadPoolExecutor` 线程池 | `mapLimit` 受控并发，请求数/并发数/超时均有上限 |
| 会话 | `requests.Session` + `.pkl` 会话文件 | 无状态；需要登录态时由调用方在单次调用里带请求头 |
| 技能 | `ai-mian/hack-skills` 下 101 份 `SKILL.md` | 精选重写为 8 个 `aimy-*` 技能 |

> 上游 34 个模块的命名与职责取自 `main.py` 的子命令注册和 `tools/*.py` 的实际实现；`ai-mian/hack-skills` 下经统计有 101 个 `SKILL.md`。

## 1. 34 个模块的处置总表

处置含义：

- **移植**：逻辑保留，改写为 `lib/engine/*.js` 的纯 JS 模块（导出 `meta` + `run(ctx)`）。
- **合并**：能力并入另一个模块，不单独成文件。
- **重写**：保留职责，实现完全重写（通常是安全边界所在）。
- **部分**：只吸收其中无害的部分（如指纹、编码变体），利用部分丢弃。
- **替换**：运行时机制被其他形态取代（如技能 playbook）。
- **不移植**：主动拒绝，理由见「理由」列。

| # | 上游文件 | 上游职责 | 处置 | 本插件对应 | 理由 |
|---|---|---|---|---|---|
| 1 | `auth_bypass.py` | 管理后台路径 + 默认凭据尝试 | 不移植 | — | 属凭据攻击；插件只做检测，不尝试登录 |
| 2 | `auth_engine.py` | 表单/API 登录、CSRF token 提取、`.pkl` 会话 | 不移植 | — | 需要持久化凭据与有状态会话，与「无状态单次调用 + 不入库凭据」冲突；方法沉淀进 `aimy-auth-and-jwt` 技能 |
| 3 | `chain_engine.py` | 多漏洞组合成利用链 | 不移植 | — | 利用链组合即武器化，超出「检测」边界 |
| 4 | `cmdi_detector.py` | 命令注入检测（回显/时延） | 移植 | `lib/engine/cmdi.js` | 纯检测，无副作用 |
| 5 | `cors_scanner.py` | CORS 配置检查 | 移植 | `lib/engine/cors.js` | 纯检测 |
| 6 | `crawler.py` | 站内爬虫、链接/表单/参数提取 | 移植 | `lib/engine/crawler.js` | 只读抓取，供后续检测选点 |
| 7 | `deserialization_detector.py` | 反序列化端点猜测（正则 + base64 参数） | 不移植 | — | 判定依赖目标实现细节，误报高，且极易滑向 gadget 链利用；交由人工复核 |
| 8 | `deser_weaponizer.py` | 反序列化利用 payload 生成 | 不移植 | — | 武器化，明确禁止 |
| 9 | `fuzz_engine.py` | 通用线程池模糊测试器 | 合并/重写 | `lib/http.js` 的 `mapLimit` + 引擎内调度 | 并发调度由护栏探针统一实现，避免各引擎自建线程池绕过预算 |
| 10 | `graphql_scanner.py` | GraphQL 端点识别与内省查询 | 移植 | `lib/engine/graphql.js` | 只读内省，不写数据 |
| 11 | `http_client.py` | `requests` 封装、会话、代理 | 重写 | `lib/http.js` | 安全边界所在：改为唯一出口 + scope 校验 + 预算/超时/截断/重定向复检 |
| 12 | `jwt_detector.py` | JWT 存在性与不安全配置识别 | 移植 | `lib/engine/jwt.js` | 只解析与检查声明，不伪造、不破解 |
| 13 | `jwt_exploiter.py` | 弱密钥爆破、`alg=none` 伪造 | 不移植 | — | 密钥破解与 token 伪造属利用；相关风险改由 `aimy_jwt_audit` 报告指出 |
| 14 | `lfi_scanner.py` | 路径穿越 / 文件包含检测 | 移植 | `lib/engine/lfi.js` | 只做回显与报错特征判定，不落地读取任意文件 |
| 15 | `nosqli_detector.py` | NoSQL 注入检测 | 移植 | `lib/engine/nosqli.js` | 纯检测 |
| 16 | `orchestrator.py` | deepscan / autohunt / auto 多阶段编排 | 合并 | `aimy_web_scan` + `aimy_report`，流程指导见技能 | 保留「爬取 → 选点 → 检测 → 报告」编排，去掉其中的武器化阶段 |
| 17 | `param_miner.py` | 从页面/JS 挖掘参数名 | 移植 | `lib/engine/param-miner.js` | 只读提取候选参数 |
| 18 | `payload_mutator.py` | payload 编码与变异（raw/url/b64/hex） | 部分 | `lib/engine/payloads.js` | 仅保留检测 marker 的编码变体，不生成利用载荷 |
| 19 | `proto_pollution.py` | 原型链污染检测 | 移植 | `lib/engine/proto-pollution.js` | 只观测响应回显，不做运行时利用 |
| 20 | `proxy.py` | MITM 代理、凭据捕获 | 不移植 | — | 中间人拦截与凭据截获明确禁止 |
| 21 | `reverse_shell.py` | 反弹 Shell 生成器 | 不移植 | — | 武器化，明确禁止 |
| 22 | `sqli_blind.py` | 时间型盲注验证 | 合并 | `lib/engine/sqli.js`（仅 veteran 模式） | 时间盲注保留但限制 `SLEEP ≤ 5s`，且只在老鸟模式启用 |
| 23 | `sqli_oob.py` | OOB 带外注入（自建 HTTP 回连服务器） | 不移植 | — | 需要对外监听与回连，属带外利用；插件不提供服务端监听 |
| 24 | `sqli_weaponizer.py` | 注入后的数据提取/拖库 | 不移植 | — | 数据提取即实战利用 |
| 25 | `sql_injection.py` | 错误型 / 布尔型 SQL 注入检测 | 移植 | `lib/engine/sqli.js` | 纯检测 |
| 26 | `ssrf_detector.py` | SSRF 检测（回显/时延） | 移植 | `lib/engine/ssrf.js` | 只观测响应差异，不接 OOB、不读元数据 |
| 27 | `ssrf_lateral.py` | 云元数据读取、内网横向 | 不移植 | — | 横向移动与云凭据窃取明确禁止 |
| 28 | `ssrf_pwn.py` | SSRF 文件读取与云元数据利用 | 不移植 | — | 武器化 |
| 29 | `ssti_detector.py` | 模板注入检测 | 移植 | `lib/engine/ssti.js` | 使用无副作用算术 marker，不做命令执行 |
| 30 | `waf_bypass.py` | WAF 指纹 + 各类绕过 payload 集 | 部分 | 指纹思路并入 `lib/engine/tech-fingerprint.js` | 识别 WAF 是信息收集；绕过属于规避防御，不移植 |
| 31 | `workflow.py` | JSON 工作流运行时（步骤/条件/循环） | 替换 | 8 个 `aimy-*` 技能 | 用模型可读的 playbook 取代脚本化工作流，避免任意步骤编排 |
| 32 | `xss_detector.py` | XSS 反射检测 | 移植 | `lib/engine/xss.js` | 用无害 marker，不执行脚本 |
| 33 | `xss_validator.py` | XSS 上下文与复验 | 合并 | `lib/engine/xss.js` | 复验逻辑并入同一模块，保证同一 payload 只报一次 |
| 34 | `__init__.py` | 空包标记 | 无对应 | — | Python 包机制，JS ESM 不需要 |

另外两处**不在 `tools/` 里**的上游能力：

| 上游位置 | 职责 | 本插件对应 |
|---|---|---|
| `main.py::cmd_portscan` | TCP 端口探测 | `aimy_port_scan`（工具层用 `node:net` 实现，不走引擎模块） |
| `main.py::cmd_dirfuzz` | 目录/路径枚举 | `aimy_dir_fuzz`（工具层实现软 404 基线与枚举，不走引擎模块） |

本插件**新增**、上游没有直接对应物的模块：

| 模块 | 作用 |
|---|---|
| `lib/engine/tech-fingerprint.js` | 技术栈 / 中间件 / WAF 指纹（吸收上游 WAF 指纹思路） |
| `lib/engine/headers.js` | 安全响应头检查（HSTS、CSP、X-Frame-Options 等） |
| `lib/engine/index.js` | 引擎目录与调度：`CHECK_CATALOG` / `listChecks()` / `runChecks()`，以及 `crawl()` / `mineParams()` / `fingerprint()` 辅助入口 |
| `lib/engine/util.js` | URL 与参数拼接、token 提取、相似度、稳定排序 |
| `lib/scope.js` | 授权范围登记、匹配、持久化与审计（上游完全没有） |
| `lib/store.js` / `lib/report.js` | 会话内 Finding 去重与报告渲染（上游只有零散 JSON 输出） |

## 2. CLI 子命令 → 工具调用对照

上游 `main.py` 注册了 33 个子命令。下表给出每条命令在本插件里的对应方式。工具参数的完整定义见 [TOOLS.md](TOOLS.md)。

### 2.1 侦察与枚举

| 上游命令 | 本插件 |
|---|---|
| `python main.py portscan scanme.nmap.org` | `aimy_port_scan` |
| `python main.py portscan scanme.nmap.org --ports 22,80,443` | `aimy_port_scan`（端口列表参数） |
| `python main.py dirfuzz https://example.com --wordlist common.txt` | `aimy_dir_fuzz` |
| `python main.py crawl example.com --depth 2 --max-pages 30` | `aimy_crawl` |
| `python main.py param-mine example.com` | `aimy_crawl`（爬取同时挖掘参数） |

### 2.2 单点检测

| 上游命令 | 本插件 |
|---|---|
| `python main.py sqlcheck "https://example.com/item?id=1" --param id` | `aimy_web_scan`（`checks: ["sqli"]`） |
| `python main.py sqli-blind ... --param id` | `aimy_web_scan`（`checks: ["sqli"]`，需 `mode: veteran`） |
| `python main.py xsscheck "https://example.com/search?q=1" --param q` | `aimy_web_scan`（`checks: ["xss"]`） |
| `python main.py xss-validate ... --param q` | `aimy_web_scan`（`checks: ["xss"]`，重复观测会合并为同一条 Finding） |
| `python main.py cmdi ... --param cmd` | `aimy_web_scan`（`checks: ["cmdi"]`） |
| `python main.py ssti ... --param name` | `aimy_web_scan`（`checks: ["ssti"]`） |
| `python main.py ssrf ... --param url` | `aimy_web_scan`（`checks: ["ssrf"]`） |
| `python main.py nosqli ... --param id` | `aimy_web_scan`（`checks: ["nosqli"]`） |
| `python main.py lfi ... --param file` | `aimy_web_scan`（`checks: ["lfi"]`） |
| `python main.py cors https://example.com` | `aimy_web_scan`（`checks: ["cors"]`） |
| `python main.py graphql https://example.com/graphql` | `aimy_web_scan`（`checks: ["graphql"]`） |
| `python main.py proto-pollution ...` | `aimy_web_scan`（`checks: ["proto-pollution"]`） |
| `python main.py jwt https://example.com --param token` | `aimy_jwt_audit`（审计给定令牌）；扫页面里的令牌用 `aimy_web_scan`（`checks: ["jwt"]`） |
| `python main.py waf https://example.com` | 无直接命令；仅保留少量 CDN/WAF 特征（如 Cloudflare）在 `aimy_recon` 的技术栈指纹中 |
| `python main.py deser ...` | 不提供，见 §1 第 7 行 |
| `python main.py auth-bypass ...` | 不提供，见 §1 第 1 行 |

### 2.3 多阶段与报告

| 上游命令 | 本插件 |
|---|---|
| `python main.py deepscan example.com` | `aimy_crawl` → `aimy_web_scan` → `aimy_report` |
| `python main.py autohunt example.com` | `aimy_recon` → `aimy_crawl` → `aimy_web_scan` → `aimy_report` |
| `python main.py auto example.com --max-pages 30` | 同上，页数与深度由 `aimy_crawl` 参数控制 |
| `python main.py workflow <name>` | 改用 `aimy-*` 技能中的 playbook 分步执行 |

### 2.4 不提供的子命令

| 上游命令 | 处置 |
|---|---|
| `sqli-oob` | 需要自建回连服务器，不提供 |
| `sqli-weaponize` | 数据提取，不提供 |
| `jwt-exploit` | 破解与伪造，不提供 |
| `ssrf-pwn` / `ssrf-lateral` | 云元数据/横向，不提供 |
| `deser-weaponize` | 利用 payload 生成，不提供 |
| `reverse-shell` | 反弹 Shell 生成，不提供 |
| `chain` | 利用链组合，不提供 |
| `proxy` | MITM 凭据捕获，不提供 |
| `fuzz` | 通用并发模糊器被引擎内调度取代，不单独暴露 |
| `payload-mutate` | 编码与变异只在检测引擎内部使用，不对外暴露 |

## 3. 行为差异（升级时需要知道的事）

1. **必须先登记范围**。上游「给个 URL 就打」；本插件第一次调用任何网络工具前必须先 `aimy_scope(action="add", ...)`，否则直接拒绝。
2. **默认不跟随重定向**。上游 `requests` 默认跟随；本插件默认 `followRedirects: false`，避免被跳转带出授权范围。需要跟随时显式开启，且每一跳都会重新过 scope。
3. **默认不碰回环/内网**。`127.0.0.1`、`10/8`、`172.16/12`、`192.168/16` 需要 `allowPrivateNetworks: true` 才能登记与访问（靶场本地演练的场景）。
4. **请求预算更严**。rookie 模式单次调用最多 24 个请求、超时 8s；veteran 模式最多 60 个请求、超时 12s。上游没有硬预算。
5. **时间盲注需 veteran**。rookie 模式不启用时间型 payload；veteran 模式允许，但 `SLEEP` 上限 5 秒。
6. **不持久化凭据**。上游可以登录后把会话存成 `.pkl`；本插件不保存任何凭据，需要登录态的检测请在单次调用里传请求头，或在技能指导下由人工完成。
7. **结果与会话绑定**。Finding 存在内存里（默认最多 800 条、60 次运行记录），插件重启即清空；只有授权范围会持久化到 `scope.json`。
8. **没有 Web UI 面板**。本插件只提供工具、技能与报告文件，不提供图形界面。

## 4. 技能迁移：101 份 Markdown → 8 个可执行 playbook

上游 `ai-mian/hack-skills` 下有 101 个 `SKILL.md`，主题覆盖面很广，但多数是「方法清单」。本插件把它们按工作流重组为 8 个技能，每个技能都可以直接引用本插件工具：

| 本插件技能 | 吸收上游技能的主题 |
|---|---|
| `aimy-authorized-scope` | 授权、范围、合规、测试前置条件 |
| `aimy-recon-workflow` | 信息收集、指纹、端口、目录、爬虫、参数挖掘 |
| `aimy-web-vuln-triage` | SQLi / XSS / SSTI / 命令注入 / LFI / SSRF / CORS 的判定与误报排除 |
| `aimy-auth-and-jwt` | 认证、会话、JWT 配置风险 |
| `aimy-api-and-graphql` | REST / GraphQL 内省与接口面梳理 |
| `aimy-finding-report` | 证据整理、严重度、复现步骤、修复建议、报告结构 |
| `aimy-rookie-mode` | 学习路径、低风险演练、rookie 预算下的取舍 |
| `aimy-veteran-mode` | 老鸟模式下的检测顺序、时间盲注使用条件、边界把握 |

技能是**方法指导**，不是自动化执行器：它们不会代替你调用工具，也不会绕过 `aimy_scope`。

## 5. 不移植之后的替代建议

对明确不移植的利用能力，建议的替代路径：

| 场景 | 建议 |
|---|---|
| 验证 SQL 注入可利用性 | 用 `aimy_web_scan` 确认注入点后，在**书面授权**的靶场内由人工复现；不要用本插件拖库 |
| 验证 SSRF 可达内网 | 只报告检测结论；内网可达性验证需在授权书明确允许的范围内人工进行 |
| 验证 JWT 可伪造 | `aimy_jwt_audit` 指出 `alg=none`、弱配置等问题；伪造验证请由人工在隔离环境完成 |
| 验证反序列化 | 本插件不提供检测；请人工分析目标依赖与 sink |
| 需要登录态 | 由调用方提供短期 token 或请求头；不要把长期凭据写进插件配置 |

## 6. 升级检查清单

从上游 CLI 迁移到本插件时，逐项确认：

- [ ] 已在 DSH 宿主里安装插件并能看到 8 个 `aimy_*` 工具。
- [ ] 已用 `aimy_scope` 登记本次授权目标，并写清授权依据（≥ 8 字符）。
- [ ] 确认当前 `mode`（默认 `rookie`）；需要时间盲注时切到 `veteran`。
- [ ] 需要访问本地靶场时，确认 `allowPrivateNetworks: true` 且范围里登记了 `127.0.0.1:端口`。
- [ ] 需要重定向时显式开启 `followRedirects`，并确认跳转目标也在范围内。
- [ ] 跑完检测后用 `aimy_report` 生成报告；报告默认脱敏。
- [ ] 确认不再使用上游的 `reverse-shell`、`*-weaponize`、`chain`、`proxy` 等子命令。

---

上游仓库：<https://github.com/zxz0119/aimy-sikll>（v2.0.0，MIT）
本插件仓库：<https://github.com/DaiYiqq/dsh-daiyi-aimy-skill>

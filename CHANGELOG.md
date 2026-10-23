# Changelog

本文件记录 `dsh-daiyi-aimy-skill` 的对外变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

上游项目：[zxz0119/aimy-sikll](https://github.com/zxz0119/aimy-sikll)（Python CLI，v2.0.0）。
本插件是它的 DeepSeek Harness 再开发版本，版本号从上游的 `2.x` 直接进入 `3.0.0`，以区分「CLI」与「Cordis 插件」两条产品线。

## [Unreleased]

### 文档

- README 多语言化：简体中文（主语言，`README.md`）、English（`README.en.md`）、繁體中文（`README.zh-TW.md`）、日本語（`README.ja.md`），四份文档顶部都有语言切换栏。
- 修正仓库 About 简介的中文编码（此前提交时被按 ASCII 发送，中文变成问号）。
- `npm run check` 改为「契约校验 + 全仓语法检查」（新增 `scripts/check-syntax.mjs`）。


## [3.0.0] - 2026-10-23

首个 DSH 插件版本。相对上游 v2.0.0，这是一次**形态重写**而不只是加壳：从「命令行脚本」变成「常驻宿主、由模型调用的 Cordis 插件」。

### Added

- **DSH 插件入口**：`lib/index.js` 导出 `name` / `inject` / `apply`，以 `ctx.tools.register()` 注册 8 个模型可调用工具，以 `ctx.skills.register()` 注册 8 个 `aimy-*` 技能；`apply` 设计为不抛异常，单个注册失败只降级告警。
- **8 个原生工具**：`aimy_scope`、`aimy_recon`、`aimy_port_scan`、`aimy_dir_fuzz`、`aimy_crawl`、`aimy_web_scan`、`aimy_jwt_audit`、`aimy_report`。每个工具都有结构化的 `parameters` 与 `output.schema`，返回对象而不是打印 JSON 文本。
- **授权范围护栏（deny-by-default）**：新增 `lib/scope.js`。任何网络目标必须先通过 `aimy_scope` 登记并附带授权说明；范围支持 host、`host:port`、scheme、`*.` 通配子域、路径前缀与过期时间，可持久化到 `scope.json` 并保留审计日志。上游没有这层机制。
- **护栏 HTTP 探针 `lib/http.js`**：插件内唯一的出口。统一处理超时、请求预算、响应体截断、重定向逐跳复检、外部取消；引擎模块只能拿到注入的 `ctx.probe`，拿不到 `fetch`。
- **12 个检测模块 + 3 个侦察模块**（`lib/engine/**`）：检测为 sqli、xss、cmdi、ssti、ssrf、nosqli、lfi、cors、jwt、graphql、proto-pollution、headers；侦察为 crawler、param-miner、tech-fingerprint。端口扫描与目录枚举在工具层实现（`lib/tools/port-scan.js`、`lib/tools/dir-fuzz.js`）。全部只做检测，不写文件、不落库、不横向。
- **会话级结果存储与三种报告**：`lib/store.js` 负责 Finding 去重与排序、运行记录与请求计数；`lib/report.js` 输出 Markdown / JSON / SARIF。
- **8 个技能包**：`aimy-authorized-scope`、`aimy-recon-workflow`、`aimy-web-vuln-triage`、`aimy-auth-and-jwt`、`aimy-api-and-graphql`、`aimy-finding-report`、`aimy-rookie-mode`、`aimy-veteran-mode`，把上游 101 份 Markdown 技能里可复用的方法整理成可执行 playbook。
- **两种安装方式**：DSH 桌面端插件管理器安装本地目录 / git 仓库；或手动 `file:` 依赖 + `pnpm install`，由插件管理器 reconcile 进 `dsh.profile.bundles`。
- **零运行时依赖**：只用 `node:` 内置模块；`@deepseek-ai/dsh-tools`、`@deepseek-ai/dsh-skill`、`@deepseek-ai/cordis` 声明为可选 peer，由宿主提供。
- **工程配套**：`scripts/validate-plugin.mjs` 契约校验、`node --test` 测试、GitHub Actions CI（Node 24，`npm run verify`）。

### Changed

- **运行模式**：`rookie`（默认，保守预算、不启用时间盲注）与 `veteran`（更高预算、允许时间盲注与激进 payload）两级；模式只调预算与 payload 激进度，**不放宽授权边界**。
- **并发模型**：上游用线程池 `ThreadPoolExecutor` 直接并发；本插件改为受控并发（`mapLimit`），请求数与并发数都有硬上限，且可被外部 `AbortSignal` 取消。
- **默认网络行为**：默认不跟随重定向，默认不访问回环 / 内网地址（需显式 `allowPrivateNetworks: true`），默认不读取超过 256 KiB 的响应体。
- **输出形态**：从 `print(json.dumps(...))` 改为工具结构化返回 + `aimy_report` 统一出报告，便于模型直接消费与宿主审计。
- **认证方式**：不再使用 `requests.Session` 与 `.pkl` 会话文件；需要登录态的检测由调用方在单次调用里显式提供请求头，插件不持久化凭据。

### Removed

明确**不移植**上游的武器化模块（详见 [docs/MIGRATION.md](docs/MIGRATION.md)）：

- `reverse_shell.py`（反弹 Shell 生成器）
- `deser_weaponizer.py`（反序列化利用 payload / gadget 生成）
- `ssrf_pwn.py`、`ssrf_lateral.py`（云元数据读取、文件读取与横向移动）
- `sqli_weaponizer.py`、`sqli_oob.py`（数据提取拖库、OOB 带外回连）
- `waf_bypass.py` 的绕过 payload 集（仅保留 WAF 指纹识别思路）
- `chain_engine.py`（利用链组合）、`proxy.py`（MITM 凭据捕获）、`jwt_exploiter.py`（密钥破解与 token 伪造）
- `auth_bypass.py`、`deserialization_detector.py`、`auth_engine.py`（凭据攻击 / 有状态登录 / 判定过于贴近利用）

### Security

- 默认拒绝：没有任何授权范围时，所有网络工具直接拒绝并提示先调用 `aimy_scope`。
- 授权说明字段强制不少于 8 个字符，阻止「随手一填」。
- 永久拒绝 `0.0.0.0/8`、`169.254.0.0/16`、组播、保留地址等异常地址类别。
- 重定向逐跳复检 scope，防止被 302 带出授权范围。
- 报告默认对疑似凭据做脱敏（`redactSecrets: true`）。
- 审计日志记录范围登记 / 移除 / 清空等动作，最多保留 200 条。

[Unreleased]: https://github.com/DaiYiqq/dsh-daiyi-aimy-skill/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/DaiYiqq/dsh-daiyi-aimy-skill/releases/tag/v3.0.0

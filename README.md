# dsh-daiyi-aimy-skill

<p align="center">
  <b>简体中文</b> ·
  <a href="README.en.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="package.json"><img alt="Node" src="https://img.shields.io/badge/node-%5E22.19%20%7C%7C%20%3E%3D24-brightgreen.svg"></a>
  <a href="package.json"><img alt="DSH" src="https://img.shields.io/badge/DSH-%3E%3D0.2.0--rc.1-6f42c1.svg"></a>
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-0-success.svg">
  <a href="https://github.com/zxz0119/aimy-sikll"><img alt="upstream" src="https://img.shields.io/badge/upstream-aimy--sikll%20v2.0.0-orange.svg"></a>
</p>

> **为 DeepSeek Harness 提供「授权范围内」的侦察与 Web 漏洞检测能力：8 个原生工具 + 8 个技能，默认拒绝，只做检测。**

`dsh-daiyi-aimy-skill` 是 [zxz0119/aimy-sikll](https://github.com/zxz0119/aimy-sikll)（Python CLI，v2.0.0）的 **DeepSeek Harness（DSH）Cordis 插件**再开发版。它把上游的命令行脚本改造成宿主内常驻的原生工具，并加上了上游没有的**授权范围护栏**：没有登记授权范围时，任何网络工具都不会执行。

- 形态：ESM Cordis 插件，运行时**零第三方依赖**（只用 `node:` 内置模块）。
- 宿主：DSH `>=0.2.0-rc.1 <0.3.0`；Node `^22.19 || >=24`。
- 版本：`3.0.0`，MIT，作者 戴亿。

## 特性

| 特性 | 说明 |
|---|---|
| **8 个模型可调用工具** | 范围管理、侦察、端口、目录、爬虫、Web 检测、JWT 审计、报告 |
| **默认拒绝（deny-by-default）** | 任何网络目标必须先 `aimy_scope` 登记，未登记直接拒绝并提示下一步 |
| **授权依据与审计** | 登记必须写授权说明（≥ 8 字符），范围可设过期时间，变更写审计日志 |
| **12 个检测模块 + 3 个侦察模块** | 检测：sqli / xss / cmdi / ssti / ssrf / nosqli / lfi / cors / jwt / graphql / proto-pollution / headers；侦察：crawler / param-miner / tech-fingerprint。端口与目录枚举在工具层实现 |
| **单一网络出口** | 所有请求经 `lib/http.js` 护栏探针：逐请求 scope 校验、预算、超时、响应体截断、重定向复检 |
| **8 个中文技能** | 授权范围、侦察、Web 判定、认证与 JWT、API 与 GraphQL、报告、菜鸟模式、老鸟模式 |
| **三种报告格式** | Markdown / JSON / SARIF，报告默认脱敏 |
| **零运行时依赖** | 不用 `requests`、不用第三方 HTTP 库；宿主提供 `dsh-tools` 与 `dsh-skill` |
| **只做检测** | 不提供反弹 shell、反序列化利用链、SSRF 横向、OOB 带外、WAF 绕过等武器化能力 |
| **无 UI 面板** | 只提供工具、技能与报告文件；没有图形界面 |

## 安装

前置：DSH 桌面端（`>=0.2.0-rc.1 <0.3.0`）与 Node `^22.19 || >=24`。本插件没有构建步骤，也没有运行时依赖。

### 方式 A：用 DSH 插件管理器（推荐）

打开 DSH 桌面端「**设置 → 插件**」，用插件管理器安装：

- **本地目录**：选择本仓库目录（含 `package.json` 与 `cordis.patch.yml`）。
- **git 仓库**：填 `https://github.com/DaiYiqq/dsh-daiyi-aimy-skill`。

安装后插件管理器的 reconcile 会读取本包的 `dsh.bundle.patch`，把 `cordis.patch.yml` 的 insert 项（`id: daiyi-aimy-skill`）写入 profile。

### 方式 B：手动放进插件目录

1. 把本目录放到 DSH 插件目录下（例如 `~/.dsh/plugins/dsh-daiyi-aimy-skill`）。
2. 在 profile 的 `package.json` 的 `dependencies` 中加入：

   ```json
   {
     "dsh-daiyi-aimy-skill": "file:~/dsh/plugins/dsh-daiyi-aimy-skill"
   }
   ```

   > `file:` 后面写**本机绝对路径**；上面的 `~/...` 只是示意。
3. 在 profile 目录执行 `pnpm install`。
4. 重启 / 重新加载 DSH。插件管理器 reconcile 时会因为本包声明了 `dsh.bundle.patch`，把包名加入 `dsh.profile.bundles`。

安装成功后，会话里能看到 8 个 `aimy_*` 工具，技能目录里出现 8 个 `aimy-*` 技能。

## 快速开始（5 行）

```text
// 第 1 步：登记授权范围——不登记，后面所有网络工具都会拒绝
aimy_scope(action="add", target="example.com", authorization="客户授权函 #A-1024，范围 example.com 全站", expiresInHours=72)
aimy_recon(target="https://example.com")
aimy_crawl(target="https://example.com/", maxPages=10)
aimy_web_scan(target="https://example.com/search?q=test", checks=["xss", "sqli"])
aimy_report(action="report", format="md", outputPath="reports/example-com.md")
```

一次完整调用的返回示例（节选）：

```json
{
  "target": "https://example.com/search?q=test",
  "checks": ["xss", "sqli"],
  "skipped": [],
  "params": [{ "name": "q", "location": "query", "sample": "test" }],
  "findings": [
    {
      "module": "xss",
      "checkId": "xss-reflected",
      "title": "反射型 XSS（HTML 上下文）",
      "severity": "high",
      "confidence": "high",
      "url": "https://example.com/search?q=test",
      "param": "q",
      "payload": "aimy1337<script>alert(1)</script>",
      "evidence": "参数 q 在 HTML 上下文原样回显；payload「…」未编码出现在响应中。响应 200，片段：<div>…</div>",
      "cwe": "CWE-79",
      "remediation": "按输出上下文做 HTML/属性/JS 编码，使用白名单过滤，并配置 CSP 作为纵深防御。"
    }
  ],
  "requests": 9,
  "notes": ["runId=run-1a2b3c4d", "模式=rookie"]
}
```

> 上面的 finding 仅用于展示字段形状，不代表 `example.com` 真的存在该问题。实际返回以你的目标与配置为准。

## 工具

| 工具 | 作用 | 需要授权范围 |
|---|---|---|
| `aimy_scope` | 登记 / 查看 / 移除 / 清空授权范围，试判目标是否放行 | 否（闸门本身） |
| `aimy_recon` | DNS、HTTP 基线、安全响应头、技术栈指纹、robots.txt | 是 |
| `aimy_port_scan` | TCP 端口连通性探测（仅握手），高危端口暴露告警 | 是 |
| `aimy_dir_fuzz` | 路径/目录枚举，软 404 基线过滤，敏感路径告警 | 是 |
| `aimy_crawl` | 同源爬取：页面、链接、表单、参数、JS 接口路径 | 是 |
| `aimy_web_scan` | 一次跑一组 Web 检测（12 类 checks，见文档） | 是 |
| `aimy_jwt_audit` | 离线 JWT 审计：算法、弱密钥、声明、外部密钥源 | 否（纯本地） |
| `aimy_report` | 汇总、列发现、导出 Markdown / JSON / SARIF | 否 |

完整参数表、返回形状、错误码与限制见 [docs/TOOLS.md](docs/TOOLS.md)。

## 技能

| 技能 | 何时加载 |
|---|---|
| `aimy-authorized-scope` | 会话开始、切换/扩大目标，或工具返回 `NO_SCOPE` / `NO_MATCH` / `EXPIRED` / `PRIVATE_BLOCKED` |
| `aimy-recon-workflow` | 范围已登记，需要摸清域名、端口、目录、页面、参数与技术栈 |
| `aimy-web-vuln-triage` | 已有带参数的 URL，需要判定 Web 漏洞真伪与定级 |
| `aimy-auth-and-jwt` | 目标有登录态、Bearer token、JWT，或要验证会话与对象级授权 |
| `aimy-api-and-graphql` | 存在 `/api`、`/graphql`、`/swagger` 等接口面 |
| `aimy-finding-report` | 一轮检测结束，需要出报告或给 CI 出 SARIF |
| `aimy-rookie-mode` | 新手、生产环境，或 `mode=rookie` 时 |
| `aimy-veteran-mode` | 授权明确、预发/靶场，需要更高覆盖与链式验证时 |

技能是**方法指导**，不会自动执行工具，也不能绕过 `aimy_scope`。

## 与上游的升级对照

| 维度 | 上游 `aimy-sikll` v2.0.0 | 本插件 v3.0.0 |
|---|---|---|
| 形态 | Python CLI，`python main.py <子命令>` | DSH Cordis 插件，模型直接调用工具 |
| 授权 | 输入目标即探测 | deny-by-default，先登记范围再探测 |
| 网络出口 | 各模块各自用 `requests` | 唯一护栏探针，逐请求 scope 校验 |
| 输出 | 终端 JSON 文本 | 结构化返回值 + 三种格式报告 |
| 依赖 | `requests` 等 | 零运行时第三方依赖 |
| 会话 | `.pkl` 会话文件 | 无状态，不保存凭据 |
| 并发 | 线程池 | 受控并发 + 请求预算 + 取消 |
| 武器化 | 有（反弹 shell、拖库、横向等） | **不提供**，对应模块不移植 |
| 技能 | 101 份 Markdown | 精选重写为 8 个可执行 playbook |

34 个上游模块的逐项处置（移植 / 合并 / 只吸收部分 / 不移植及原因）与 CLI 命令对照见 [docs/MIGRATION.md](docs/MIGRATION.md)。

## 配置

配置来自 `cordis.patch.yml` 的 `config`，与默认值合并；非法值回退默认并记录 warning。

```yaml
- insert:
    - id: daiyi-aimy-skill
      name: dsh-daiyi-aimy-skill
      config:
        mode: rookie
        persistScope: true
```

| 配置项 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `mode` | `rookie` \| `veteran` | `rookie` | 运行模式；只影响预算与 payload 激进度，不放宽授权边界 |
| `persistScope` | boolean | `true` | 是否把授权范围写入磁盘；`false` 时仅进程内存、重启失效 |
| `scopeFile` | string | `<DSH_HOME>/daiyi-aimy-skill/scope.json` | 授权范围文件路径 |
| `timeoutMs` | number | 8000（rookie）/ 12000（veteran） | 单请求超时，上限 60000 |
| `maxRequests` | number | 24 / 60 | 单次工具调用请求预算，上限 400 |
| `concurrency` | number | 4 / 8 | 并发上限，上限 32 |
| `maxBodyBytes` | number | 262144 | 响应体上限，最大 4 MiB |
| `followRedirects` | boolean | `false` | 默认不跟随重定向 |
| `maxRedirects` | number | 3 | 跟随时的最大跳数 |
| `userAgent` | string | `dsh-daiyi-aimy-skill/3.0.0 (...)` | 默认 UA，目标可识别测试来源 |
| `allowPrivateNetworks` | boolean | `false` | 是否允许登记/访问回环与内网地址 |
| `redactSecrets` | boolean | `true` | 报告中对疑似凭据脱敏 |
| `maxFindings` | number | 800 | 内存中最多保留的 finding 数 |
| `maxRuns` | number | 60 | 内存中最多保留的运行记录数 |

## 安全与合规

- **只做检测**：不提供反弹 shell、反序列化利用链、SSRF 横向、OOB 带外回连、WAF 绕过、数据提取、凭据攻击、MITM 凭据捕获。
- **默认拒绝**：没有授权范围时，所有网络工具直接拒绝；范围必须写明授权依据。
- **范围可约束**：支持 `host`、`host:port`、scheme、`*.` 通配子域、路径前缀与过期时间；回环/内网默认禁止。
- **不保存凭据**：插件不持久化 token/cookie/登录态；范围文件不记录凭据。
- **不承诺检出率**：检测基于响应差异启发式，存在误报漏报；结论必须由有授权的人类复核。
- **合法使用**：仅用于已获**书面授权**的目标。未授权探测、数据提取、持久化访问、拒绝服务等均被禁止，也不在插件能力范围内。

完整授权模型、匹配规则与漏洞报告渠道见 [docs/SECURITY.md](docs/SECURITY.md)。

**发现插件自身安全问题**：请优先通过 GitHub Security Advisory 或邮件 `1703205607@qq.com` 私下联系，修复前请勿公开细节。

## 目录结构

```text
dsh-daiyi-aimy-skill/
├── lib/
│   ├── index.js            # 插件入口：name / inject / apply
│   ├── config.js           # 配置归一化与模式预算
│   ├── scope.js            # 授权范围：解析、匹配、持久化、审计
│   ├── http.js             # 护栏 HTTP 探针（唯一网络出口）
│   ├── store.js            # Finding 存储、去重、运行记录
│   ├── report.js           # Markdown / JSON / SARIF 渲染
│   ├── tools/              # 8 个模型可调用工具
│   ├── engine/             # 12 个检测模块 + 3 个侦察模块 + 注册表
│   └── skills/             # 技能加载器
├── skills/                 # 8 个 aimy-* 技能（SKILL.md）
├── docs/                   # TOOLS / MIGRATION / SECURITY / ARCHITECTURE / CONTRACT
├── scripts/                # validate-plugin.mjs 契约校验
├── test/                   # 契约测试、引擎测试、技能测试
├── cordis.patch.yml
├── package.json
├── README.md               # 简体中文（主语言）
├── README.en.md            # English
├── README.zh-TW.md         # 繁體中文
├── README.ja.md            # 日本語
├── CHANGELOG.md
└── LICENSE
```

## 开发与测试

要求 Node `^22.19 || >=24`。**零第三方依赖**，因此不需要 `npm install`。

```bash
npm run check     # 契约校验 + 全仓语法检查
npm test          # node --test "test/**/*.test.js"（递归）
npm run verify    # check + test（CI 跑的就是这一条）
```

单独校验某个文件：

```bash
node --check lib/http.js
node --test test/engine/sqli.test.js
```

CI：[.github/workflows/ci.yml](.github/workflows/ci.yml)，`ubuntu-latest` + Node 24，只跑 `npm run verify`，不做额外安装。

更多设计说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)；新增检测模块的步骤也在那里。

## 许可证

[MIT](LICENSE) © 2026 戴亿 <1703205607@qq.com>

上游项目 `aimy-sikll` 同为 MIT 许可证；本插件是独立再开发，不是上游的官方发行版。

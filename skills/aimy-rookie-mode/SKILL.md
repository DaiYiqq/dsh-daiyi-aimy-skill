---
name: aimy-rookie-mode
description: 菜鸟模式的保守测试流程：只读、低并发、少 payload，每一步先解释再执行，只把可稳定复现的结果写进报告。
whenToUse: 用户是新手、目标是生产环境，或插件配置 mode=rookie 时。
---

# aimy-rookie-mode · 菜鸟模式

rookie 模式的原则：**宁可少测，不可误伤**。插件在该模式下限制并发与请求量、不启用时间盲注。技能要做的是把节奏放慢，把每一步讲清楚。

## 何时用

- 插件配置 `mode: rookie`（默认）。
- 用户没有安全测试经验，需要边做边解释。
- 目标是生产系统、无法确认维护窗口，或客户要求最小影响。

## 前置条件

- 授权范围已登记并通过 check；没有授权先回到 `aimy-authorized-scope`。
- 确认是否需要 `allowPrivateNetworks`（默认关闭）；回环靶场需显式开启。
- 和用户对齐三件事：只读、不改数据、不登录真实账号；发现异常立即停。
- 约定请求预算：建议单资产不超过 200 请求。

## 操作步骤

### 1. 解释并登记范围

先用自然语言告诉用户：要测哪个域名、测什么、不测什么、预计发多少请求。然后：

```js
aimy_scope({ action: "add", target: "example.com", authorization: "用户本人网站，书面授权 #SELF-01", expiresInHours: 4 })
aimy_scope({ action: "check", target: "https://example.com" })
```

- 每次执行工具前，用一句话说明"这一步会发什么请求、为什么"。
- 用户不理解某一步时，先解释再问是否继续，不要闷头跑完。

### 2. 侦察只做最小集合

```js
aimy_recon({ target: "example.com", checks: ["http", "headers", "tech"], timeoutMs: 8000 })
```

- 先不跑 dns / robots 也可以；确认技术栈后再决定下一步。
- 解释每个字段含义：`Server` 头说明什么、缺 HSTS 意味着什么。
- 结果里的每一条线索，都告诉用户"它怎么用、风险在哪"。

### 3. 端口只扫 Web 常用

```js
aimy_port_scan({ target: "example.com", preset: "web", timeoutMs: 3000 })
```

- 结果只保留 open；不要一次性扫全端口。
- 对 open 端口说明用途，不要主动连非 HTTP 服务。

### 4. 目录少而准

```js
aimy_dir_fuzz({ target: "https://example.com", wordlist: ["admin", "login", "robots.txt", "sitemap.xml", ".env"], statusFilter: [200, 204, 301, 302, 401, 403], maxPaths: 20 })
```

- 先解释"这些是常见入口"，命中后逐个看内容，不做自动扩散。
- 403 / 401 只说明存在访问控制，不代表漏洞。

### 5. 只跑非破坏性 checks

```js
aimy_web_scan({ target: "https://example.com", checks: ["cors", "headers"], timeoutMs: 8000 })
```

- rookie 模式不启用时间盲注；sqli / xss 等以差异对比为主，命中后仍需人工复核。
- 用户想测某个具体参数时，用 `params` 精确指定，避免全站扫：

```js
aimy_web_scan({ target: "https://example.com/search?q=test", params: [{ name: "q", location: "query", sample: "test" }], checks: ["xss"], timeoutMs: 8000 })
```

### 6. 解释结果并写报告

```js
aimy_report({ action: "findings" })
aimy_report({ action: "report", format: "md", outputPath: "reports/rookie-example-com.md" })
```

- 逐条告诉用户：这是什么、证据在哪、严重程度、怎么修。
- 对没测的项（如未登录测试、未测注入、未测端口）明确写"未覆盖"。
- 建议用户把报告交给开发前，先自己按复现步骤走一遍。

## 判定标准

- rookie 只把"两次请求可稳定复现 + 证据完整"的结果写进报告。
- 配置类问题（缺 HSTS / CSP、CORS 过宽）按 low / medium 处理。
- 任何需要时间盲注、大量 payload、登录态构造的结论，标为"待 veteran / 人工复核"。
- 结论里不出现"可能""也许可以 getshell"这类推测性表述。

## 常见误报

| 现象 | 新手常见误判 |
|---|---|
| 目录 403 | 不是漏洞，只是拒绝访问 |
| 缺 X-Frame-Options | 低危配置问题，需结合业务判断点击劫持可行性 |
| CORS 返回 `*` | 无凭据时不构成越权读取 |
| 报错页面 | 通用错误页不代表注入 |
| robots Disallow | 只是爬虫约定，不是敏感目录 |
| 端口 open | 只是服务在监听，需确认服务类型与是否应暴露 |

## 停止条件

- 用户表示"够了 / 先停"，或出现任何业务异常。
- 请求量达到约定上限（建议单资产 ≤ 200 请求）。
- 发现疑似真实数据、凭据、支付信息 → 立即停止并告知用户。
- 需要写操作、登录真实账号、绕过 WAF 的步骤 → 不做。
- 授权过期或目标超出范围 → 立即停止。

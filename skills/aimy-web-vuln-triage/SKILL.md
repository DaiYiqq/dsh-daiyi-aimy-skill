---
name: aimy-web-vuln-triage
description: 用 aimy_web_scan 的 checks 选择、参数构造与二次复核，把扫描命中收敛成可复现、可定级的 finding。
whenToUse: 已有带参数的 URL，需要判定 Web 漏洞真伪、严重级别与是否写入报告时。
---

# aimy-web-vuln-triage · Web 漏洞判定

`aimy_web_scan` 只做检测：用无害 marker、响应差异对比，veteran 模式下才用 ≤5 秒时间盲注。技能的价值在于**选对 checks**、**给对参数**、**排除误报**，而不是把所有检查全开。

## 何时用

- `aimy_recon` / `aimy_crawl` 已产出带参数的 URL。
- 某个入口有明确输入点（查询参数、表单字段、JSON 字段）。
- 需要决定"这条命中要不要写进报告、算什么级别"。

## 前置条件

- `aimy_scope` 的 `check` 已通过；参数与请求方法来自真实页面 / 接口，不要凭空造。
- 了解目标技术栈（来自 `aimy_recon` 的 tech），用于选 checks。
- 明确当前模式：rookie 默认 checks 少，veteran 才追加注入类检查。
- 记下基线：不带 payload 的正常请求状态码、长度、响应时间。

## 操作步骤

### 1. 先跑低风险基线

```js
aimy_web_scan({ target: "https://example.com/search?q=test", checks: ["headers", "cors"], timeoutMs: 8000 })
```

- `headers`：安全响应头缺失 / 配置错误；`cors`：跨域策略是否过宽。
- 这两类不需要 payload，适合作为第一轮，也用来确认目标可达、WAF 行为正常。

### 2. 按参数类型选注入类 checks

```js
aimy_web_scan({ target: "https://example.com/product?id=1", checks: ["sqli", "xss", "lfi", "nosqli"], params: [{ name: "id", location: "query", sample: "1" }], timeoutMs: 8000 })
```

- SQL 类参数 → `sqli`；反射到 HTML → `xss`；文件 / 路径参数 → `lfi`；JSON 对象参数 → `nosqli`。
- 命令拼接参数（host、cmd、ping）→ `cmdi`；模板参数（name、greeting）→ `ssti`；URL 参数（url、next、image）→ `ssrf`。
- 省略 `params` 时插件自动从 URL / 表单发现；多参数时逐个列出，避免只测第一个。

### 3. POST / JSON 入口

```js
aimy_web_scan({ target: "https://example.com/api/login", method: "POST", checks: ["sqli", "nosqli", "xss"], params: [{ name: "username", location: "json", sample: "test" }, { name: "password", location: "json", sample: "test" }] })
```

- JSON 参数必须标 `location: "json"`，否则基线请求格式不对，结果没有意义。
- 表单参数用 `location: "body"`；`location` 只有 `query` / `body` / `json` 三种。

### 4. 全量一轮（仅 veteran / 预发环境）

```js
aimy_web_scan({ target: "https://example.com/product?id=1", checks: ["sqli", "xss", "cmdi", "ssti", "ssrf", "nosqli", "lfi", "cors", "graphql", "proto", "headers"] })
```

- 全量只在明确允许且非生产高峰时用；单 URL 请求预算约 40 次。
- 跑完先看 `aimy_report({ action: "summary" })` 的请求量与错误率，超预算就停。

### 5. 逐条复核 finding

```js
aimy_report({ action: "findings", severity: ["high", "critical"] })
```

- 回看 `evidence`：是否包含状态码、关键字、时延对比；`confidence` 是否够高；`confirmed` 是否二次确认。
- 能手工复现（同 URL 同参数再发一次，得到同样差异）才升级为 high / critical；只有一次差异的降到 medium / low 或删除。

## 判定标准

- **确认**：两次独立请求出现同样差异，且差异可归因到被测参数（其他参数不变）。
- **严重级别**：能直接读取 / 篡改业务数据 → high 以上；仅配置问题（缺 HSTS、CORS 过宽）→ low / medium。
- **confidence**：rookie 模式的时间型结果一律不确认；veteran 的时间盲注需两次一致且脱离 payload 后恢复。
- **误报排除**成立后，该条从报告候选中删除，而不是降级保留。
- `evidence` 必须能让人照着复现：方法、URL、参数、payload、观察值缺一不可。

## 常见误报

| 现象 | 排除方法 |
|---|---|
| 状态码变化但 body 相同 | 比较 body 长度 / 哈希，状态码可能被 WAF 随机化 |
| 页面回显 payload 但被 HTML 转义 | 检查是否以文本形式出现；转义不是 XSS |
| 时延抖动被当成盲注 | 基线重跑 3 次取中位数，差异需稳定且远大于抖动 |
| 数据库报错来自通用错误页 | 换不同 payload 复测，报错是否随参数变化 |
| CORS 返回 `*` 但无凭据 | 只有带凭据且回显 Origin 才算风险 |
| 403 / 406 被当成"注入被拦截" | 先确认 WAF 是否对基线也拦截 |
| 响应长度变化来自随机广告 / 时间戳 | 抓两次基线确认动态内容，再比较稳定片段 |

## 停止条件

- 两条以上 checks 指向同一处 SQL / 命令注入可能时，不继续扩大 payload，转人工确认。
- 目标出现写入迹象（数据变化、邮件发出、订单生成），立即停止。
- 请求预算用尽或错误率升高时停止，不重试轰炸。
- 任何需要 OOB 回连、shell、文件写入的验证：插件不提供，转交授权方人工处理。
- 授权过期或目标移出范围，立即停止。

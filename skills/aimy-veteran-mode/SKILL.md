---
name: aimy-veteran-mode
description: 老鸟模式的高覆盖流程：更高并发、全量 checks、时间盲注二次确认与链式排查，但始终只做检测、不越界利用。
whenToUse: 授权范围明确、目标是预发 / 靶场，或需要更高覆盖与链式验证时。
---

# aimy-veteran-mode · 老鸟模式

veteran 提高的是**覆盖与并发**，不是授权。它允许全部 checks、更大请求量、≤5 秒时间盲注，但仍然不写数据、不出网回连、不构造利用链。经验体现在：先排序再打、用最小请求证明最大风险、每条结论都能复现。

## 何时用

- 插件配置 `mode: veteran`，且目标是预发 / 测试环境，或明确允许高覆盖的生产系统。
- 已有资产清单与参数清单，需要系统化覆盖注入类检查。
- 前一轮 rookie 结果需要升级验证（时间盲注二次确认、链式排查）。

## 前置条件

- 授权范围、时间窗、限速约定全部书面确认；联系人可随时叫停。
- 已用 `aimy_recon` / `aimy_crawl` 产出 URL + 参数清单，避免盲扫。
- 配置了 `mode: veteran` 与合适的 `maxRequests`、`timeoutMs`；`allowPrivateNetworks` 只对自建靶场开启。
- 准备停止方案：一旦触发告警，立即降低并发或停。

## 操作步骤

### 1. 快速资产面

```js
aimy_recon({ target: "example.com", checks: ["dns", "http", "headers", "tech", "robots"], timeoutMs: 6000 })
aimy_port_scan({ target: "example.com", preset: "common", timeoutMs: 2000 })
```

- 先确认 CDN / WAF，避免把 WAF 拦截当成漏洞。
- 端口按"web → db → 其他"排序，只对确认 open 的端口做后续。

### 2. 目录与接口高覆盖

```js
aimy_dir_fuzz({ target: "https://example.com", extensions: ["php", "bak", "json", "zip"], statusFilter: [200, 204, 301, 302, 401, 403, 500], maxPaths: 200, followRedirects: true })
aimy_crawl({ target: "https://example.com", maxPages: 50, maxDepth: 3, includeForms: true, includeJs: true })
```

- 用软 404 对照过滤；把爬到的参数直接生成 web_scan 输入。
- JS 里的接口路径优先于字典猜测。
- 301 / 302 跟随时要记录每一跳的 Location，确认没有跳出授权范围。

### 3. 全量 checks

```js
aimy_web_scan({ target: "https://example.com/product?id=1", checks: ["sqli", "xss", "cmdi", "ssti", "ssrf", "nosqli", "lfi", "cors", "graphql", "proto", "headers"], params: [{ name: "id", location: "query", sample: "1" }], timeoutMs: 6000 })
```

- 按参数语义分组：id → sqli / nosqli；q / name → xss / ssti；url / file / path → ssrf / lfi；host / cmd → cmdi。
- 每轮结束检查 `aimy_report({ action: "summary" })` 的请求量与错误率，超预算就停。
- 多参数 URL 逐个参数跑，不要只测第一个。

### 4. 时间盲注二次确认（仅 veteran）

- 插件会在 ≤5 秒内做基线 / 延迟对比；只有两次独立请求都稳定复现，才把 finding 的 `confirmed` 视为真。
- 复测时保持同一参数、同一 payload、同一网络路径；记录基线中位数与延迟值。
- 仍不构造数据读取、不拖库；确认存在即可。
- 若延迟差异不稳定，降级为"待复核"，不要硬定为高危。

### 5. 链式排查（只到"影响证明"为止）

1. 信息泄露（目录 / 备份 / 文档）→ 判断是否含配置或凭据线索。
2. 认证面（JWT / 会话）→ 确认算法 / 密钥 / 会话失效问题。
3. 注入类 → 确认点、参数、类型，停止在"可复现响应差异"。
4. 组合：如"匿名可读的备份 + 其中配置"只做**引用关系**说明，不实际使用凭据登录。
- 每条链在报告里写清"已验证环节"和"未验证环节"，不要把推断写成事实。

### 6. 输出与复核

```js
aimy_report({ action: "findings", severity: ["high", "critical"] })
aimy_report({ action: "report", format: "md", outputPath: "reports/veteran-example-com.md" })
aimy_report({ action: "report", format: "json", outputPath: "reports/veteran-example-com.json" })
```

- 高 / 严重 finding 必须能给出复现请求与观察值；不能复现的降级或删除。
- 报告附上 checks 列表、URL 数、请求量，证明覆盖。

## 判定标准

- **时间盲注确认**：两次独立延迟均显著高于基线（阈值由插件按样例计算），且去掉 payload 后恢复。
- **链式结论**：每个环节都有独立证据；禁止"可能可以 RCE"这类无证据升级。
- **覆盖声明**：报告写清 checks、URL 数、请求量、未测项，不夸大。
- **严重级别**：能证明读取 / 篡改业务数据才算 high 以上；只有报错或差异证据的按 medium 处理。

## 常见误报

| 现象 | 排除方法 |
|---|---|
| 并发下时延抖动 | 降低并发重测，基线取中位数 |
| WAF 对 payload 返回 403 | 用无害 marker 对照，拦截不等于漏洞 |
| 备份文件命中但内容为空 / 模板 | 看实际内容再定级 |
| 同一 finding 多参数重复 | 按 checkId + 根因归并 |
| 链式推断跨系统 | 跨系统必须重新确认授权 |
| 第三方组件版本旧 | 只记为线索，需确认实际可利用路径 |

## 停止条件

- 请求量 / 并发达到约定上限，或错误率 > 5%。
- 触发 WAF / IDS 告警、业务方叫停、或出现数据写入迹象。
- 需要 OOB 回连、反弹 shell、拖库、反序列化利用链 → 一律不做，转人工。
- 授权过期或范围外目标 → 立即停并重新登记。
- 发现真实用户数据 → 只保留最小证据并立即报告。

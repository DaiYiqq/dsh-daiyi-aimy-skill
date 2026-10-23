---
name: aimy-recon-workflow
description: 按 aimy_recon → aimy_port_scan → aimy_dir_fuzz → aimy_crawl 的分层顺序做资产侦察，产出可复核的资产与参数清单。
whenToUse: 授权范围已登记，需要先摸清域名、端口、目录、页面、参数与技术栈时。
---

# aimy-recon-workflow · 侦察工作流

侦察的目标不是"多打几个请求"，而是产出**可复核的资产清单**：域名 / 端口 / 目录 / URL / 参数 / 技术栈。每一步的输出都是下一步的输入，跑完把清单交给 `aimy_web_scan` 和报告。

## 何时用

- 授权范围刚登记好，需要先建立目标画像。
- `aimy_web_scan` 缺参数、缺入口，需要先发现可测 URL 和参数。
- 报告需要资产面信息（开放端口、目录、技术栈）作为背景与覆盖证据。

## 前置条件

- 已用 `aimy_scope` 登记并 `check` 通过；子域、端口要单独登记。
- 明确当前模式：rookie（低并发、少路径）或 veteran（高并发、全量），见 `aimy-rookie-mode` / `aimy-veteran-mode`。
- 确认测试时间窗与限速约定；对生产站点先问清可承受的请求速率。
- 准备记录载体：一个资产表（域名 / 端口 / 路径 / URL / 参数 / 技术栈），每条注明来源工具与时间。

## 操作步骤

### 1. 网络与协议层

```js
aimy_recon({ target: "example.com", checks: ["dns", "http", "headers", "tech", "robots"], timeoutMs: 8000 })
```

- `dns`：确认 A / AAAA / CNAME，识别 CDN 与 WAF；CNAME 指向第三方时先核对授权范围。
- `http`：确认可达协议（http / https）、重定向链、默认首页状态码。
- `headers`：记录 `Server`、`X-Powered-By`、`Set-Cookie`、HSTS 等，供后续 headers 检查对比。
- `tech`：输出技术栈线索（框架、CMS、JS 库），决定后续 wordlist 与 checks 选择。
- `robots`：拿 Disallow 列表当"目录提示"，但 robots 本身不是漏洞。

### 2. 端口面

```js
aimy_port_scan({ target: "example.com", preset: "web", timeoutMs: 3000 })
```

- `preset` 取 `top20` / `common` / `web` / `db`；只关心 Web 面就用 `web`。
- 明确端口清单时用 `ports` 覆盖 preset：

```js
aimy_port_scan({ target: "127.0.0.1", ports: [80, 443, 8080, 8443], timeoutMs: 2000 })
```

- 回环 / 内网目标需要 `allowPrivateNetworks: true`，且仅限自建靶场。
- 只对确认 open 的端口继续做后续探测，closed / filtered 不追。

### 3. 目录与文件

```js
aimy_dir_fuzz({ target: "https://example.com", extensions: ["php", "bak", "json"], statusFilter: [200, 204, 301, 302, 401, 403], maxPaths: 120, followRedirects: false })
```

- 自定义字典时传 `wordlist`（字符串数组），rookie 模式控制在 40 条以内。
- 301 / 302 默认不跟随，先记录 `Location` 再判断是否同源。
- 对"像命中"的路径做二次核对：同一路径再请求一次 + 一个随机不存在路径对照，排除 soft-404。

### 4. 页面与参数

```js
aimy_crawl({ target: "https://example.com", maxPages: 20, maxDepth: 2, includeForms: true, includeJs: true })
```

- `includeForms` 收集表单 action / method / 字段，直接生成 `aimy_web_scan` 的 `params`。
- `includeJs` 从 JS 中提取接口路径（如 `/api/v1/*`），补进 dir_fuzz 或 web_scan 目标。
- 爬取结果按 URL 去重、按参数名归并，形成 `{ url, method, params[] }` 列表。

### 5. 汇编资产清单

- 域名 / 端口 / 目录 / URL / 参数 / 技术栈各一张表，标注来源工具与时间。
- 把待测 URL 与 params 作为 `aimy_web_scan` 的输入；把资产表写进最终报告背景。
- 清单里每一条都要再 `aimy_scope({ action: "check", target })` 一次，范围外条目直接剔除。

## 判定标准

- **端口 open**：同端口再连一次仍成功，且不是防火墙"全连成功"假象（换端口对照）。
- **目录命中**：目标路径与随机路径在状态码 / 响应长度 / 内容上明显不同。
- **指纹**：至少两条独立证据（header + 页面特征 + 静态资源路径），单条证据只记为线索。
- **参数**：来自真实表单 / JS / URL，不凭空构造；每个参数保留 sample 值用于后续基线。
- 资产清单覆盖率要写进报告：测了几个 URL、几个参数、多少请求。

## 常见误报

| 现象 | 排除方法 |
|---|---|
| 任意路径都返回 200 | 随机路径对照，多数是 SPA fallback 或软 404 |
| 端口全 open | 目标有防火墙 / 代理回显，换端口再对照 |
| 通配 DNS 导致子域全解析 | 查随机子域，能解析即通配，不代表子域存在 |
| 403 当成"存在且可绕过" | 403 只说明被拒，先看 WAF 类型再决定是否继续 |
| robots 里的路径当成漏洞 | 只是爬虫约定，需实际访问验证 |
| 目录命中但内容是欢迎页 | 看 body 特征，模板页不算资产 |

## 停止条件

- 请求错误率或延迟明显上升（5xx 比例 > 5%），先降速或停。
- 响应中出现真实用户数据、凭据、他人业务内容，立即停止并报告。
- 目标解析到授权清单外的 IP / 域名，或子域指向第三方托管。
- 端口扫描触发 IDS / IPS 告警，或被联系人叫停。
- 请求量达到本轮约定预算，不重试轰炸。

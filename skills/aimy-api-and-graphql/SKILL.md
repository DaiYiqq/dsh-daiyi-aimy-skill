---
name: aimy-api-and-graphql
description: 发现并检测 API / GraphQL 暴露面：接口文档、introspection、批量查询与隐藏参数，只做只读验证。
whenToUse: 目标存在 /api、/graphql、/swagger 等接口面，或前端 JS 中出现接口路径时。
---

# aimy-api-and-graphql · API 与 GraphQL 面

API 的测试重点是**暴露面**与**授权边界**，不是把每个字段都打一遍。先找入口，再判断是否允许匿名访问、是否存在越权与放大查询。

## 何时用

- `aimy_recon` 的 tech / headers 提示前后端分离、OpenAPI、GraphQL。
- `aimy_crawl` 的 includeJs 收集到 `/api/`、`/v1/`、`/graphql` 路径。
- 需要判断 introspection 是否开放、批量查询是否受控、隐藏参数是否存在。

## 前置条件

- 范围已登记；API 主机（如 `api.example.com`）与主域分开登记。
- 明确请求格式：REST（JSON）、GraphQL（POST `/graphql`）、RPC 风格。
- 准备测试账号；匿名访问测试与登录后测试分开做，结论不要混在一起。
- 插件只做检测：不调用 mutation、不做批量数据抓取、不改任何资源。

## 操作步骤

### 1. 找接口入口

```js
aimy_dir_fuzz({ target: "https://api.example.com", wordlist: ["api", "v1", "v2", "graphql", "swagger", "openapi.json", "docs", "health"], extensions: ["json"], statusFilter: [200, 204, 301, 302, 401, 403], maxPaths: 40 })
```

- swagger / openapi 文档能直接给出参数、枚举与示例，优先拿文档。
- 对比 404 页与文档页长度，避免把 SPA 回退页当成接口。
- 命中 `401` / `403` 的路径也记为入口，后面用测试账号判断授权。

### 2. 爬取 JS 找隐藏接口

```js
aimy_crawl({ target: "https://example.com", maxPages: 20, maxDepth: 2, includeForms: true, includeJs: true })
```

- 从 JS bundle 里提取 `/api/...`、fetch / axios 调用、GraphQL endpoint。
- 把新发现的接口补进 `aimy_dir_fuzz` / `aimy_web_scan`，不要直接在真实用户数据上试。
- 前端路由（`/dashboard`、`/settings`）不算 API，按响应 Content-Type 区分。

### 3. GraphQL introspection 与查询面

```js
aimy_web_scan({ target: "https://example.com/graphql", method: "POST", checks: ["graphql"], params: [{ name: "query", location: "json", sample: "{__typename}" }], timeoutMs: 8000 })
```

- 关注：introspection 是否开放、错误信息是否泄露 schema、是否允许批量 / 别名放大查询。
- 只读查询 `{__typename}` 或 `query { __schema { types { name } } }` 属于检测行为；不要构造破坏性 mutation。
- 返回 200 且包含字段列表 → introspection 开放；结合授权要求判断风险。
- GraphQL 错误通常也是 HTTP 200，必须看响应里的 `errors` 字段。

### 4. 参数挖掘（隐藏参数 / 批量赋值）

```js
aimy_web_scan({ target: "https://example.com/api/v1/users/me", params: [{ name: "role", location: "query", sample: "user" }, { name: "isAdmin", location: "query", sample: "false" }], checks: ["sqli", "nosqli", "xss"], timeoutMs: 8000 })
```

- 隐藏参数只测"是否改变响应 / 权限判断"，不构造提权后的写操作。
- JSON body 批量赋值验证：只观察响应里是否多出字段，不做持久化修改。
- 参数名来自 JS / 接口文档 / 错误信息，不要无边界猜。

### 5. 授权边界

- 匿名请求 → 401 / 403 是正常；匿名 200 才是问题。
- 登录后请求他人资源（见 `aimy-auth-and-jwt` 的交叉账号方法），只读验证。
- GraphQL 单端点里不同字段可能走不同授权逻辑，逐个字段确认，不要用一次查询代表全部。

### 6. 回归与覆盖记录

```js
aimy_report({ action: "summary" })
aimy_report({ action: "report", format: "json", outputPath: "reports/api-example-com.json" })
```

- 记录测过的接口数、参数数、checks、请求量；需要登录 / 特殊权限而未测的接口单独列出。
- 修复验证：对同一接口用同样的检查重跑，记录新旧响应差异，不要只看旧报告。
- GraphQL 结论要注明是匿名可访问还是登录后可访问，两者风险级别不同。

## 判定标准

- **文档暴露**：swagger / openapi 可匿名读取，且包含内部接口、管理接口或调试接口。
- **introspection 开放**：匿名或普通账号能拿到完整 schema（`__schema` 有返回）。
- **批量查询风险**：单请求可返回远超正常量的数据（如一次 1000 条），且无速率 / 复杂度限制。
- **隐藏参数风险**：加入字段后响应出现不该出现的敏感字段（如 password、token、internal），或权限判断改变。
- **越权**：普通账号能读取他人资源，且用另一账号反向验证成功。

## 常见误报

| 现象 | 排除方法 |
|---|---|
| `/api` 返回 200 但内容是 HTML | 前端路由回退，看 Content-Type |
| GraphQL 返回错误但 HTTP 200 | GraphQL 错误也是 200，看 errors 字段 |
| `__typename` 有返回就认为 introspection 开放 | introspection 专指 `__schema` / `__type` 查询 |
| 匿名能读 openapi.json | 公开文档不一定是问题，看是否含内部接口 |
| 参数加进去响应变长 | 可能只是回显 / 反射，确认是否有敏感值 |
| 批量查询返回多页 | 分页是正常设计，看是否可无限放大 |

## 停止条件

- 发现接口返回真实用户数据，立即停止并只保留一条最小证据。
- 确认 introspection 需要构造大规模查询才能继续时，停；不做数据抓取。
- 任何 mutation / 写接口验证一律不做，转人工在授权后处理。
- 目标限流 / 封禁开始影响正常业务时停止。
- 授权过期或 API 主机移出范围，立即停止。

---
name: aimy-authorized-scope
description: 在任何目标操作前用 aimy_scope 登记并核验授权范围，把范围闸门当成所有网络工具的强制前置步骤。
whenToUse: 会话开始、切换目标、扩大范围，或任何工具返回 NO_SCOPE / NO_MATCH / EXPIRED / PRIVATE_BLOCKED 时。
---

# aimy-authorized-scope · 授权范围与合规

`aimy_scope` 是本插件的 deny-by-default 闸门：没有登记范围时，`aimy_recon`、`aimy_port_scan`、`aimy_dir_fuzz`、`aimy_crawl`、`aimy_web_scan` 全部拒绝执行（`aimy_jwt_audit` 是纯本地 JWT 解析、不发网络请求，因此不受范围限制，但也只应在授权测试中使用）。顺序永远是：先建范围，再做任何探测。

## 何时用

- 新会话第一次接触任何目标之前。
- 目标从主域切到子域、端口、路径前缀，或从测试环境切到预发/生产环境时。
- 任何工具返回 `NO_SCOPE`、`NO_MATCH`、`EXPIRED`、`PRIVATE_BLOCKED` 时。
- 交接给同事、结束任务、需要清理范围时。

## 前置条件

1. 拿到可核对的书面授权：授权方、目标清单（域名 / IP / 端口 / 路径）、测试类型、时间窗、紧急联系人。
2. 把授权依据压缩成一句话存进 `authorization`：编号 + 范围，**至少 8 个字符**，不能写"客户同意了"。
3. 确认目标归属：解析到的 IP、CNAME、CDN 是否仍属于授权方；第三方托管域名通常不在范围内。
4. 回环 / 内网目标（`127.0.0.1`、`10.x`、`192.168.x`）需要插件配置 `allowPrivateNetworks: true`，且只应在自建靶场使用。
5. 记住：`goal` 是"完成授权测试"，不是"打穿目标"。范围外的任何请求都算违规。

## 操作步骤

### 1. 登记授权范围

```js
aimy_scope({ action: "add", target: "example.com", authorization: "客户授权函 #A-1024：example.com 全端口 Web 测试，2026-11-01 前有效", expiresInHours: 48 })
```

- `target` 支持 `example.com`、`*.example.com`、`https://example.com/app`、`example.com:8443`、`127.0.0.1:8080`。
- 通配只匹配子域，不覆盖 apex；`*.example.com` 需要单独登记一条。
- 端口、scheme、路径前缀都会参与匹配，登记什么就只覆盖什么。

### 2. 核对已登记范围

```js
aimy_scope({ action: "list" })
```

- 逐条看 host、port、scheme、pathPrefix、expiresAt 是否覆盖接下来的操作。
- `list` 结果是报告附录的一部分，先截图/复制保存，避免结束时忘记。

### 3. 开测前逐目标 check

```js
aimy_scope({ action: "check", target: "https://example.com/login" })
```

- 结果里的放行判定看 `check.ok`：为 `true` 才继续；为 `false` 时看 `check.code`，值为 `NO_MATCH` 就补登记，不要绕过。
- `check` 能识别 `EXPIRED`、`PRIVATE_BLOCKED`、`FORBIDDEN_ADDRESS`，按拒绝码处理；`message` 会给出"目标在/不在授权范围内"。

### 4. 扩大范围时先 remove 再 add

```js
aimy_scope({ action: "remove", target: "example.com" })
aimy_scope({ action: "add", target: "https://example.com:8443/app", authorization: "授权补充邮件 #A-1024-2：新增 8443 端口与 /app 前缀", expiresInHours: 24 })
```

- 新目标必须带新的授权依据，不能沿用旧编号。
- 子域 `api.example.com` 与主域分开登记；第三方 API 平台不在客户授权内。

### 5. 结束清理

```js
aimy_scope({ action: "clear" })
```

- 清理前先 `list` 并保存快照；清理后不得再用旧结果继续请求。
- 清理范围 ≠ 删除审计日志；报告里要保留登记与清理时间。

## 判定标准

- **允许**：`aimy_scope({ action: "check" })` 返回的 `check.ok` 为 `true`，且 `check.entry` 的 host / port / scheme / pathPrefix 与当前操作完全一致。
- **拒绝**：`check.code` 为 `NO_SCOPE`（先 add）、`NO_MATCH`（范围不含该 URL）、`EXPIRED`（重新登记）、`PRIVATE_BLOCKED`（未开 allowPrivateNetworks）、`FORBIDDEN_ADDRESS`（链路本地 / 组播 / 保留地址，禁止登记）。
- 授权文本必须能回溯到具体文件、邮件或工单；口头同意不算授权依据。
- 示例目标只使用 `example.com`、`http://127.0.0.1:8080`、`scanme.nmap.org` 这类公开可测目标；真实客户目标以授权清单为准。

## 常见误报（其实是常见违规）

| 现象 | 正确处理 |
|---|---|
| 主域已登记，子域没登记 | 子域不是自动覆盖，单独 add `*.example.com` 或具体子域 |
| 登记 `example.com`，测试 `https://example.com:8443` | 端口不匹配，补登记带端口的目标 |
| 解析到第三方 CDN IP 就去扫 IP | IP 归属不在授权清单，停下并找授权方确认 |
| 授权过期后仍继续 | `list` 里 `expired: true` 的目标一律重登 |
| 拿示例域名当"真实客户"练习 | 只在公开授权演示目标上练习，别碰真实资产 |

## 停止条件

- 目标不在已登记范围，且当次拿不到书面扩展授权。
- 授权过期、授权方撤回、联系人要求暂停。
- 发现目标是第三方 SaaS / 云厂商共享设施，或验证需要访问他人数据。
- 探测出现明显业务影响：5xx 比例上升、响应时间翻倍、触发告警。
- 任何需要写操作（上传、删除、改配置、拖库）的验证：插件只做检测，直接停。

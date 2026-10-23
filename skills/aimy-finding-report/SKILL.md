---
name: aimy-finding-report
description: 用 aimy_report 把检测结果整理成 md / json / sarif 报告，写清证据、复现步骤、影响与修复建议。
whenToUse: 一轮检测结束需要输出报告、给 CI 出 SARIF、或交付前复核 finding 时。
---

# aimy-finding-report · 取证与报告

报告的读者是客户 / 开发 / 复核人。每条 finding 必须回答：在哪个 URL、哪个参数、用什么请求、观察到什么、如何复现、如何修。`aimy_report` 是唯一出口。

## 何时用

- 每次检测结束后（哪怕 0 条命中，也要出 summary 证明覆盖范围）。
- 需要按 severity 过滤、给开发出 JSON、或给 CI 出 SARIF。
- 交付前复核 finding，剔除误报与重复项。

## 前置条件

- 本轮工具调用已结束，store 中有运行记录与 findings。
- 已保存范围快照与授权依据（来自 `aimy_scope` 的 `list`），准备作为附录。
- 每个 finding 的 `evidence` 已人工看过，确认不是误报、不是幻觉。
- 确认报告里不会出现真实用户数据、token、cookie；需要时先脱敏。

## 操作步骤

### 1. 先看汇总

```js
aimy_report({ action: "summary" })
```

- 确认扫描目标、时间、模式、请求量、各 severity 数量与模块分布。
- 0 命中也要保留 summary，作为"已测且未发现"的覆盖证据。
- 汇总异常（请求量远超预算、模块报错）要先排查，再导出报告。

### 2. 复核 finding 明细

```js
aimy_report({ action: "findings", severity: ["high", "critical"] })
```

- 逐条看 `evidence`：状态码、关键字、时延、对比差异是否齐全（≤800 字符）。
- `confidence: low` 且未 `confirmed` 的条目，要么补验证，要么删除。
- 同一 `checkId` + 同一参数的重复记录按根因归并，保留代表性 URL。

### 3. 输出 Markdown 报告

```js
aimy_report({ action: "report", format: "md", outputPath: "reports/example-com-2026-10-23.md" })
```

- 报告结构建议：范围与授权 → 测试环境 / 时间窗 → 资产面 → finding 列表（按 severity）→ 覆盖与未测项 → 附录（scope 快照、请求样例）。
- 每条 finding 写复现步骤：编号、前提（账号 / 角色）、请求（方法 / URL / 参数，脱敏）、观察（状态码 / 关键字 / 时延）、结论。
- 写"未测项"：没测的端口、没登录的角色、没跑的 checks，避免让人误以为全覆盖。

### 4. 输出 JSON（给开发 / 平台）

```js
aimy_report({ action: "report", format: "json", severity: ["medium", "high", "critical"], outputPath: "reports/example-com-2026-10-23.json" })
```

- JSON 保留原始字段（module / checkId / url / param / payload / evidence / cwe / remediation），便于导入漏洞平台。
- 交付前确认没有把真实用户数据、token、cookie 写进报告。

### 5. 输出 SARIF（给 CI / 代码扫描平台）

```js
aimy_report({ action: "report", format: "sarif", outputPath: "reports/example-com-2026-10-23.sarif" })
```

- SARIF 适合在 CI 里做增量告警；同一 finding 的 ruleId 用 `checkId`，便于去重。
- 确认 severity 映射符合平台规则（critical / high → error，medium → warning，low / info → note）。
- 确认 `artifactLocation.uri` 能对应到扫描 URL，否则平台无法定位。

### 6. 查看历史运行

```js
aimy_report({ action: "runs" })
```

- 对比不同时间窗的结果，确认修复是否生效；不要用旧 finding 直接当新结论。
- 修复验证要重新扫描同一 URL 同参数，并记录新请求的时间。

### 7. 清理（可选）

```js
aimy_report({ action: "clear" })
```

- 只在报告已归档、不再需要对比时清；清之前备份 JSON。
- 清理后 summary / findings 为空，不能拿旧结论充数。

## 判定标准

- **可交付**：每条 finding 都有 URL + 参数 + 证据 + 复现步骤 + 修复建议，且 severity / confidence 与证据一致。
- **不可交付**：只有标题没有证据、无法复现、把 info 级配置问题写成高危、泄露凭据 / 真实数据。
- **修复建议要具体**：如"改参数化查询 / 白名单校验 / 输出编码 / 设置 Content-Security-Policy"，不要写"加强安全"。
- **覆盖声明要诚实**：报告写清 checks、URL 数、请求量、未测项，不夸大。

## 常见误报（报告层面）

| 问题 | 处理 |
|---|---|
| 同一 check 在多 URL 重复 | 按 checkId + 参数归并，保留代表性 URL |
| 扫描器差异未被复核 | 删除或标"待复核"，不要直接进高危 |
| 报告含测试 token / cookie | 脱敏后再交付 |
| 修复建议模板化 | 对每条 finding 写对应修复点 |
| severity 与 evidence 不匹配 | 按影响重新定级，不确定就降级 |

## 停止条件

- 证据不足且无法在不扩大影响的前提下复现 → 不写进报告。
- 报告将包含真实用户数据 / 凭据 → 停止导出，先脱敏。
- 客户要求只交 summary 时，不擅自导出完整 findings。
- 发现报告内容与授权范围不符（含范围外目标）→ 停止交付并修正。

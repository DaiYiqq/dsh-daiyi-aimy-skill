# 内部开发契约 · dsh-daiyi-aimy-skill

> 本文件是给参与开发的 agent/人类看的**写死契约**，不是用户文档。
> 任何模块都必须严格遵守下面的数据形状；跨模块只通过这里定义的形状交互。
> 语言：源码注释与 README 用中文，标识符用英文。全部 ESM（`"type": "module"`），**运行时零第三方依赖**，只用 `node:` 内置模块。

## 0. 插件加载契约（DSH / Cordis）

`lib/index.js` 必须导出：

```js
export const name = 'daiyi-aimy-skill'
export const inject = ['tools', 'skills']   // 缺任一服务时不得抛错
export function apply(ctx, config) { /* 注册工具与技能，返回可清理的副作用 */ }
export default apply
```

工具注册：`ctx.tools.register(defineTool({ ... }))`，`defineTool` 从 `@deepseek-ai/dsh-tools` 导入（宿主提供，禁止写进 dependencies）。
技能注册：`ctx.skills.register({ name, description, whenToUse, content, invocation })`。
`apply` 必须**永不抛异常**：单个工具注册失败只 `log.warn` 并继续，保证插件不会拖垮宿主启动。

## 1. 目录与写入边界（谁写哪里）

| 范围 | owner | 允许写 |
|---|---|---|
| `package.json` `cordis.patch.yml` `lib/index.js` `lib/config.js` `lib/scope.js` `lib/http.js` `lib/store.js` `lib/report.js` `lib/tools/**` `lib/engine/index.js` `docs/CONTRACT.md` | lead | 全部 |
| `lib/engine/**`（除 `index.js`）`test/engine/*.test.js` | engine-core | 仅这些 |
| `skills/**` `lib/skills/**` `test/skills.test.js` | skills-author | 仅这些 |
| `README*.md` `docs/*.md`（除 CONTRACT.md） `CHANGELOG.md` `LICENSE` `.github/**` `.gitignore` `.editorconfig` | docs-author | 仅这些 |
| `test/contract/*` `test/helpers/**` `scripts/validate-plugin.mjs` | contract-verifier | 仅这些 |
| `test/scope.test.js` `test/core.test.js` `test/http.test.js` `test/plugin.test.js` | lead | 仅这些 |

禁止跨范围写文件；发现需要改别人的文件 → 通知 lead。

### 1.1 参数 schema 的硬规则（已被宿主编译器验证）

- `required` 字段**只能写 `true` 或省略**；写 `required: false` 会被宿主判为
  `unsupported JSON schema: ... required must be true when present`。
- 支持的关键字：`type` / `oneOf` / `properties` / `required` / `additionalProperties` / `items` / `enum` / `const`；
  `type` 只能是单个字符串；`type` 数组不支持。
- 值类型支持 `string` / `number` / `integer` / `boolean` / `array` / `object` / `json`。

## 2. 核心类型（JSDoc 形状，全部普通对象，不要用 class）

### 2.1 Target

```js
/** @typedef {{ url: URL, origin: string, host: string }} Target */
```

### 2.2 ProbeResponse —— `lib/http.js` 的 `probe()` 返回

```js
/**
 * @typedef {object} ProbeResponse
 * @property {'GET'|'POST'|'HEAD'|'PUT'|'OPTIONS'} method
 * @property {string} url            最终 URL（未跟随重定向时即请求 URL）
 * @property {number} status         HTTP 状态码；网络失败为 0
 * @property {Record<string,string>} headers  小写 key
 * @property {string} body           响应体，已按 maxBodyBytes 截断
 * @property {number} elapsedMs
 * @property {boolean} truncated     body 是否被截断
 * @property {string} [error]        网络层错误消息（status===0 时必有）
 */
```

### 2.3 ProbeContext —— 传给每个 engine 模块的 `run(ctx)`

```js
/**
 * @typedef {object} ProbeContext
 * @property {Target} target
 * @property {(url: string|URL, init?: ProbeInit) => Promise<ProbeResponse>} probe
 * @property {Array<ParamSpec>} params       待测参数；无参数时为空数组
 * @property {'rookie'|'veteran'} mode
 * @property {boolean} authorized            始终为 true（进入引擎前已过 scope 闸门）
 * @property {AbortSignal} signal
 * @property {(level:'debug'|'info'|'warn', msg:string) => void} log
 * @property {{ timeoutMs:number, maxRequests:number, maxBodyBytes:number }} limits
 */

/**
 * @typedef {object} ProbeInit
 * @property {'GET'|'POST'|'HEAD'|'PUT'|'OPTIONS'} [method]
 * @property {Record<string,string>} [headers]
 * @property {string} [body]
 * @property {boolean} [followRedirects]   默认 false
 */

/**
 * @typedef {object} ParamSpec
 * @property {string} name
 * @property {'query'|'body'|'json'} location
 * @property {string} sample                已知的合法样例值（用于构造基线）
 */
```

### 2.4 Finding —— 引擎唯一输出

```js
/**
 * @typedef {object} Finding
 * @property {string} module            引擎模块 id，如 'sqli'
 * @property {string} checkId           检查点 id，如 'sqli-error-boolean'
 * @property {string} title             一句话标题（中文）
 * @property {'info'|'low'|'medium'|'high'|'critical'} severity
 * @property {'low'|'medium'|'high'} confidence
 * @property {string} url
 * @property {string} [param]
 * @property {string} [payload]
 * @property {string} evidence          ≤800 字符，必须包含可复核的观测（状态码/关键字/时延）
 * @property {string} [cwe]             如 'CWE-89'
 * @property {string} [remediation]     修复建议（中文一句话）
 * @property {boolean} [confirmed]      true=重复验证过（时间型盲注第二次确认等）
 */
```

**硬性要求**

1. 引擎模块**绝不自己发网络请求**，只能调用 `ctx.probe`；不得 import `lib/http.js`。
2. 单模块总请求数 ≤ `ctx.limits.maxRequests`（默认 40），且每次 await 后检查 `ctx.signal.aborted`。
3. 只做**检测**：不得写入、删除、反弹 shell、横向移动、拖库、构造反序列化利用链。
   允许：无害 marker（如 `aimy1337`）、时间盲注 `SLEEP`（≤5s，且只在 veteran 模式）、
   DNS/HTTP 回连探测**不发起**（无 OOB 服务）。
4. 结果**确定性**：同一输入同一响应 → 同一输出（排序稳定，不用 Date.now/Math.random 参与判定）。
5. 无副作用：模块不得写文件、不得改环境变量。

### 2.5 引擎模块导出形状

```js
export const meta = {
  id: 'sqli',                        // kebab，唯一；必须与 CHECK_CATALOG.moduleId 一致
  title: 'SQL 注入检测',
  kinds: ['sqli'],                   // 供 aimy_web_scan 的 checks 参数选择
  cwe: 'CWE-89',
  defaultSeverity: 'high',
  minMode: 'rookie',                 // 'rookie' | 'veteran'
}
/**
 * @param {ProbeContext} ctx
 * @returns {Promise<Finding[]>}
 */
export async function run(ctx) { return [] }
```

`lib/engine/index.js`（lead 写）是**按需动态加载**的目录调度器，实际导出：

```js
export const CHECK_CATALOG  // [{ check, moduleId, title, file, minMode }]，12 项，工具参数 enum 的唯一来源
export function listChecks()                 // [{ id, title }] 同步；供 defineTool 的 enum 使用
export async function runChecks(ctx, checks, { onSkip, log })  // 逐项加载并执行，单项失败只跳过
export async function crawl(ctx, options)     // 转调 crawler.js 的 crawl()
export async function mineParams(ctx, options)// 转调 param-miner.js 的 mineParams()
export async function fingerprint(ctx)        // 转调 tech-fingerprint.js 的 fingerprint()
```

模块文件缺失或语法错误时，`runChecks` 只把该项记入 `onSkip`，不抛错——
这样单个引擎模块的问题不会让整个插件加载失败。

## 3. 技能包契约（skills-author）

- 每个技能目录 `skills/<kebab-name>/SKILL.md`，frontmatter：

```markdown
---
name: aimy-recon-workflow
description: 一句话（≤160 字符，中文，用于目录）
whenToUse: 何时加载（一句话）
---

正文 markdown…
```

- 名称必须 kebab-case（`^[a-z0-9]+(?:-[a-z0-9]+)*$`），**统一以 `aimy-` 开头**，避免和宿主内置技能撞名。
- `lib/skills/index.js` 导出：

```js
/**
 * @returns {Promise<{ skills: Array<{ name:string, description:string, whenToUse?:string, content:string }>, warnings: Array<{ file:string, message:string }> }>}
 */
export async function loadSkillPack(options?: { dirs?: string[] }): Promise<{ skills, warnings }>
/** 解析单文件文本（非法输入抛错，由 loadSkillPack 捕获转 warnings） */
export function parseSkillMarkdown(text: string, filename: string): { name, description, whenToUse, content }
/** 最小 YAML frontmatter 解析（只支持 key: value 标量） */
export function parseFrontmatter(text: string): { data: Record<string,string>, body: string }
```

调用方约定：插件入口用 `const { skills, warnings } = await loadSkillPack()` 解构，**不会**把返回值当数组用。

`loadSkillPack` 必须：只用 `node:fs/promises`，路径由 `fileURLToPath(import.meta.url)` 推出包根，按目录名排序保证确定性，解析失败跳过并返回 `warnings` 数组（`{file, message}`）而不抛错。

## 4. 报告契约（lead）

`lib/report.js` 导出 `renderMarkdown(report)`, `renderJson(report)`, `renderSarif(report)`；
`report` 形状见 `lib/store.js` 的 `snapshot()`。

## 5. 校验（contract-verifier）

- `scripts/validate-plugin.mjs`：读 `package.json`，断言 `dsh.bundle.patch` 存在且是文件、
  `exports['.']`/`exports['./cordis.patch.yml']` 指向文件、`lib/index.js` 有 `name/inject/apply`、
  `cordis.patch.yml` 的 insert 项 `name` 与包名一致、`skills/*/SKILL.md` frontmatter 合法。
- `test/contract/*.test.js`：用**真实** `@deepseek-ai/dsh-tools` 的 `defineTool` 校验每个工具的
  `parameters`/`output.schema` 合法（从 `D:\openclaw\_dsh_asar_ref\dsh-tools` 借源码，见脚本说明）。
- 全部 `node --test` 可通过，且 `node --check` 覆盖所有 `lib/**/*.js`。

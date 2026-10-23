# 契约测试（contract-verifier 维护范围）

独立验收脚本与测试，不依赖网络、不依赖完整 DSH 运行时；缺少宿主/文件时 **skip 而不是 fail**。

## 运行

```bash
# 全仓库测试（package.json 的 npm test 就用这条）
node --test "test/**/*.test.js"

# 只跑契约测试
node --test "test/contract/*.test.js"

# 插件清单/文件契约校验器（exit 0/1，人读清单）
node scripts/validate-plugin.mjs
node scripts/validate-plugin.mjs --json
```

> ⚠️ `node --test test/contract`（把目录当位置参数）在 Node 22/24 上不可用：Node 的
> test runner 只接受文件或 glob 位置参数，目录会被当成模块执行并报
> `Cannot find module ...\test\contract`。本地实测 Node v24.21.0。
> 请使用上面的 glob 写法（或 Node 20 的目录写法）。

## 真实宿主（`@deepseek-ai/dsh-tools`）来源顺序

`test/helpers/dsh-tools.mjs` 按以下顺序寻找真实 `defineTool`：

1. `DSH_TOOLS_DIR` 环境变量；
2. 仓库真实 `node_modules/@deepseek-ai/dsh-tools`；
3. `test/helpers/vendor/@deepseek-ai/dsh-tools`（若 vendored 整包）；
4. 解包源码 `../_dsh_asar_ref/dsh-tools`（可用 `DSH_UNPACKED_ROOT` 覆盖）。

解包来源会用 Node 的 `registerHooks()` 装一个最小 import map（`@deepseek-ai/dsh-tools` /
`dsh-llm` / `dsh-util-values` / `schemastery` / `cosmokit`），把真实 `lib/types/schema.js`
的 `defineTool` 加载起来。包根 `lib/index.js` 依赖整个 LLM 运行时闭包（typert-protocol +
zod，约 9MB），因此会自动回退到 `lib/types/schema.js`（原因记录在 `loadDshTools().notes`）。

`test/helpers/vendor/` 已被 `.gitignore` 忽略（见 `test/helpers/VENDOR.md`）：
全新 clone / CI 上没有它时，需要真实宿主的用例会 skip，其余用例照常通过。

## 对 `lib/tools/index.js` 导出形状的要求

工具定义必须是**真实** `defineTool(...)` 的结果（`test/helpers/tools-adapter.mjs` 的软适配器识别）：

```js
export const TOOLS = [ ... ]        // 首选
export const tools = [ ... ]        // 备选
export default [ ... ]              // 备选
export function createTools(deps) { return [ ... ] }  // 工厂形状（当前实现，适配器以桩 deps 调用）
```

工具数量契约：`lib/index.js` 的 `apply(ctx, {})` 在假 ctx 上注册 **8 工具 / 8 技能**。

## 文件

- `validate-plugin.test.js`：校验器解析器（最小 YAML/frontmatter）+ 合规/违规夹具 + 真实仓库
- `tool-definitions.test.js`：真实 `defineTool` 校验 `lib/tools/index.js` 的每个定义
- `plugin-apply.test.js`：`lib/index.js` 的 `apply()` 行为（注册数量、永不抛错、重复 apply、缺服务）
- `../helpers/dsh-tools.mjs`：宿主加载与 import map
- `../helpers/fake-ctx.mjs`：假 Cordis ctx（tools/skills/logger/effect）
- `../helpers/tools-adapter.mjs`：导出形状软适配器
- `../helpers/tool-assertions.mjs`：工具/技能定义共享断言

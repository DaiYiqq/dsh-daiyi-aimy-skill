# 测试用第三方依赖（vendor）说明

`test/helpers/vendor/` 存放**从本机 DSH 安装包 `app.asar` 原样解包**的第三方代码，仅供
契约测试在没有网络、没有完整 DSH 运行时的环境下加载**真实** `@deepseek-ai/dsh-tools`
的 `defineTool` 与 schema 编译器。

> ⚠️ 该目录已被 `.gitignore` 忽略（`test/helpers/vendor/`），不会进入仓库/发布包。
> 这意味着：**全新 clone 或 CI 上没有这个目录时，依赖真实宿主的契约测试会 skip
> 而不是 fail**（见 `test/helpers/dsh-tools.mjs`）。本地开发时如需跑真实校验，
> 按下面步骤重新解包即可。

## 目录内容（2026-10 解包，宿主版本 0.2.1-rc.2）

| 包 | 版本 | 保留的文件 | 用途 |
|---|---|---|---|
| `@deepseek-ai/dsh-tools` | 0.2.1-rc.2 | 不复制，直接读取 `../_dsh_asar_ref/dsh-tools` | 被测的真实 `defineTool` 实现 |
| `@deepseek-ai/dsh-llm` | 0.2.1-rc.2 | 仅 `lib/types/error.js` | `HarnessError`（schema 错误基类，独立文件、无依赖） |
| `@deepseek-ai/dsh-util-values` | 0.2.1-rc.2 | `lib/index.js` | `assertNever` / `isJsonValue` 等纯函数 |
| `@deepseek-ai/schemastery` | 3.18.5 | `lib/index.mjs` + `lib/index.cjs` | 通过 import map 指到 vendor（宿主包根会用到） |
| `@deepseek-ai/cosmokit` | 1.8.6 | `lib/index.js` | schemastery 的唯一依赖 |

刻意**没有** vendored 的重型依赖：`@deepseek-ai/dsh-typert-protocol`（约 5.5MB）与 `zod`
（约 3.9MB）。它们只被 `dsh-tools` 包根 `lib/index.js` 的 LLM 运行时闭包使用；契约校验
只需要 `lib/types/schema.js` + `lib/types/json-schema.js`，加载时会先尝试包根、失败后
自动回退到这两个模块（原因会记录在 `loadDshTools()` 返回的 `notes` 里）。

## 重新解包

需要一个能读取 `app.asar` 的小工具。本机（开发机）示例：

```powershell
node D:\dsh\tools\asar-extract.mjs "D:\deep seek\resources\app.asar" `
  "dsh/node_modules/@deepseek-ai/dsh-llm/" `
  "D:\openclaw\dsh-daiyi-aimy-skill\test\helpers\vendor\@deepseek-ai\dsh-llm"
# 其余包同理：把 @deepseek-ai/dsh-llm 换成 dsh-util-values / schemastery / cosmokit
```

解包后按上表裁剪（`dsh-llm` 只留 `LICENSE`、`package.json`、`lib/types/error.js`），
再运行：

```powershell
node --test "test/contract/*.test.js"
```

## 来源与许可证

所有文件均为上游 npm 包（MIT，`@deepseek-ai/*`）的原样字节，未做任何改写；每个包目录
内保留了上游 `LICENSE`。第三方代码仅用于测试，不参与插件运行时（插件本身零第三方依赖）。

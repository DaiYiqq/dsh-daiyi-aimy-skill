/**
 * 加载宿主包 `@deepseek-ai/dsh-tools` 的**真实** `defineTool` 与 schema 编译器。
 *
 * 测试运行环境（CI / 评审机器）通常没有安装 DSH，也没有网络。本模块按以下优先级
 * 寻找宿主实现，任何一级都失败时不抛异常，而是返回 `{ ok: false, reason, searched }`，
 * 让调用方用 `t.skip()` 跳过「需要真实宿主」的断言，而不是把环境缺失败判成产品失败。
 *
 *   1. 环境变量 `DSH_TOOLS_DIR` 指定的目录（调试/离线镜像用）。
 *   2. 仓库自身 node_modules 中真实安装的 `@deepseek-ai/dsh-tools`（开发态最真实）。
 *   3. `test/helpers/vendor/@deepseek-ai/dsh-tools`（可选，若有人把整包 vendored 进来）。
 *   4. 已解包的宿主源码 `../_dsh_asar_ref/dsh-tools`（本仓库开发时的默认来源）。
 *
 * ## 为什么要 import map
 *
 * 已解包的 `dsh-tools` 没有 node_modules，且其包根 `lib/index.js` 会静态 import 整个
 * LLM 运行时闭包（dsh-typert-protocol + zod，解包后约 9MB）。契约校验只需要其中
 * `lib/types/schema.js` 的 `defineTool` / `parameterSchemaSpecToJsonSchema` /
 * `valueSchemaSpecToJsonSchema` 与 `lib/types/json-schema.js` 的 `assertSupportedJsonSchema`，
 * 这两个文件只依赖 `@deepseek-ai/dsh-llm` 的 `HarnessError` 和 `@deepseek-ai/dsh-util-values`。
 * 因此这里用 `node:module` 的 `registerHooks()`（Node >= 22.15 / 24 的同步 resolve hook）
 * 实现一个**最小 import map**：
 *
 *   - `@deepseek-ai/dsh-tools`      -> 选定的入口文件（包根或 lib/types/schema.js）
 *   - `@deepseek-ai/dsh-llm`        -> vendor 里的真实 `lib/types/error.js`（只取 HarnessError 子模块）
 *   - `@deepseek-ai/dsh-util-values`-> vendor 里的真实 `lib/index.js`
 *   - `@deepseek-ai/schemastery`    -> vendor 里的真实 `lib/index.mjs`
 *   - `@deepseek-ai/cosmokit`       -> vendor 里的真实 `lib/index.js`（schemastery 的唯一依赖）
 *
 * vendor 目录由 `test/helpers/vendor/README.md` 记录来源与版本，全部是 app.asar 里原样
 * 解包的上游代码，没有改写。
 *
 * ## 使用顺序（重要）
 *
 * 本模块必须在**任何** `lib/**` 模块被 import 之前加载并安装 import map，因为
 * `lib/tools/index.js` 会用裸说明符 `import { defineTool } from '@deepseek-ai/dsh-tools'`。
 * 测试里请先 `const host = await loadDshTools()`，再 `await import('.../lib/tools/index.js')`；
 * 不要用静态 import 提前触发 `lib/**` 的模块求值。
 *
 * @module test/helpers/dsh-tools
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { createRequire, registerHooks } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** 本 helpers 目录的绝对路径。 */
export const HELPERS_DIR = path.dirname(fileURLToPath(import.meta.url))
/** 插件仓库根目录的绝对路径。 */
export const REPO_ROOT = path.resolve(HELPERS_DIR, '..', '..')
/** 解包第三方依赖的目录（全部为 app.asar 原样解包）。 */
export const VENDOR_DIR = path.join(HELPERS_DIR, 'vendor')

/**
 * 已解包宿主源码根的默认位置：仓库同级的 `_dsh_asar_ref`。
 * 可用 `DSH_UNPACKED_ROOT` 覆盖（指向包含 `dsh-tools/` 的目录）。
 */
export const UNPACKED_ROOT = process.env.DSH_UNPACKED_ROOT
  ? path.resolve(process.env.DSH_UNPACKED_ROOT)
  : path.resolve(REPO_ROOT, '..', '_dsh_asar_ref')

/** 从包根加载时，可能因为缺少重型 peer 依赖而失败；失败后回退到的最小入口。 */
const SCHEMA_ENTRY = path.join('lib', 'types', 'schema.js')
const ROOT_ENTRY = path.join('lib', 'index.js')

/** 真实 defineTool 所需的最小 vendor 依赖映射（只有解包来源才需要）。 */
const VENDOR_IMPORT_TARGETS = Object.freeze({
  '@deepseek-ai/dsh-llm': path.join(VENDOR_DIR, '@deepseek-ai', 'dsh-llm', 'lib', 'types', 'error.js'),
  '@deepseek-ai/dsh-util-values': path.join(VENDOR_DIR, '@deepseek-ai', 'dsh-util-values', 'lib', 'index.js'),
  '@deepseek-ai/schemastery': path.join(VENDOR_DIR, '@deepseek-ai', 'schemastery', 'lib', 'index.mjs'),
  '@deepseek-ai/cosmokit': path.join(VENDOR_DIR, '@deepseek-ai', 'cosmokit', 'lib', 'index.js'),
})

/** 当前已安装的解析钩子（全局只装一次；映射表可被后续来源选择重写）。 */
const hookState = {
  installed: false,
  /** @type {Record<string, string>} specifier -> file URL */
  map: Object.create(null),
}

function isFile(filePath) {
  try {
    return statSync(filePath).isFile()
  } catch {
    return false
  }
}

function toUrl(filePath) {
  return pathToFileURL(filePath).href
}

/**
 * 构造某个目录下可用的 import 映射：总是先把 `@deepseek-ai/dsh-tools` 指到入口，
 * 解包来源再补上 vendor 里的最小依赖闭包。
 * @param {string} dshToolsEntry 入口文件的绝对路径
 * @param {boolean} withVendorDeps 是否加入 vendor 依赖映射
 * @returns {Record<string, string>}
 */
function buildImportMap(dshToolsEntry, withVendorDeps) {
  /** @type {Record<string, string>} */
  const map = Object.create(null)
  map['@deepseek-ai/dsh-tools'] = toUrl(dshToolsEntry)
  if (withVendorDeps) {
    for (const [specifier, filePath] of Object.entries(VENDOR_IMPORT_TARGETS)) {
      if (isFile(filePath)) map[specifier] = toUrl(filePath)
    }
  }
  return map
}

/** 安装（或更新）同步 resolve 钩子。多次调用是幂等的。 */
function installHooks() {
  if (hookState.installed) return
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const target = hookState.map[specifier]
      if (target !== undefined) {
        return { url: target, shortCircuit: true }
      }
      return nextResolve(specifier, context)
    },
  })
  hookState.installed = true
}

/**
 * 尝试 import 一个入口，成功返回模块命名空间，失败返回错误。
 * @param {string} entryPath 入口文件绝对路径
 */
async function tryImport(entryPath) {
  try {
    return { module: await import(toUrl(entryPath)), error: null }
  } catch (error) {
    return { module: null, error }
  }
}

/** 把任意错误压成一句可读文本。 */
function describeError(error) {
  if (error instanceof Error) return `${error.name}: ${error.message}`
  return String(error)
}

/** 列出候选来源：(kind, 包根目录, 是否真实安装)。 */
function candidateSources() {
  /** @type {Array<{kind: string, rootDir: string, installed: boolean}>} */
  const candidates = []

  if (process.env.DSH_TOOLS_DIR) {
    candidates.push({
      kind: 'env',
      rootDir: path.resolve(process.env.DSH_TOOLS_DIR),
      installed: false,
    })
  }

  // 真实安装的包：/node_modules/@deepseek-ai/dsh-tools（最真实、零映射）。
  try {
    const requireFromRepo = createRequire(path.join(REPO_ROOT, 'package.json'))
    let rootDir
    try {
      // 优先用 package.json 定位包根（不依赖 exports 是否暴露 main）。
      rootDir = path.dirname(requireFromRepo.resolve('@deepseek-ai/dsh-tools/package.json'))
    } catch {
      rootDir = path.resolve(path.dirname(requireFromRepo.resolve('@deepseek-ai/dsh-tools')), '..')
    }
    candidates.push({ kind: 'installed', rootDir, installed: true })
  } catch {
    // 未安装，继续找解包副本。
  }

  candidates.push({ kind: 'vendor', rootDir: path.join(VENDOR_DIR, '@deepseek-ai', 'dsh-tools'), installed: false })
  candidates.push({ kind: 'unpacked', rootDir: path.join(UNPACKED_ROOT, 'dsh-tools'), installed: false })
  return candidates
}

/** 读取包版本，失败返回 undefined。 */
function readPackageVersion(rootDir) {
  try {
    const parsed = JSON.parse(readFileSync(path.join(rootDir, 'package.json'), 'utf8'))
    return typeof parsed.version === 'string' ? parsed.version : undefined
  } catch {
    return undefined
  }
}

/**
 * 逐个候选来源尝试加载。第一优先是包根（与宿主真实加载路径一致）；
 * 包根因缺少重型 peer 依赖失败时，回退到 `lib/types/schema.js`。
 */
async function resolveHostModule() {
  const searched = []
  /** @type {Error | null} */
  let lastError = null

  for (const candidate of candidateSources()) {
    if (!existsSync(candidate.rootDir)) {
      searched.push({ kind: candidate.kind, rootDir: candidate.rootDir, status: 'missing' })
      continue
    }

    const rootEntry = path.join(candidate.rootDir, ROOT_ENTRY)
    const schemaEntry = path.join(candidate.rootDir, SCHEMA_ENTRY)
    if (!isFile(rootEntry) && !isFile(schemaEntry)) {
      searched.push({ kind: candidate.kind, rootDir: candidate.rootDir, status: 'no-entry' })
      continue
    }

    installHooks()
    const withVendorDeps = !candidate.installed
    const attempts = []
    if (isFile(rootEntry)) attempts.push({ entry: rootEntry, kind: 'package-root' })
    if (isFile(schemaEntry) && schemaEntry !== rootEntry) attempts.push({ entry: schemaEntry, kind: 'schema-module' })

    let rootError = null
    for (const attempt of attempts) {
      hookState.map = buildImportMap(attempt.entry, withVendorDeps)
      const result = await tryImport(attempt.entry)
      if (result.module) {
        if (typeof result.module.defineTool !== 'function') {
          searched.push({
            kind: candidate.kind,
            rootDir: candidate.rootDir,
            status: 'missing-defineTool',
            entry: attempt.entry,
          })
          continue
        }
        const note = attempt.kind === 'schema-module' && rootError
          ? `包根不可用，已回退 lib/types/schema.js（根因：${describeError(rootError)}）`
          : undefined
        return {
          ok: true,
          module: result.module,
          source: {
            kind: candidate.kind,
            rootDir: candidate.rootDir,
            entryPath: attempt.entry,
            entryUrl: toUrl(attempt.entry),
            entryKind: attempt.kind,
            packageVersion: readPackageVersion(candidate.rootDir),
            installed: candidate.installed,
          },
          importMap: { ...hookState.map },
          notes: note ? [note] : [],
          searched,
        }
      }
      if (attempt.kind === 'package-root') {
        rootError = result.error
        lastError = result.error
      } else {
        lastError = result.error
      }
      searched.push({
        kind: candidate.kind,
        rootDir: candidate.rootDir,
        status: 'import-failed',
        entry: attempt.entry,
        error: describeError(result.error),
      })
    }
  }

  return {
    ok: false,
    reason: lastError
      ? `找不到可用的 @deepseek-ai/dsh-tools 实现：${describeError(lastError)}`
      : '找不到可用的 @deepseek-ai/dsh-tools 实现（未安装、未 vendored、也未找到解包副本）',
    searched,
  }
}

/** @type {Promise<object> | undefined} */
let cachedHost

/**
 * 加载真实宿主 `defineTool`（带缓存）。永不 reject：环境缺失时返回 `{ ok: false }`。
 *
 * 成功时返回：
 * ```js
 * {
 *   ok: true,
 *   defineTool, parameterSchemaSpecToJsonSchema, valueSchemaSpecToJsonSchema,
 *   assertSupportedJsonSchema, assertObjectJsonSchema, validateJsonSchemaValue,
 *   JsonSchemaError, ToolArgsError, validateArgs,
 *   source: { kind, rootDir, entryPath, entryUrl, entryKind, packageVersion, installed },
 *   importMap, notes, searched,
 * }
 * ```
 * @returns {Promise<object>}
 */
export function loadDshTools() {
  if (!cachedHost) {
    cachedHost = (async () => {
      const resolved = await resolveHostModule()
      if (!resolved.ok) return resolved
      let mod = resolved.module
      // `lib/types/schema.js` 只重新导出 defineTool 系列；raw schema 断言在兄弟模块
      // `lib/types/json-schema.js`。schema.js 已经 import 了它，这里拿到的是同一个模块实例。
      if (typeof mod.assertSupportedJsonSchema !== 'function') {
        const sibling = path.join(path.dirname(resolved.source.entryPath), 'json-schema.js')
        if (isFile(sibling)) {
          try {
            mod = { ...mod, ...(await import(toUrl(sibling))) }
          } catch {
            // 保持原模块；缺少断言能力时相关测试会 skip。
          }
        }
      }
      return {
        ...resolved,
        defineTool: mod.defineTool,
        parameterSchemaSpecToJsonSchema: mod.parameterSchemaSpecToJsonSchema,
        valueSchemaSpecToJsonSchema: mod.valueSchemaSpecToJsonSchema,
        assertSupportedJsonSchema: mod.assertSupportedJsonSchema,
        assertObjectJsonSchema: mod.assertObjectJsonSchema,
        validateJsonSchemaValue: mod.validateJsonSchemaValue,
        assertNever: mod.assertNever,
        JsonSchemaError: mod.JsonSchemaError,
        ToolArgsError: mod.ToolArgsError,
        validateArgs: mod.validateArgs,
      }
    })()
  }
  return cachedHost
}

/**
 * 供测试使用：环境缺失时输出一行可读 skip 原因。
 * @param {object} host loadDshTools() 结果
 * @returns {string}
 */
export function describeUnavailable(host) {
  const lines = [`真实宿主 @deepseek-ai/dsh-tools 不可用：${host.reason}`]
  for (const item of host.searched ?? []) {
    lines.push(`  尝试 ${item.kind}: ${item.rootDir} -> ${item.status}${item.error ? ` (${item.error})` : ''}`)
  }
  if (host.searched?.length) {
    lines.push('  可用环境变量 DSH_TOOLS_DIR / DSH_UNPACKED_ROOT 指定解包源码目录。')
  }
  return lines.join('\n')
}

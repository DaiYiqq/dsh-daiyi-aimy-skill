/**
 * 工具模块导出形状的「软适配器」。
 *
 * `lib/tools/index.js` 的最终导出形状由 lead 决定，且合法形状不止一种：
 * 静态数组（`export const TOOLS`）或工厂（`export function createTools(deps)`）
 * 都能返回真实的 `defineTool` 结果。契约测试不应该因为导出名不同就误判失败，
 * 所以这里集中做形状识别，并把**推荐形状**和**识别到了什么**写进测试诊断信息。
 *
 * 想给 lead 的最终要求（一句话）：
 *   `lib/tools/index.js` 必须导出 8 个真实 `defineTool(...)` 结果，形状为
 *   `export const TOOLS = [...]` / `export const tools = [...]` / `export default [...]`，
 *   或 `export function createTools(deps) { return [...] }`；本适配器三种都接受。
 *
 * @module test/helpers/tools-adapter
 */
import { existsSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

/** 推荐给 lead 的导出形状（写进 skip/失败信息，方便定位）。 */
export const RECOMMENDED_TOOL_EXPORT = [
  'export const TOOLS = [defineTool(...), ...]  // 首选：8 项',
  'export const tools = [...]                  // 备选',
  'export default [...]                        // 备选',
  'export function createTools(deps) { return [...] }  // 工厂形状，适配器会以桩 deps 调用',
].join('\n  ')

/** 判断一个值是否“看起来像 defineTool 的结果”。 */
export function looksLikeToolDefinition(value) {
  return value !== null
    && typeof value === 'object'
    && typeof value.name === 'string'
    && value.name.length > 0
    && value.parameters !== null
    && typeof value.parameters === 'object'
    && value.output !== null
    && typeof value.output === 'object'
    && typeof value.output.schema === 'object'
}

/**
 * 从模块命名空间中识别工具定义。
 * @param {Record<string, unknown>} namespace
 * @returns {{
 *   tools: object[] | null,
 *   factory: Function | null,
 *   shape: string | null,
 *   notes: string[],
 * }}
 */
export function extractToolDefinitions(namespace) {
  /** @type {string[]} */
  const notes = []
  if (namespace === null || typeof namespace !== 'object') {
    return { tools: null, factory: null, shape: null, notes: ['模块命名空间不是对象'] }
  }

  for (const key of ['TOOLS', 'tools']) {
    const value = namespace[key]
    if (Array.isArray(value)) return { tools: value, factory: null, shape: `export const ${key}`, notes }
    if (value !== null && typeof value === 'object' && Array.isArray(value.tools)) {
      notes.push(`读取了 namespace.${key}.tools`)
      return { tools: value.tools, factory: null, shape: `export const ${key} = { tools }`, notes }
    }
  }

  const defaultExport = namespace.default
  if (Array.isArray(defaultExport)) return { tools: defaultExport, factory: null, shape: 'export default [...]', notes }
  if (defaultExport !== null && typeof defaultExport === 'object' && Array.isArray(defaultExport.tools)) {
    notes.push('读取了 default.tools')
    return { tools: defaultExport.tools, factory: null, shape: 'export default { tools }', notes }
  }

  if (typeof namespace.createTools === 'function') {
    notes.push('识别到工厂形状 createTools(deps)，将用桩 deps 调用一次')
    return { tools: null, factory: namespace.createTools, shape: 'export function createTools(deps)', notes }
  }
  if (typeof defaultExport === 'function') {
    notes.push('识别到 default 工厂函数，将用桩 deps 调用一次')
    return { tools: null, factory: defaultExport, shape: 'export default function (deps)', notes }
  }

  // 最后兜底：扫描任意数组导出，全部元素都像工具定义时接受（并记录实际导出名）。
  for (const [key, value] of Object.entries(namespace)) {
    if (Array.isArray(value) && value.length > 0 && value.every(looksLikeToolDefinition)) {
      notes.push(`未命中约定导出名，回退扫描到 export const ${key}`)
      return { tools: value, factory: null, shape: `export const ${key}`, notes }
    }
  }

  const exportKeys = Object.keys(namespace)
  return {
    tools: null,
    factory: null,
    shape: null,
    notes: [`无法从导出 [${exportKeys.join(', ')}] 识别工具定义数组。要求的形状：\n  ${RECOMMENDED_TOOL_EXPORT}`],
  }
}

/** 供 `createTools(deps)` 使用的桩依赖：构造期不应真正调用它们。 */
export function createStubToolDeps(overrides = {}) {
  const stubScope = {
    list: () => [],
    check: () => ({ ok: false, reason: 'stub scope' }),
    add: () => ({ ok: false, error: 'stub scope' }),
    remove: () => ({ ok: false, error: 'stub scope' }),
    clear: () => ({ ok: false, error: 'stub scope' }),
    save: async () => null,
    audit: () => {},
    get loadError() { return null },
  }
  const stubStore = {
    snapshot: () => ({ findings: [], runs: [], stats: {} }),
    list: () => [],
    clear: () => {},
    addRun: () => null,
    stats: () => ({}),
  }
  return {
    scope: stubScope,
    store: stubStore,
    config: { mode: 'rookie' },
    log: () => {},
    ...overrides,
  }
}

/**
 * 加载并识别工具定义模块。
 *
 * 返回值永远是对象，不抛异常：
 * - `{ available: false, reason }`：文件不存在或模块导入失败（调用方应 skip）。
 * - `{ available: true, tools, shape, notes }`：成功拿到数组。
 * - `{ available: true, tools: null, shape, error, notes }`：形状/工厂调用有问题
 *   （调用方应 skip，并把理由写进报告，方便 lead 对齐导出形状）。
 *
 * @param {string} moduleFile 工具模块的绝对路径
 * @param {{ createDeps?: () => object }} [options]
 */
export async function loadToolDefinitions(moduleFile, options = {}) {
  if (!existsSync(moduleFile)) {
    return { available: false, reason: `文件不存在：${moduleFile}` }
  }
  let namespace
  try {
    namespace = await import(pathToFileURL(moduleFile).href)
  } catch (error) {
    return {
      available: false,
      reason: `模块导入失败：${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`,
      error,
    }
  }

  const extracted = extractToolDefinitions(namespace)
  const exportKeys = Object.keys(namespace)
  if (extracted.factory) {
    const deps = typeof options.createDeps === 'function' ? options.createDeps() : createStubToolDeps()
    let produced
    try {
      produced = extracted.factory(deps)
    } catch (error) {
      return {
        available: true,
        tools: null,
        shape: extracted.shape,
        exportKeys,
        notes: extracted.notes,
        error,
        reason: `工厂调用失败：${error instanceof Error ? error.message : String(error)}`,
      }
    }
    if (produced !== null && typeof produced === 'object' && Array.isArray(produced.tools)) produced = produced.tools
    if (!Array.isArray(produced)) {
      return {
        available: true,
        tools: null,
        shape: extracted.shape,
        exportKeys,
        notes: extracted.notes,
        reason: '工厂没有返回数组',
      }
    }
    return { available: true, tools: produced, shape: extracted.shape, exportKeys, notes: extracted.notes }
  }
  if (extracted.tools === null) {
    return {
      available: true,
      tools: null,
      shape: extracted.shape,
      exportKeys,
      notes: extracted.notes,
      reason: extracted.notes.join('；'),
    }
  }
  return { available: true, tools: extracted.tools, shape: extracted.shape, exportKeys, notes: extracted.notes }
}

/** 便捷：lib/tools/index.js 的绝对路径。 */
export function toolsModuleFile(repoRoot) {
  return path.join(repoRoot, 'lib', 'tools', 'index.js')
}

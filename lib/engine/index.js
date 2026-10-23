/**
 * 检测引擎目录与调度。
 *
 * 设计取舍：
 * - 引擎模块**按需动态加载**，单个模块语法错误或缺失只会让那项检查被跳过，
 *   不会让整个插件加载失败（插件注册必须永不抛错）。
 * - 目录（CHECK_CATALOG）是工具参数枚举的唯一来源；模块的 meta.id 在加载时校验，
 *   不一致会记录 warning 并以目录为准。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/index
 */

/**
 * 检查项目录。
 * @type {Array<{ check: string, moduleId: string, title: string, file: string, minMode: 'rookie' | 'veteran' }>}
 */
export const CHECK_CATALOG = [
  { check: 'sqli', moduleId: 'sqli', title: 'SQL 注入', file: './sqli.js', minMode: 'rookie' },
  { check: 'xss', moduleId: 'xss', title: '跨站脚本', file: './xss.js', minMode: 'rookie' },
  { check: 'cmdi', moduleId: 'cmdi', title: '命令注入', file: './cmdi.js', minMode: 'rookie' },
  { check: 'ssti', moduleId: 'ssti', title: '模板注入', file: './ssti.js', minMode: 'rookie' },
  { check: 'ssrf', moduleId: 'ssrf', title: '服务端请求伪造', file: './ssrf.js', minMode: 'rookie' },
  { check: 'nosqli', moduleId: 'nosqli', title: 'NoSQL 注入', file: './nosqli.js', minMode: 'rookie' },
  { check: 'lfi', moduleId: 'lfi', title: '路径遍历/文件包含', file: './lfi.js', minMode: 'rookie' },
  { check: 'cors', moduleId: 'cors', title: '跨域配置', file: './cors.js', minMode: 'rookie' },
  { check: 'jwt', moduleId: 'jwt', title: 'JWT 令牌检测', file: './jwt.js', minMode: 'rookie' },
  { check: 'graphql', moduleId: 'graphql', title: 'GraphQL 暴露面', file: './graphql.js', minMode: 'rookie' },
  { check: 'proto', moduleId: 'proto-pollution', title: '原型污染', file: './proto-pollution.js', minMode: 'rookie' },
  { check: 'headers', moduleId: 'headers', title: '安全响应头', file: './headers.js', minMode: 'rookie' },
]

/** @type {Map<string, { module: any, meta: any } | { error: string, reason: string }>} */
const moduleCache = new Map()

/**
 * 供工具参数 enum 使用的同步目录。
 * @returns {Array<{ id: string, title: string }>}
 */
export function listChecks() {
  return CHECK_CATALOG.map((entry) => ({ id: entry.check, title: entry.title }))
}

/**
 * 加载（并缓存）一个引擎模块。
 * @param {{ check: string, moduleId: string, file: string }} entry
 * @param {(level: string, message: string) => void} [log]
 * @returns {Promise<{ module: any, meta: any } | { error: string, reason: string }>}
 */
async function loadModule(entry, log) {
  const cached = moduleCache.get(entry.check)
  if (cached !== undefined) return cached
  try {
    const module = await import(new URL(entry.file, import.meta.url).href)
    if (typeof module.run !== 'function') {
      const failed = { error: 'MISSING_RUN', reason: `引擎模块 ${entry.file} 未导出 run(ctx)` }
      moduleCache.set(entry.check, failed)
      log?.('warn', failed.reason)
      return failed
    }
    const meta = module.meta ?? { id: entry.moduleId, title: entry.title }
    if (meta.id !== undefined && meta.id !== entry.moduleId) {
      log?.('warn', `引擎模块 ${entry.file} 的 meta.id="${meta.id}" 与目录登记 "${entry.moduleId}" 不一致，以目录为准`)
    }
    const loaded = { module, meta }
    moduleCache.set(entry.check, loaded)
    return loaded
  } catch (error) {
    const failed = {
      error: 'LOAD_FAILED',
      reason: `加载引擎模块 ${entry.file} 失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`,
    }
    moduleCache.set(entry.check, failed)
    log?.('warn', failed.reason)
    return failed
  }
}

/**
 * 依次执行选中的检查，汇总 findings。
 *
 * 模块之间串行执行（一次工具调用内已经很占网络，串行更可控、日志更可读）；
 * 单个模块抛错不会中断其余检查。
 *
 * @param {object} ctx ProbeContext
 * @param {string[]} checks 检查 id 列表（对应 CHECK_CATALOG.check）
 * @param {{ onSkip?: (check: string, reason: string) => void, log?: (level: string, message: string) => void }} [options]
 * @returns {Promise<unknown[]>} Finding[]
 */
export async function runChecks(ctx, checks, options = {}) {
  const wanted = Array.isArray(checks) && checks.length > 0 ? checks : CHECK_CATALOG.map((entry) => entry.check)
  const log = options.log
  /** @type {unknown[]} */
  const findings = []
  for (const check of wanted) {
    if (ctx.signal?.aborted === true) break
    const entry = CHECK_CATALOG.find((item) => item.check === check)
    if (entry === undefined) {
      options.onSkip?.(check, '未知检查项')
      continue
    }
    if (entry.minMode === 'veteran' && ctx.mode !== 'veteran') {
      options.onSkip?.(check, '该检查只在老鸟模式启用')
      continue
    }
    const loaded = await loadModule(entry, log)
    if ('error' in loaded) {
      options.onSkip?.(check, loaded.reason)
      continue
    }
    try {
      const result = await loaded.module.run(ctx)
      if (Array.isArray(result) && result.length > 0) findings.push(...result)
    } catch (error) {
      if (ctx.signal?.aborted === true) break
      const reason = `检查 ${check} 执行失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`
      log?.('warn', reason)
      options.onSkip?.(check, reason)
    }
  }
  return findings
}

/**
 * 同源爬取（供 aimy_crawl / aimy_web_scan 使用）。
 * @param {object} ctx
 * @param {{ maxPages?: number, maxDepth?: number, includeForms?: boolean, includeJs?: boolean }} [options]
 */
export async function crawl(ctx, options = {}) {
  const module = await import(new URL('./crawler.js', import.meta.url).href)
  if (typeof module.crawl !== 'function') throw new Error('引擎 crawler 模块未导出 crawl(ctx, options)')
  return module.crawl(ctx, options)
}

/**
 * 参数挖掘（供后续扩展；当前 web_scan 优先用爬取结果）。
 * @param {object} ctx
 * @param {object} [options]
 */
export async function mineParams(ctx, options = {}) {
  const module = await import(new URL('./param-miner.js', import.meta.url).href)
  if (typeof module.mineParams !== 'function') throw new Error('引擎 param-miner 模块未导出 mineParams(ctx, options)')
  return module.mineParams(ctx, options)
}

/**
 * 技术指纹（供 aimy_recon 使用；失败返回空数组而不是抛错）。
 * @param {object} ctx
 * @returns {Promise<Array<{ name: string, confidence: string, evidence: string }>>}
 */
export async function fingerprint(ctx) {
  try {
    const module = await import(new URL('./tech-fingerprint.js', import.meta.url).href)
    if (typeof module.fingerprint === 'function') return await module.fingerprint(ctx)
    if (typeof module.run === 'function') return []
  } catch {
    return []
  }
  return []
}

/**
 * 测试/诊断用：清空模块缓存。
 */
export function resetModuleCache() {
  moduleCache.clear()
}

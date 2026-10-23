/**
 * 隐藏参数挖掘（参数名枚举 + 响应差异判断）。
 *
 * 对外接口：
 * - `mineParams(ctx, options)` → `{ params, tested }`
 *   options: `{ candidates?: string[], fromCrawl?: boolean }`
 * - `run(ctx)` → Finding[]（把"接受但未被使用"的候选参数汇总成 info 级提示，可为空）
 *
 * 检测原理：
 * 1. 取目标基线（状态码 + 响应长度）；
 * 2. 依次给候选参数名附加确定性 marker 值发 GET 请求；
 * 3. 状态码变化、长度差 >25B 或 marker 被反射 → 认为该参数"被应用接受"；
 *    若与基线同为 404 则不记录（软 404 噪声过滤）；
 * 4. `fromCrawl: true` 时先做一次小规模爬取，把已出现参数排除在候选外，
 *    并复用爬取到的同源端点。
 *
 * 局限：
 * - 差异可能来自缓存/随机内容/时间戳，因此输出只作为**线索**（info + low），
 *   不作为漏洞结论；
 * - 只测 GET 查询参数（POST 字段需要表单上下文，交由工具层决定）；
 * - 参数名候选有限（rookie 10 / veteran 24），冷门命名会漏。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/param-miner
 */

import {
  createSession, queryParamNames, setQueryParam, isHttpResponse, makeFinding,
  stableSortFindings, handleModuleError, oneLine, readyForMode, asString,
} from './util.js'
import { COMMON_GET_PARAMS, MARKER } from './payloads.js'
import { crawl } from './crawler.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'param-miner',
  title: '隐藏参数挖掘',
  kinds: ['param-miner', 'recon'],
  cwe: 'CWE-200',
  defaultSeverity: 'info',
  minMode: 'rookie',
}

/** 每个模式最多测试的候选参数（还会被剩余请求预算钳制）。 */
const CANDIDATE_LIMIT = { rookie: 10, veteran: 24 }
/** 长度差阈值（字节）。 */
const LENGTH_DELTA = 25

/**
 * 挖掘候选参数。
 * @param {object} ctx ProbeContext
 * @param {{ candidates?: string[], fromCrawl?: boolean }} [options]
 * @returns {Promise<{ params: Array<{ name: string, location: string, sample: string }>, tested: number }>}
 */
export async function mineParams(ctx, options = {}) {
  const session = createSession(ctx)
  const targetUrl = String(ctx?.target?.url ?? '')
  const result = { params: /** @type {Array<{ name: string, location: string, sample: string }>} */ ([]), tested: 0 }
  if (targetUrl.length === 0 || session.remaining <= 0) return result

  /** @type {Set<string>} */
  const known = new Set(queryParamNames(targetUrl))
  const params = Array.isArray(ctx?.params) ? ctx.params : []
  for (const spec of params) {
    if (typeof spec?.name === 'string') known.add(spec.name)
  }

  let crawlRequests = 0
  if (options.fromCrawl === true) {
    try {
      const crawled = await crawl(ctx, { maxPages: 3, maxDepth: 1, includeForms: true, includeJs: true })
      crawlRequests = crawled.requests
      for (const param of crawled.params) known.add(param.name)
      for (const pageUrl of crawled.urls) {
        for (const name of queryParamNames(pageUrl)) known.add(name)
      }
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }

  const maxRequests = Number.isFinite(ctx?.limits?.maxRequests) ? Math.trunc(Number(ctx.limits.maxRequests)) : 40
  // 基线 1 次；爬取已消耗的请求也要计入模块总预算。
  const probeBudget = Math.max(0, maxRequests - crawlRequests - 1)
  const modeLimit = CANDIDATE_LIMIT[ctx?.mode === 'veteran' ? 'veteran' : 'rookie'] ?? 10
  const candidateLimit = Math.min(modeLimit, probeBudget)

  let pool
  if (Array.isArray(options.candidates) && options.candidates.length > 0) {
    pool = options.candidates.filter((name) => typeof name === 'string' && name.length > 0)
  } else {
    pool = COMMON_GET_PARAMS
  }
  const candidates = pool
    .filter((name) => !known.has(name))
    .filter((name, index, list) => list.indexOf(name) === index)
    .slice(0, Math.max(0, candidateLimit))

  const baseline = await session.probe(targetUrl, { method: 'GET' })
  if (!baseline || !isHttpResponse(baseline)) return result

  for (const name of candidates) {
    if (session.aborted || session.remaining <= 0) break
    const testValue = `${MARKER}_${name}`
    const response = await session.probe(setQueryParam(targetUrl, name, testValue), { method: 'GET' })
    if (!response) break
    result.tested += 1
    if (!isHttpResponse(response)) continue
    if (response.status === 404 && baseline.status === 404) continue
    const lengthDelta = Math.abs(response.body.length - baseline.body.length)
    const reflected = response.body.includes(testValue)
    const accepted = response.status !== baseline.status || lengthDelta > LENGTH_DELTA || reflected
    if (!accepted) continue
    result.params.push({ name, location: 'query', sample: '1' })
  }

  result.params.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
  return result
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  /** @type {object[]} */
  const findings = []
  try {
    const mined = await mineParams(ctx, { fromCrawl: true })
    if (mined.params.length === 0) return []
    const names = mined.params.map((param) => param.name)
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'param-miner',
      title: '发现疑似隐藏参数',
      severity: 'info',
      confidence: 'low',
      url: String(ctx?.target?.url ?? ''),
      evidence:
        `在 ${mined.tested} 个候选参数中，${names.length} 个使响应与基线不同（状态码/长度/反射）：` +
        `${oneLine(names.join(', '), 300)}。差异也可能来自缓存或动态内容，仅作线索，需人工确认。`,
      cwe: meta.cwe,
      remediation: '核对应用是否真的处理这些参数；未使用的参数不应影响响应。',
    }))
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

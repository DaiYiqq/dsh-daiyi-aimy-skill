/**
 * SQL 注入检测（错误型 / 布尔型 / 时间型）。
 *
 * 检测原理：
 * 1. 先对每个参数发一次**基线请求**（使用给定 sample），记录状态码、长度与响应体；
 * 2. 错误型：注入引号等破坏语法的字符，命中 ≥2 个**不同的数据库错误特征**
 *    （且基线中不存在）才判定，避免把普通错误页当注入；
 * 3. 布尔型：成对发送真/假条件，要求"真值响应更接近基线、假值明显偏离"
 *    （长度差 ≥40B 或状态码翻转），单纯回显长度变化不算；
 * 4. 时间型（仅 veteran）：SLEEP(2) 注入后与基线时延比较，且**第二次复现**才判定。
 *
 * 局限：
 * - 只能发现"有明确反馈"的注入点；完全无回显且无时延的盲注需要 OOB/更复杂技术，
 *   本模块按契约不做 OOB；
 * - WAF/统一错误页会掩盖特征，导致漏报（宁可漏报，不臆造）；
 * - 时间型受网络抖动影响，阈值取 1200ms 且两次复现，仍可能被高延迟网络干扰。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/sqli
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue,
  isHttpResponse, similarity, matchSignatures, makeFinding, stableSortFindings,
  handleModuleError, describeResponse, oneLine, readyForMode,
} from './util.js'
import { forMode, SQL_ERROR_QUERIES, SQL_BOOLEAN_PAIRS, SQL_TIME_PROBES, SQL_ERROR_SIGNATURES } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'sqli',
  title: 'SQL 注入检测',
  kinds: ['sqli', 'sql-injection'],
  cwe: 'CWE-89',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/** 布尔判定：真值响应与基线相似度至少要比假值高这么多。 */
const BOOLEAN_SIMILARITY_MARGIN = 0.08
/** 布尔判定：假值响应长度差阈值（字节）。 */
const BOOLEAN_LENGTH_DELTA = 40
/** 时间判定：相对基线的额外时延阈值（毫秒）。 */
const TIME_DELTA_MS = 1200

/**
 * 错误型检测：至少 2 个不同数据库错误特征，且基线里没有。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {ReturnType<typeof sendParamBaseline>} baseline
 * @returns {Promise<object | null>}
 */
async function checkErrorBased(session, spec, baseline) {
  const payloads = forMode(SQL_ERROR_QUERIES, session.ctx.mode)
  const baselineIds = new Set(matchSignatures(baseline.body, SQL_ERROR_SIGNATURES).map((hit) => hit.id))
  /** @type {Map<string, { sig: object, match: string, payload: string }>} */
  const collected = new Map()

  for (const payload of payloads) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, payload)
    if (!response) break
    if (!isHttpResponse(response)) continue
    for (const hit of matchSignatures(response.body, SQL_ERROR_SIGNATURES)) {
      if (baselineIds.has(hit.id) || collected.has(hit.id)) continue
      const sig = SQL_ERROR_SIGNATURES.find((candidate) => candidate.id === hit.id)
      if (sig === undefined) continue
      collected.set(hit.id, { sig, match: hit.match, payload })
    }
  }

  if (collected.size < 2) return null
  const details = [...collected.values()]
    .slice(0, 4)
    .map((entry) => `${entry.sig.id}(${entry.sig.db})="${oneLine(entry.match, 60)}"`)
    .join('；')
  const firstPayload = [...collected.values()][0]?.payload ?? payloads[0] ?? ''
  return makeFinding({
    module: meta.id,
    checkId: 'sqli-error',
    title: '错误型 SQL 注入',
    severity: 'high',
    confidence: 'high',
    url: String(session.ctx?.target?.url ?? ''),
    param: spec.name,
    payload: firstPayload,
    evidence: `基线 ${describeResponse(baseline)}；参数 ${spec.name} 注入后命中 ${collected.size} 个不同数据库错误特征：${details}。`,
    cwe: meta.cwe,
    remediation: '使用参数化查询/预编译语句，禁止把用户输入拼接进 SQL；统一错误页避免泄露数据库细节。',
  })
}

/**
 * 布尔型检测：真值接近基线、假值明显偏离。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {ReturnType<typeof sendParamBaseline>} baseline
 * @returns {Promise<object | null>}
 */
async function checkBooleanBased(session, spec, baseline) {
  const pairs = forMode(SQL_BOOLEAN_PAIRS, session.ctx.mode)
  for (const pair of pairs) {
    if (session.aborted || session.remaining < 2) break
    if (!Array.isArray(pair) || pair.length !== 2) continue
    const trueResponse = await sendParamValue(session, spec, pair[0])
    if (!trueResponse) break
    const falseResponse = await sendParamValue(session, spec, pair[1])
    if (!falseResponse) break
    if (!isHttpResponse(trueResponse) || !isHttpResponse(falseResponse)) continue

    const lengthDelta = Math.abs(trueResponse.body.length - falseResponse.body.length)
    const trueSimilarity = similarity(baseline.body, trueResponse.body)
    const falseSimilarity = similarity(baseline.body, falseResponse.body)
    const statusFlip = trueResponse.status !== falseResponse.status
    const trueCloser = trueSimilarity - falseSimilarity >= BOOLEAN_SIMILARITY_MARGIN
    const statusEvidence = statusFlip && trueSimilarity >= 0.9 && falseSimilarity < 0.9

    if ((lengthDelta >= BOOLEAN_LENGTH_DELTA && trueCloser) || statusEvidence) {
      return makeFinding({
        module: meta.id,
        checkId: 'sqli-boolean',
        title: '布尔型 SQL 注入',
        severity: 'high',
        confidence: 'medium',
        url: String(session.ctx?.target?.url ?? ''),
        param: spec.name,
        payload: pair[0],
        evidence:
          `基线 ${describeResponse(baseline)}；真值 ${pair[0]} → ${describeResponse(trueResponse)}（相似度 ${trueSimilarity.toFixed(2)}）；` +
          `假值 ${pair[1]} → ${describeResponse(falseResponse)}（相似度 ${falseSimilarity.toFixed(2)}）；长度差 ${lengthDelta}B，状态码翻转=${statusFlip}。`,
        cwe: meta.cwe,
        remediation: '使用参数化查询/预编译语句，并对查询结果做统一处理，避免真/假条件造成可观测差异。',
      })
    }
  }
  return null
}

/**
 * 时间型检测（仅 veteran）：相对基线时延 + 二次复现。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {ReturnType<typeof sendParamBaseline>} baseline
 * @returns {Promise<object | null>}
 */
async function checkTimeBased(session, spec, baseline) {
  const probes = forMode(SQL_TIME_PROBES, session.ctx.mode)
  const baselineElapsed = baseline.elapsedMs
  for (const probe of probes) {
    if (session.aborted || session.remaining < 2) break
    const first = await sendParamValue(session, spec, probe.value)
    if (!first) break
    const firstDelta = first.elapsedMs - baselineElapsed
    if (!isHttpResponse(first) || firstDelta < TIME_DELTA_MS) continue
    const second = await sendParamValue(session, spec, probe.value)
    if (!second) break
    const secondDelta = second.elapsedMs - baselineElapsed
    if (!isHttpResponse(second) || secondDelta < TIME_DELTA_MS) continue
    return makeFinding({
      module: meta.id,
      checkId: 'sqli-time',
      title: '时间型盲注 SQL 注入',
      severity: 'high',
      confidence: 'medium',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: probe.value,
      evidence:
        `参数 ${spec.name} 基线时延 ${Math.round(baselineElapsed)}ms；` +
        `${probe.dialect} SLEEP 载荷两次请求耗时 ${Math.round(first.elapsedMs)}ms / ${Math.round(second.elapsedMs)}ms，` +
        `相对基线 +${Math.round(firstDelta)}ms / +${Math.round(secondDelta)}ms（阈值 ${TIME_DELTA_MS}ms，已复现）。`,
      cwe: meta.cwe,
      remediation: '使用参数化查询/预编译语句；对数据库查询设置超时并监控异常长查询。',
      confirmed: true,
    })
  }
  return null
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  const session = createSession(ctx)
  /** @type {object[]} */
  const findings = []
  const params = pickParams(ctx, 2)

  for (const spec of params) {
    if (session.aborted) break
    try {
      const baseline = await sendParamBaseline(session, spec)
      if (!baseline) break
      if (!isHttpResponse(baseline)) continue

      let finding = await checkErrorBased(session, spec, baseline)
      if (finding === null && !session.aborted) finding = await checkBooleanBased(session, spec, baseline)
      if (finding === null && !session.aborted && session.ctx.mode === 'veteran') {
        finding = await checkTimeBased(session, spec, baseline)
      }
      if (finding !== null) findings.push(finding)
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }

  return stableSortFindings(findings)
}

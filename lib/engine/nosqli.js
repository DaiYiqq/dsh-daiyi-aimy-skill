/**
 * NoSQL 注入检测（错误型 / 布尔型 / JSON 操作符注入）。
 *
 * 检测原理：
 * 1. 取基线后注入 MongoDB 风格表达式（`' || '1'=='1` 等），
 *    命中 **MongoDB/BSON 专有错误特征**（基线中不存在）才判定错误型；
 * 2. 布尔型对比真/假表达式的响应，要求"真值更接近基线、假值明显偏离"；
 * 3. 仅当参数位于 JSON body 时，veteran 模式追加一次只读操作符注入
 *    （`{"$ne": ""}`），观察是否从 4xx 变为 2xx 或出现明显数据扩张。
 *
 * 局限：
 * - 只覆盖 MongoDB 风格语法，不覆盖 Redis/Cassandra 等其他数据存储；
 * - JSON 操作符注入只做**只读**查询探测，不写入/不投毒；
 * - 应用层统一错误页会掩藏特征，导致漏报。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/nosqli
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue, isHttpResponse,
  matchSignatures, similarity, makeFinding, stableSortFindings, handleModuleError,
  describeResponse, oneLine, readyForMode,
} from './util.js'
import {
  forMode, NOSQLI_BOOLEAN_PAIRS, NOSQLI_ERROR_SIGNATURES, NOSQLI_JSON_PROBES,
} from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'nosqli',
  title: 'NoSQL 注入检测',
  kinds: ['nosqli', 'nosql-injection'],
  cwe: 'CWE-943',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

const BOOLEAN_SIMILARITY_MARGIN = 0.08
const BOOLEAN_LENGTH_DELTA = 30

/**
 * 错误型 + 布尔型检测。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {object} baseline
 * @returns {Promise<object | null>}
 */
async function checkExpressions(session, spec, baseline) {
  const pairs = forMode(NOSQLI_BOOLEAN_PAIRS, session.ctx.mode)
  /** @type {Map<string, { match: string, payload: string }>} */
  const errorHits = new Map()

  for (const pair of pairs) {
    if (session.aborted || session.remaining < 2) break
    if (!Array.isArray(pair) || pair.length !== 2) continue
    const trueResponse = await sendParamValue(session, spec, pair[0])
    if (!trueResponse) break
    const falseResponse = await sendParamValue(session, spec, pair[1])
    if (!falseResponse) break
    if (!isHttpResponse(trueResponse) || !isHttpResponse(falseResponse)) continue

    const baselineIds = new Set(matchSignatures(baseline.body, NOSQLI_ERROR_SIGNATURES).map((hit) => hit.id))
    for (const hit of matchSignatures(trueResponse.body, NOSQLI_ERROR_SIGNATURES)) {
      if (baselineIds.has(hit.id) || errorHits.has(hit.id)) continue
      errorHits.set(hit.id, { match: hit.match, payload: pair[0] })
    }
    if (errorHits.size > 0) continue

    const lengthDelta = Math.abs(trueResponse.body.length - falseResponse.body.length)
    const trueSimilarity = similarity(baseline.body, trueResponse.body)
    const falseSimilarity = similarity(baseline.body, falseResponse.body)
    const statusFlip = trueResponse.status !== falseResponse.status
    if (
      (lengthDelta >= BOOLEAN_LENGTH_DELTA && trueSimilarity - falseSimilarity >= BOOLEAN_SIMILARITY_MARGIN) ||
      (statusFlip && trueSimilarity >= 0.9 && falseSimilarity < 0.9)
    ) {
      return makeFinding({
        module: meta.id,
        checkId: 'nosqli-boolean',
        title: '布尔型 NoSQL 注入',
        severity: 'high',
        confidence: 'medium',
        url: String(session.ctx?.target?.url ?? ''),
        param: spec.name,
        payload: pair[0],
        evidence:
          `基线 ${describeResponse(baseline)}；真值 ${pair[0]} → ${describeResponse(trueResponse)}（相似度 ${trueSimilarity.toFixed(2)}）；` +
          `假值 ${pair[1]} → ${describeResponse(falseResponse)}（相似度 ${falseSimilarity.toFixed(2)}）；长度差 ${lengthDelta}B，状态码翻转=${statusFlip}。`,
        cwe: meta.cwe,
        remediation: '对查询参数做类型校验与白名单；禁止把请求 JSON 直接作为数据库查询对象使用。',
      })
    }
  }

  if (errorHits.size > 0) {
    const entries = [...errorHits.entries()].slice(0, 2)
    const details = entries.map(([id, hit]) => `${id}="${oneLine(hit.match, 60)}"`).join('；')
    return makeFinding({
      module: meta.id,
      checkId: 'nosqli-error',
      title: '错误型 NoSQL 注入',
      severity: 'high',
      confidence: errorHits.size >= 2 ? 'high' : 'medium',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: entries[0]?.[1]?.payload ?? '',
      evidence: `参数 ${spec.name} 注入后命中 ${errorHits.size} 个 MongoDB/BSON 错误特征：${details}；基线 ${describeResponse(baseline)}。`,
      cwe: meta.cwe,
      remediation: '统一数据库错误页，避免泄露查询细节；对用户输入做类型与结构校验。',
    })
  }
  return null
}

/**
 * JSON 操作符注入（只读探测，仅 veteran + json 位置参数）。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {object} baseline
 * @returns {Promise<object | null>}
 */
async function checkJsonOperators(session, spec, baseline) {
  if (spec.location !== 'json') return null
  for (const probe of forMode(NOSQLI_JSON_PROBES, session.ctx.mode)) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, probe.value)
    if (!response) break
    if (!isHttpResponse(response)) continue
    const expanded = response.body.length - baseline.body.length
    const statusRecovered = baseline.status >= 400 && response.status >= 200 && response.status < 300
    if (!statusRecovered && !(response.status >= 200 && response.status < 300 && expanded >= 60)) continue
    return makeFinding({
      module: meta.id,
      checkId: 'nosqli-json',
      title: 'JSON 操作符注入（NoSQL）',
      severity: 'medium',
      confidence: 'medium',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: JSON.stringify(probe.value),
      evidence:
        `参数 ${spec.name} 位于 JSON body；普通值基线 ${describeResponse(baseline)}；` +
        `注入只读操作符 ${JSON.stringify(probe.value)} 后 ${describeResponse(response)}（长度变化 ${expanded}B，状态恢复=${statusRecovered}）。`,
      cwe: meta.cwe,
      remediation: '对 JSON body 做结构校验，拒绝对象/数组形式的操作符；查询参数只接受标量类型。',
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
  for (const spec of pickParams(ctx, 2)) {
    if (session.aborted) break
    try {
      const baseline = await sendParamBaseline(session, spec)
      if (!baseline) break
      if (!isHttpResponse(baseline)) continue
      let finding = await checkExpressions(session, spec, baseline)
      if (finding === null && !session.aborted && ctx.mode === 'veteran') {
        finding = await checkJsonOperators(session, spec, baseline)
      }
      if (finding !== null) findings.push(finding)
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

/**
 * 原型链污染探测（JSON / 表单查询串）。
 *
 * 检测原理：
 * 1. 先取基线（GET 与 JSON POST 各一次），记录状态码与响应体；
 * 2. 用**无害 marker 属性** `aimypp1337` 构造 `__proto__[aimypp1337]=1`
 *    与 `{"__proto__":{"aimypp1337":"1"}}` 两种载荷；
 * 3. 只观测服务端响应差异：若响应 JSON 的**根对象**直接出现该 marker，
 *    说明服务端把原型属性合并进了业务对象（低置信线索）。
 *
 * 明确不做（降低副作用）：
 * - 不使用 `constructor.prototype` 之外的持久化投毒、不覆盖业务字段；
 * - 不构造 gadget 链、不触发 RCE、不做二次利用；
 * - 只发一次探测请求，不依赖"污染后再请求"的持久化验证。
 *
 * 局限：原型污染是否可利用取决于应用后续如何处理对象，本模块只给
 * low 置信度的线索；JSON 解析层直接拒绝 `__proto__` 时会返回空数组。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/proto-pollution
 */

import {
  createSession, setQueryParam, isHttpResponse, safeJsonParse, makeFinding,
  stableSortFindings, handleModuleError, oneLine, readyForMode, describeResponse,
} from './util.js'
import {
  forMode, PROTO_POLLUTION_MARKER, PROTO_POLLUTION_QUERY_PAYLOADS, PROTO_POLLUTION_JSON_PAYLOADS,
} from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'proto-pollution',
  title: '原型链污染探测',
  kinds: ['proto-pollution', 'prototype-pollution'],
  cwe: 'CWE-1321',
  defaultSeverity: 'medium',
  minMode: 'rookie',
}

/**
 * 判断响应 JSON 根对象是否带 marker 属性。
 * @param {string} body
 * @returns {boolean}
 */
function hasRootMarker(body) {
  const json = safeJsonParse(body)
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    // 非 JSON 时退化为严格文本匹配（"aimypp1337": 形式）。
    return new RegExp(`"${PROTO_POLLUTION_MARKER}"\\s*:`).test(body)
  }
  return Object.prototype.hasOwnProperty.call(json, PROTO_POLLUTION_MARKER)
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  const session = createSession(ctx)
  const targetUrl = String(ctx?.target?.url ?? '')
  if (targetUrl.length === 0 || session.remaining <= 0) return []
  /** @type {object[]} */
  const findings = []

  try {
    // --- 查询串形式 ---
    const getBaseline = await session.probe(targetUrl, { method: 'GET' })
    if (!getBaseline || !isHttpResponse(getBaseline)) return []
    if (getBaseline.body.includes(PROTO_POLLUTION_MARKER)) return []

    for (const payload of forMode(PROTO_POLLUTION_QUERY_PAYLOADS, ctx.mode)) {
      if (session.aborted || session.remaining <= 0) break
      // payload 形如 "__proto__[aimypp1337]=1"
      const separator = payload.indexOf('=')
      const name = separator >= 0 ? payload.slice(0, separator) : payload
      const value = separator >= 0 ? payload.slice(separator + 1) : '1'
      const response = await session.probe(setQueryParam(targetUrl, name, value), { method: 'GET' })
      if (!response) break
      if (!isHttpResponse(response)) continue
      if (!response.body.includes(PROTO_POLLUTION_MARKER)) continue
      if (!hasRootMarker(response.body)) continue
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'proto-pollution-echo',
        title: '疑似原型链污染（查询串，响应根对象出现 marker）',
        severity: 'medium',
        confidence: 'low',
        url: targetUrl,
        payload,
        evidence:
          `基线 ${describeResponse(getBaseline)}；注入 ${payload} 后响应根 JSON 出现 marker 属性 "${PROTO_POLLUTION_MARKER}"，` +
          `响应 ${describeResponse(response)}。可能是服务端合并了 __proto__ 键，也可能是显式回显，需人工确认后续影响。`,
        cwe: meta.cwe,
        remediation: '拒绝请求体/查询串中的 __proto__/constructor/prototype 键；使用 Object.create(null) 或 Map 承载用户输入。',
      }))
      break
    }

    // --- JSON body 形式 ---
    for (const probe of forMode(PROTO_POLLUTION_JSON_PAYLOADS, ctx.mode)) {
      if (session.aborted || session.remaining < 2) break
      const jsonBaseline = await session.probe(targetUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ probe: '1' }),
      })
      if (!jsonBaseline) break
      if (!isHttpResponse(jsonBaseline)) continue
      if (jsonBaseline.body.includes(PROTO_POLLUTION_MARKER)) continue
      const response = await session.probe(targetUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(probe.body),
      })
      if (!response) break
      if (!isHttpResponse(response)) continue
      if (!response.body.includes(PROTO_POLLUTION_MARKER)) continue
      if (!hasRootMarker(response.body)) continue
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'proto-pollution-json',
        title: '疑似原型链污染（JSON body，响应根对象出现 marker）',
        severity: 'medium',
        confidence: 'low',
        url: targetUrl,
        payload: JSON.stringify(probe.body),
        evidence:
          `JSON 基线 ${describeResponse(jsonBaseline)}；注入 ${probe.id} 载荷后响应根 JSON 出现 marker 属性 ` +
          `"${PROTO_POLLUTION_MARKER}"（${describeResponse(response)}）。仅观测到响应差异，未做持久化投毒或利用链验证。`,
        cwe: meta.cwe,
        remediation: '对 JSON body 做严格结构校验，拒绝 __proto__/constructor/prototype 键，并冻结关键对象原型。',
      }))
      break
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

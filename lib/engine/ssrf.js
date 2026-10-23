/**
 * SSRF（服务端请求伪造）检测 —— 仅回显 / 本地判断，不做 OOB。
 *
 * 检测原理：
 * 1. 把内部地址或 file:// URL 注入参数，观察**目标应用自身**返回的内容；
 * 2. 出现基线没有的强内容特征（/etc/passwd 的 root:...:0:0:、云元数据
 *    instance-id/security-credentials、win.ini 段名等）→ 判定可回显 SSRF；
 * 3. 只出现"Connection refused / Could not resolve host"一类服务端回连错误，
 *    且与基线明显不同 → 仅给 low/low 的疑似结论。
 *
 * 明确不做：
 * - 不搭建 DNS/HTTP 回调服务（OOB），不向外部攻击者域名发起探测；
 * - 不探测内网网段、不做端口扫描、不读取云凭据内容；
 * - 不做 DNS 解析：主机是否内网由 util.isInternalHost 离线分类判断。
 *
 * 局限：无回显的盲 SSRF 无法发现；统一错误页会掩盖回连错误。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/ssrf
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue, isHttpResponse,
  matchSignatures, makeFinding, stableSortFindings, handleModuleError,
  describeResponse, oneLine, readyForMode, isInternalHost, similarity,
} from './util.js'
import { forMode, SSRF_PROBES, SSRF_EVIDENCE_SIGNATURES, SSRF_ERROR_SIGNATURES } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'ssrf',
  title: 'SSRF（服务端请求伪造）检测',
  kinds: ['ssrf'],
  cwe: 'CWE-918',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/**
 * 解析注入值里的主机信息（离线，不发请求）。
 * @param {string} payload
 * @returns {{ scheme: string, host: string, internal: boolean }}
 */
function describePayload(payload) {
  try {
    const url = new URL(payload)
    return { scheme: url.protocol.replace(':', ''), host: url.hostname, internal: isInternalHost(url.hostname) }
  } catch {
    return { scheme: '', host: '', internal: false }
  }
}

/**
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {object} baseline
 * @returns {Promise<object | null>}
 */
async function checkParam(session, spec, baseline) {
  const probes = forMode(SSRF_PROBES, session.ctx.mode)
  const baselineIds = new Set(matchSignatures(baseline.body, SSRF_EVIDENCE_SIGNATURES).map((hit) => hit.id))
  /** @type {object | null} */
  let weakFinding = null

  for (const payload of probes) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, payload)
    if (!response) break
    if (!isHttpResponse(response)) continue
    const targetInfo = describePayload(payload)

    // 强证据：取回了内部资源内容。
    const strongHits = matchSignatures(response.body, SSRF_EVIDENCE_SIGNATURES).filter((hit) => !baselineIds.has(hit.id))
    if (strongHits.length > 0) {
      const hit = strongHits[0]
      return makeFinding({
        module: meta.id,
        checkId: 'ssrf-read',
        title: 'SSRF（可回显内部资源）',
        severity: 'high',
        confidence: 'high',
        url: String(session.ctx?.target?.url ?? ''),
        param: spec.name,
        payload,
        evidence:
          `参数 ${spec.name} 注入「${payload}」（scheme=${targetInfo.scheme || '?'}，host=${targetInfo.host || '?'}，内网判断=${targetInfo.internal}）后，` +
          `响应出现内部内容特征 ${hit.id}="${oneLine(hit.match, 80)}"；基线 ${describeResponse(baseline)}，命中响应 ${describeResponse(response)}。`,
        cwe: meta.cwe,
        remediation: '对可发起网络请求的参数使用目标白名单，禁止内网/回环/元数据地址，并关闭不必要的 URL 协议。',
      })
    }

    // 弱证据：服务端回连错误（仅在与基线明显不同、且不是简单回显时记录）。
    if (weakFinding === null && baselineIds.size === 0) {
      const errorMatches = SSRF_ERROR_SIGNATURES
        .map((re) => new RegExp(re.source, re.flags).exec(response.body)?.[0] ?? '')
        .filter((match) => match.length > 0)
      const baselineHasError = SSRF_ERROR_SIGNATURES.some((re) => new RegExp(re.source, re.flags).test(baseline.body))
      const bodySimilarity = similarity(baseline.body, response.body)
      const reflected = response.body.includes(payload)
      if (errorMatches.length > 0 && !baselineHasError && !reflected && (response.status !== baseline.status || bodySimilarity < 0.9)) {
        weakFinding = makeFinding({
          module: 'ssrf',
          checkId: 'ssrf-error-echo',
          title: '疑似 SSRF（服务端回连错误回显）',
          severity: 'low',
          confidence: 'low',
          url: String(session.ctx?.target?.url ?? ''),
          param: spec.name,
          payload,
          evidence:
            `参数 ${spec.name} 注入「${payload}」（host=${targetInfo.host || '?'}）后响应出现服务端连接错误「${oneLine(errorMatches[0], 80)}」，` +
            `基线无同类错误且响应相似度仅 ${bodySimilarity.toFixed(2)}；无法排除应用自身网络错误，故为低置信疑似。`,
          cwe: meta.cwe,
          remediation: '限制服务端可请求的目标地址与协议，并统一错误信息避免暴露回连行为。',
        })
      }
    }
  }
  return weakFinding
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
      const finding = await checkParam(session, spec, baseline)
      if (finding !== null) findings.push(finding)
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

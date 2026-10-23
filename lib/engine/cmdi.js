/**
 * 命令注入检测（回显型 / 时延型）。
 *
 * 检测原理：
 * 1. 先取基线，记录基线响应体，避免把页面本来就有的 "uid=" 之类文本当命中；
 * 2. 回显型：注入 `; id`、`| id` 等操作符，只有响应里出现**基线没有的**
 *    强特征（uid=/gid=/passwd root/Windows 版本等）才算命中；
 *    命中后再用第二个不同操作符复测，复现成功才 confirmed；
 * 3. 时延型（仅 veteran）：注入 `sleep 2`，相对基线时延 ≥1200ms 且二次复现才判定。
 *
 * 局限：
 * - 只做检测，不执行写文件/反弹 shell/下载等危险命令；payload 仅含 id/sleep；
 * - 无回显且无时延的命令注入（例如输出被丢弃）无法发现；
 * - sleep 可能被目标自身的慢请求干扰，故要求基线对比 + 二次复现。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/cmdi
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue, isHttpResponse,
  matchSignatures, makeFinding, stableSortFindings, handleModuleError,
  describeResponse, oneLine, readyForMode,
} from './util.js'
import {
  forMode, CMDI_ECHO_PROBES, CMDI_OUTPUT_SIGNATURES, CMDI_WEAK_SIGNATURES, CMDI_TIME_PROBES,
} from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'cmdi',
  title: '命令注入检测',
  kinds: ['cmdi', 'command-injection', 'rce'],
  cwe: 'CWE-78',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/** 相对基线的额外时延阈值（毫秒）。 */
const TIME_DELTA_MS = 1200

/**
 * 在响应里找基线没有的强/弱回显特征。
 * @param {string} body
 * @param {string} baselineBody
 * @returns {{ strong: Array<{ id: string, match: string }>, weak: Array<{ id: string, match: string }> }}
 */
function collectEcho(body, baselineBody) {
  const baselineStrong = new Set(matchSignatures(baselineBody, CMDI_OUTPUT_SIGNATURES).map((hit) => hit.id))
  const baselineWeak = new Set(matchSignatures(baselineBody, CMDI_WEAK_SIGNATURES).map((hit) => hit.id))
  return {
    strong: matchSignatures(body, CMDI_OUTPUT_SIGNATURES).filter((hit) => !baselineStrong.has(hit.id)),
    weak: matchSignatures(body, CMDI_WEAK_SIGNATURES).filter((hit) => !baselineWeak.has(hit.id)),
  }
}

/**
 * 回显型检测：命中后用第二个操作符复测。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {object} baseline
 * @returns {Promise<object | null>}
 */
async function checkEcho(session, spec, baseline) {
  const probes = forMode(CMDI_ECHO_PROBES, session.ctx.mode)
  /** @type {Array<{ probe: object, response: object, hits: { strong: object[], weak: object[] } }>} */
  const hits = []

  for (const probe of probes) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, probe.value)
    if (!response) break
    if (!isHttpResponse(response)) continue
    const echo = collectEcho(response.body, baseline.body)
    if (echo.strong.length === 0 && echo.weak.length < 2) continue
    hits.push({ probe, response, hits: echo })
    if (hits.length >= 1 && echo.strong.length > 0) break
  }

  if (hits.length === 0) return null
  const first = hits[0]
  const strongIds = first.hits.strong.map((hit) => `${hit.id}="${oneLine(hit.match, 60)}"`)
  const weakIds = first.hits.weak.map((hit) => hit.id)
  const hasStrong = first.hits.strong.length > 0
  let confirmed = false

  // 复测：换一个不同操作符，再命中任意回显特征才 confirmed。
  if (session.remaining > 0 && !session.aborted) {
    const second = probes.find((probe) => probe.operator !== first.probe.operator)
    if (second !== undefined) {
      const response = await sendParamValue(session, spec, second.value)
      if (response && isHttpResponse(response)) {
        const echo = collectEcho(response.body, baseline.body)
        confirmed = echo.strong.length > 0 || echo.weak.length >= 2
      }
    }
  }

  const detail = hasStrong ? `强特征：${strongIds.join('、')}` : `弱特征（≥2）：${weakIds.join('、')}`
  return makeFinding({
    module: meta.id,
    checkId: 'cmdi-echo',
    title: hasStrong ? '命令注入（回显）' : '疑似命令注入（错误回显）',
    severity: hasStrong ? 'high' : 'low',
    confidence: hasStrong ? 'high' : 'medium',
    url: String(session.ctx?.target?.url ?? ''),
    param: spec.name,
    payload: first.probe.value,
    evidence:
      `参数 ${spec.name} 基线 ${describeResponse(baseline)}；载荷「${first.probe.value}」触发${detail}。` +
      `响应 ${describeResponse(first.response)}${confirmed ? '；已用不同操作符复现' : ''}。`,
    cwe: meta.cwe,
    remediation: '避免调用 shell；使用参数化 API/白名单，把用户输入与命令参数严格分离。',
    ...(confirmed ? { confirmed: true } : {}),
  })
}

/**
 * 时延型检测（仅 veteran）：基线对比 + 二次复现。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {object} baseline
 * @returns {Promise<object | null>}
 */
async function checkTime(session, spec, baseline) {
  const probes = forMode(CMDI_TIME_PROBES, session.ctx.mode)
  for (const probe of probes) {
    if (session.aborted || session.remaining < 2) break
    const first = await sendParamValue(session, spec, probe.value)
    if (!first) break
    const firstDelta = first.elapsedMs - baseline.elapsedMs
    if (!isHttpResponse(first) || firstDelta < TIME_DELTA_MS) continue
    const second = await sendParamValue(session, spec, probe.value)
    if (!second) break
    const secondDelta = second.elapsedMs - baseline.elapsedMs
    if (!isHttpResponse(second) || secondDelta < TIME_DELTA_MS) continue
    return makeFinding({
      module: meta.id,
      checkId: 'cmdi-time',
      title: '时间型命令注入',
      severity: 'high',
      confidence: 'medium',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: probe.value,
      evidence:
        `参数 ${spec.name} 基线时延 ${Math.round(baseline.elapsedMs)}ms；` +
        `载荷「${probe.value}」两次请求耗时 ${Math.round(first.elapsedMs)}ms / ${Math.round(second.elapsedMs)}ms，` +
        `相对基线 +${Math.round(firstDelta)}ms / +${Math.round(secondDelta)}ms（阈值 ${TIME_DELTA_MS}ms，已复现）。`,
      cwe: meta.cwe,
      remediation: '避免调用 shell；使用参数化 API/白名单，并限制外部命令执行权限。',
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
  for (const spec of pickParams(ctx, 2)) {
    if (session.aborted) break
    try {
      const baseline = await sendParamBaseline(session, spec)
      if (!baseline) break
      if (!isHttpResponse(baseline)) continue
      let finding = await checkEcho(session, spec, baseline)
      if (finding === null && !session.aborted && ctx.mode === 'veteran') finding = await checkTime(session, spec, baseline)
      if (finding !== null) findings.push(finding)
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

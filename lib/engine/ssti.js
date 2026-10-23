/**
 * SSTI（服务端模板注入）检测。
 *
 * 检测原理：
 * 把 marker 与算术表达式拼在一起注入（如 `aimy1337{{7*7}}`），
 * 只有服务端**真正执行模板**时才会输出 `aimy133749`；
 * 若只是原样回显，响应里出现的是 `aimy1337{{7*7}}`。
 * 因此不依赖 "49" 这种可能自然出现的字符串，显著降低误报。
 *
 * 局限：
 * - 只做求值探测，不执行系统命令、不读取敏感对象（不移植上游的 RCE payload）；
 * - 表达式被沙箱/WAF 拦截或模板语法不同（如 Handlebars 不允许算术）时会漏报；
 * - 引擎归类是根据"哪个表达式被求值"的推断，不代表精确版本。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/ssti
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue, isHttpResponse,
  makeFinding, stableSortFindings, handleModuleError, describeResponse, snippetAround,
  oneLine, readyForMode,
} from './util.js'
import { forMode, SSTI_PROBES, MARKER } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'ssti',
  title: '服务端模板注入检测',
  kinds: ['ssti', 'template-injection'],
  cwe: 'CWE-94',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/**
 * 检测单个参数。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @returns {Promise<object | null>}
 */
async function checkParam(session, spec) {
  const probes = forMode(SSTI_PROBES, session.ctx.mode)
  const baseline = await sendParamBaseline(session, spec)
  if (!baseline || !isHttpResponse(baseline)) return null
  /** @type {Array<{ probe: object, response: object, expected: string }>} */
  const evaluated = []

  for (const probe of probes) {
    if (session.aborted || session.remaining <= 0) break
    const value = `${probe.prefix}${probe.expression}`
    const response = await sendParamValue(session, spec, value)
    if (!response) break
    if (!isHttpResponse(response)) continue
    // 必须出现"服务端求值后的 marker+结果"，且基线里本来没有。
    if (!response.body.includes(probe.expected)) continue
    if (baseline.body.includes(probe.expected)) continue
    evaluated.push({ probe, response, expected: probe.expected })
  }

  if (evaluated.length === 0) return null
  const first = evaluated[0]
  const snippet = oneLine(snippetAround(first.response.body, first.expected, 40), 160)
  return makeFinding({
    module: meta.id,
    checkId: 'ssti-eval',
    title: '服务端模板注入（表达式被求值）',
    severity: 'high',
    confidence: 'high',
    url: String(session.ctx?.target?.url ?? ''),
    param: spec.name,
    payload: `${first.probe.prefix}${first.probe.expression}`,
    evidence:
      `参数 ${spec.name} 注入「${first.probe.prefix}${first.probe.expression}」后响应出现求值结果「${first.expected}」；` +
      `基线 ${describeResponse(baseline)}，注入响应 ${describeResponse(first.response)}；` +
      `模板引擎线索：${first.probe.engine}${evaluated.length >= 2 ? `；共 ${evaluated.length} 个表达式被求值` : ''}。片段：${snippet}`,
    cwe: meta.cwe,
    remediation: '不要把用户输入拼进模板；使用沙箱/受限模板上下文，并对模板表达式做白名单校验。',
    ...(evaluated.length >= 2 ? { confirmed: true } : {}),
  })
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
      const finding = await checkParam(session, spec)
      if (finding !== null) findings.push(finding)
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

export { MARKER as sstiMarker }

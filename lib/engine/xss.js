/**
 * 反射型 XSS 检测（HTML / 属性 / JS 上下文判定 + 编码检测）。
 *
 * 检测原理：
 * 1. 先注入一个无副作用 marker 串 `<aimy1337>`，观察它是否**原样**回显；
 * 2. 若原样回显，根据 marker 在响应中的位置推断上下文：
 *    - 位于 `<script>` 块内 → JS 上下文；
 *    - 位于未闭合标签内部（引号内）→ 属性上下文；
 *    - 否则 → HTML 文本上下文；
 * 3. 按上下文发送对应 PoC（不含真正执行代码，只用 marker 代替 alert），
 *    只有 payload **未编码地完整出现**才算命中；两个变体都命中则 confirmed；
 * 4. 若只出现 HTML 实体/URL 编码形式，则输出 info 级别的"已编码回显"观察，
 *    不宣称可利用。
 *
 * 局限：
 * - 不处理 DOM 型 XSS（需要浏览器执行环境，本插件按契约只用 HTTP 探针）；
 * - 上下文推断是文本启发式，复杂模板/前端拼接可能误判，因此属性/JS 上下文
 *   只给 medium 置信度；
 * - 过滤规则只删除危险标签但保留 marker 的情况会被判为未命中（保守漏报）。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/xss
 */

import {
  createSession, pickParams, sendParamValue, isHttpResponse, decodeHtmlEntities,
  makeFinding, stableSortFindings, handleModuleError, snippetAround, oneLine,
  readyForMode, describeResponse,
} from './util.js'
import { forMode, XSS_PAYLOADS, MARKER } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'xss',
  title: '反射型 XSS 检测',
  kinds: ['xss', 'cross-site-scripting'],
  cwe: 'CWE-79',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

const CONTEXT_LABEL = { html: 'HTML 文本', attr: 'HTML 属性', js: 'JavaScript' }

/**
 * 判断文本末尾的引号状态，返回 `"` / `'` / 空串。
 * @param {string} text
 * @returns {string}
 */
function quoteState(text) {
  let doubleCount = 0
  let singleCount = 0
  for (const char of text) {
    if (char === '"') doubleCount += 1
    else if (char === "'") singleCount += 1
  }
  if (doubleCount % 2 === 1) return '"'
  if (singleCount % 2 === 1) return "'"
  return ''
}

/**
 * 根据 marker 在响应中的位置推断上下文。
 * @param {string} body
 * @param {number} index marker 起始下标
 * @returns {{ context: 'html' | 'attr' | 'js', quote: string }}
 */
function detectContext(body, index) {
  const before = body.slice(Math.max(0, index - 400), index)
  const scriptOpen = before.lastIndexOf('<script')
  const scriptClose = before.lastIndexOf('</script')
  if (scriptOpen >= 0 && scriptOpen > scriptClose) {
    return { context: 'js', quote: quoteState(before.slice(scriptOpen)) }
  }
  const tagOpen = before.lastIndexOf('<')
  const tagClose = before.lastIndexOf('>')
  if (tagOpen >= 0 && tagOpen > tagClose) {
    return { context: 'attr', quote: quoteState(before.slice(tagOpen)) }
  }
  return { context: 'html', quote: '' }
}

/**
 * 挑当前上下文的 payload：属性上下文优先匹配检测到的引号。
 * @param {'html' | 'attr' | 'js'} context
 * @param {string} quote
 * @param {'rookie' | 'veteran'} [mode]
 * @returns {string[]}
 */
function selectPayloads(context, quote, mode) {
  const set = XSS_PAYLOADS[context]
  const list = forMode(set, mode)
  if (context !== 'attr' || quote.length === 0) return list
  const matching = list.filter((payload) => payload.startsWith(quote))
  const rest = list.filter((payload) => !payload.startsWith(quote))
  return [...matching, ...rest]
}

/**
 * 检查响应里是否出现了 HTML 实体 / URL 编码形式的输入。
 * @param {string} body
 * @returns {string}
 */
function detectEncoding(body) {
  const marker = MARKER
  const htmlEncoded = [`&lt;${marker}&gt;`, `&#60;${marker}&#62;`, `&#x3c;${marker}&#x3e;`, `&#x3C;${marker}&#x3E;`]
  for (const variant of htmlEncoded) {
    if (body.includes(variant)) return 'HTML 实体编码'
  }
  if (body.includes(`%3C${marker}%3E`) || body.includes(`%3c${marker}%3e`)) return 'URL 编码'
  // 解码后再比对一次，覆盖混合编码（例如 &lt; ... &gt; 中间夹杂实体）。
  const decoded = decodeHtmlEntities(body)
  if (decoded.includes(`<${MARKER}>`) && !body.includes(`<${MARKER}>`)) return 'HTML 实体编码（混合形式）'
  return ''
}

/**
 * 检测单个参数。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @returns {Promise<object[]>}
 */
async function checkParam(session, spec) {
  /** @type {object[]} */
  const findings = []
  const markerProbe = `<${MARKER}>`
  const probeResponse = await sendParamValue(session, spec, markerProbe)
  if (!probeResponse || !isHttpResponse(probeResponse)) return findings

  const rawIndex = probeResponse.body.indexOf(markerProbe)
  const rawReflected = rawIndex >= 0
  const encoding = detectEncoding(probeResponse.body)

  if (!rawReflected) {
    if (encoding.length > 0) {
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'xss-encoded-reflection',
        title: '参数回显已编码（未发现可利用 XSS）',
        severity: 'info',
        confidence: 'medium',
        url: String(session.ctx?.target?.url ?? ''),
        param: spec.name,
        payload: markerProbe,
        evidence: `参数 ${spec.name} 的探测串 <${MARKER}> 以「${encoding}」形式回显，未发现未编码反射，因此不判定为 XSS。响应 ${describeResponse(probeResponse)}。`,
        cwe: meta.cwe,
        remediation: '保持输出编码实践；建议同时按上下文使用正确的编码函数。',
      }))
    }
    return findings
  }

  const { context, quote } = detectContext(probeResponse.body, rawIndex)
  const candidates = selectPayloads(context, quote, session.ctx.mode).slice(0, session.ctx.mode === 'veteran' ? 3 : 2)
  /** @type {Array<{ payload: string, response: object }>} */
  const hits = []
  for (const payload of candidates) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, payload)
    if (!response) break
    if (!isHttpResponse(response)) continue
    // 必须**原样**出现（未被 HTML 实体转义），才计为命中。
    if (!response.body.includes(payload)) continue
    if (!response.body.includes(MARKER)) continue
    hits.push({ payload, response })
  }

  if (hits.length > 0) {
    const first = hits[0]
    const contextLabel = CONTEXT_LABEL[context]
    const severity = context === 'js' ? 'medium' : 'high'
    const confidence = context === 'html' ? 'high' : 'medium'
    const snippet = oneLine(snippetAround(first.response.body, first.payload, 40), 160)
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'xss-reflected',
      title: `反射型 XSS（${contextLabel}上下文）`,
      severity,
      confidence,
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: first.payload,
      evidence:
        `参数 ${spec.name} 在${contextLabel}上下文原样回显；payload「${first.payload}」未编码出现在响应中` +
        `${hits.length >= 2 ? `，并用 ${hits.length} 个不同变体复现` : ''}。` +
        `响应 ${describeResponse(first.response)}；片段：${snippet}`,
      cwe: meta.cwe,
      remediation: '按输出上下文做 HTML/属性/JS 编码，使用白名单过滤，并配置 CSP 作为纵深防御。',
      ...(hits.length >= 2 ? { confirmed: true } : {}),
    }))
  }
  return findings
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
  for (const spec of pickParams(ctx, 3)) {
    if (session.aborted) break
    try {
      findings.push(...(await checkParam(session, spec)))
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

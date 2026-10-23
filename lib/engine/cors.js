/**
 * CORS 配置检测（Origin 反射 / null / 通配 + credentials）。
 *
 * 检测原理：
 * 1. 先发一次不带 Origin 的基线请求，识别服务端是否**无条件**返回某个 ACAO；
 * 2. 分别用 `Origin: https://evil.aimy.test` 与 `Origin: null` 探测：
 *    - ACAO 原样反射任意 Origin，且带 `Access-Control-Allow-Credentials: true`
 *      → high（可跨站读取带凭据数据）；
 *    - 反射但无 credentials → medium（可跨站读取匿名数据）；
 *    - `ACAO: null` → medium；
 *    - `ACAO: *` 且 credentials=true → low（浏览器规范会拒绝该组合，属配置错误）。
 * 3. 反射 Origin 必须与目标自身 Origin 不同，避免把正常的同源回显当漏洞。
 *
 * 局限：
 * - 只做单次 GET 探测，不验证浏览器实际执行结果；
 * - 若服务端只对特定路径/方法开放 CORS，可能漏报；
 * - 通配符 + credentials 在规范上会被浏览器拦截，因此只给 low，不夸大。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/cors
 */

import {
  createSession, isHttpResponse, headerValue, makeFinding, stableSortFindings,
  handleModuleError, describeResponse, readyForMode,
} from './util.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'cors',
  title: 'CORS 跨域配置检测',
  kinds: ['cors', 'misconfiguration'],
  cwe: 'CWE-942',
  defaultSeverity: 'medium',
  minMode: 'rookie',
}

/** 固定使用的测试 Origin，保证结果确定性。 */
const EVIL_ORIGIN = 'https://evil.aimy.test'
const NULL_ORIGIN = 'null'

/** 同一 URL 只输出 1 条 finding，按可利用性从高到低取最强场景。 */
const FINDING_PRIORITY = {
  'cors-reflected-credentials': 4,
  'cors-reflected-origin': 3,
  'cors-null-origin': 2,
  'cors-wildcard-credentials': 1,
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  const session = createSession(ctx)
  const url = String(ctx?.target?.url ?? '')
  const targetOrigin = String(ctx?.target?.origin ?? '')
  if (url.length === 0) return []

  /** @type {object[]} */
  const candidates = []
  try {
    const baseline = await session.probe(url, { method: 'GET' })
    if (!baseline) return []
    if (!isHttpResponse(baseline)) return []
    const baselineAcao = headerValue(baseline, 'access-control-allow-origin')

    for (const origin of [EVIL_ORIGIN, NULL_ORIGIN]) {
      if (session.aborted || session.remaining <= 0) break
      const response = await session.probe(url, { method: 'GET', headers: { origin } })
      if (!response) break
      if (!isHttpResponse(response)) continue
      const acao = headerValue(response, 'access-control-allow-origin')
      const acac = headerValue(response, 'access-control-allow-credentials').toLowerCase() === 'true'
      const vary = headerValue(response, 'vary')
      const common =
        `基线 ACAO="${baselineAcao || '(无)'}"；携带 Origin: ${origin} 时 ACAO="${acao || '(无)'}"，` +
        `ACAC="${acac ? 'true' : '(无)'}"，Vary="${vary || '(无)'}"，响应 ${describeResponse(response)}。`

      if (acao.toLowerCase() === 'null' && origin === NULL_ORIGIN) {
        candidates.push(makeFinding({
          module: meta.id,
          checkId: 'cors-null-origin',
          title: 'CORS 接受 null Origin',
          severity: 'medium',
          confidence: 'medium',
          url,
          evidence: `${common} 任意沙箱/本地文件页面可用 null Origin 发起跨域读取。`,
          cwe: meta.cwe,
          remediation: '拒绝 Origin: null，仅对明确可信来源返回 ACAO。',
        }))
        continue
      }

      if (acao === origin && origin !== targetOrigin) {
        candidates.push(makeFinding({
          module: meta.id,
          checkId: acac ? 'cors-reflected-credentials' : 'cors-reflected-origin',
          title: acac ? 'CORS 反射任意 Origin 且允许凭据' : 'CORS 反射任意 Origin',
          severity: acac ? 'high' : 'medium',
          confidence: 'high',
          url,
          evidence: `${common} 服务端把攻击者可控 Origin 原样反射${acac ? '，且允许携带凭据（可跨站读取登录态数据）' : '，任意站点可跨域读取匿名响应'}。`,
          cwe: meta.cwe,
          remediation: '使用固定白名单校验 Origin，禁止正则/后缀匹配；确需凭据时只允许可信来源。',
        }))
        continue
      }

      if (acao === '*' && acac) {
        candidates.push(makeFinding({
          module: meta.id,
          checkId: 'cors-wildcard-credentials',
          title: 'CORS 通配 Origin 与 credentials 同时启用',
          severity: 'low',
          confidence: 'high',
          url,
          evidence: `${common} 通配 Origin 与 Allow-Credentials:true 组合违反规范（浏览器会拒绝），但属危险配置模板，建议修正。`,
          cwe: meta.cwe,
          remediation: '不要同时使用 ACAO:* 与 Allow-Credentials:true；改为显式白名单。',
        }))
      }
    }

    // 去重 + 取优先级最高的一条：同一 URL 不重复报同类配置问题。
    const byCheck = new Map()
    for (const finding of candidates) {
      if (!byCheck.has(finding.checkId)) byCheck.set(finding.checkId, finding)
    }
    const strongest = [...byCheck.values()].sort(
      (left, right) => (FINDING_PRIORITY[right.checkId] ?? 0) - (FINDING_PRIORITY[left.checkId] ?? 0),
    )[0]
    if (strongest !== undefined) return [strongest]
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return []
}

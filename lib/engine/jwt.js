/**
 * JWT 安全检测（**仅静态分析**，不构造/发送伪造令牌）。
 *
 * 检测原理：
 * 1. 从响应体、Set-Cookie 与已知参数样例中提取 JWT（三段 base64url）；
 * 2. 本地解码 header/claims，检查静态缺陷：
 *    - header.alg = "none"（未验证签名）；
 *    - HS256/384/512 的签名能否被弱密钥字典离线校验通过（node:crypto HMAC）；
 *    - 缺少 exp 过期声明；exp 早于响应 Date 头（令牌已过期仍被返回）；
 *    - kid 含路径穿越字符；
 * 3. 所有结论都来自**已有令牌**，不修改令牌、不做 alg 混淆攻击链、不重放。
 *
 * 局限：
 * - 只做离线字典校验，字典外弱密钥发现不了（veteran 40 条）；
 * - 过期判断以响应 Date 头为参考时间，若服务端不返回 Date 则跳过；
 * - 无法判断服务端是否真的信任 alg:none（只能报告令牌/页面中出现该 header）。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/jwt
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import {
  createSession, isHttpResponse, headerValue, makeFinding, stableSortFindings,
  handleModuleError, referenceTimeFromHeaders, oneLine, readyForMode, safeJsonParse,
} from './util.js'
import { forMode, JWT_WEAK_SECRETS, JWT_SECRET_BUDGET } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'jwt',
  title: 'JWT 安全检测（静态）',
  kinds: ['jwt', 'token', 'auth'],
  cwe: 'CWE-347',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/** JWT 形状：三段 base64url，允许空签名段（alg:none）。 */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g

/** HS 算法 → node:crypto 摘要名。 */
const HMAC_ALGORITHMS = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

/**
 * base64url 解码为 UTF-8 字符串；失败返回 null。
 * @param {string} part
 * @returns {string | null}
 */
function decodeBase64Url(part) {
  try {
    return Buffer.from(part, 'base64url').toString('utf8')
  } catch {
    return null
  }
}

/**
 * 解析 JWT 为 { token, header, payload, signature, parts }；非法返回 null。
 * @param {string} token
 * @returns {{ token: string, header: object, payload: object, signature: string } | null}
 */
function parseJwt(token) {
  const parts = String(token).split('.')
  if (parts.length !== 3) return null
  const headerText = decodeBase64Url(parts[0])
  const payloadText = decodeBase64Url(parts[1])
  if (headerText === null || payloadText === null) return null
  const header = safeJsonParse(headerText)
  const payload = safeJsonParse(payloadText)
  if (header === null || typeof header !== 'object' || Array.isArray(header)) return null
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null
  return { token, header, payload, signature: parts[2] }
}

/**
 * 离线校验 HMAC 签名是否匹配字典密钥。
 * @param {{ token: string, header: object, signature: string }} parsed
 * @param {string} secret
 * @returns {boolean}
 */
function verifyHmac(parsed, secret) {
  const algorithm = String(parsed.header.alg ?? '').toUpperCase()
  const digest = HMAC_ALGORITHMS[algorithm]
  if (digest === undefined) return false
  const parts = parsed.token.split('.')
  if (parts.length !== 3 || parts[2].length === 0) return false
  let expected
  let actual
  try {
    expected = createHmac(digest, secret).update(`${parts[0]}.${parts[1]}`).digest()
    actual = Buffer.from(parts[2], 'base64url')
  } catch {
    return false
  }
  if (expected.length !== actual.length) return false
  try {
    return timingSafeEqual(expected, actual)
  } catch {
    return false
  }
}

/**
 * 从响应与已知参数中收集候选 JWT。
 * @param {object} ctx
 * @param {object} response
 * @returns {string[]}
 */
function collectTokens(ctx, response) {
  /** @type {Set<string>} */
  const tokens = new Set()
  const body = String(response.body ?? '')
  for (const match of body.matchAll(JWT_RE)) tokens.add(match[0])

  const cookie = headerValue(response, 'set-cookie')
  for (const match of cookie.matchAll(JWT_RE)) tokens.add(match[0])

  const params = Array.isArray(ctx?.params) ? ctx.params : []
  for (const spec of params) {
    if (typeof spec?.sample !== 'string') continue
    for (const match of spec.sample.matchAll(JWT_RE)) tokens.add(match[0])
  }
  return [...tokens]
}

/**
 * 检查单个令牌，返回 findings。
 * @param {object} ctx
 * @param {string} token
 * @param {number | null} referenceTime
 * @returns {object[]}
 */
function analyzeToken(ctx, token, referenceTime) {
  /** @type {object[]} */
  const findings = []
  const parsed = parseJwt(token)
  if (parsed === null) return findings
  const url = String(ctx?.target?.url ?? '')
  const tokenHint = `${oneLine(token, 24)}...`
  const algorithm = String(parsed.header.alg ?? '')

  if (algorithm.toLowerCase() === 'none') {
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'jwt-alg-none',
      title: 'JWT 使用 alg=none（未验证签名）',
      severity: 'high',
      confidence: 'medium',
      url,
      payload: tokenHint,
      evidence: `令牌 header 声明 alg="none"，claims=${oneLine(JSON.stringify(parsed.payload), 160)}。若服务端接受该令牌，任意用户可自行构造身份。`,
      cwe: meta.cwe,
      remediation: '服务端固定允许的签名算法白名单，显式拒绝 alg=none，并校验签名。',
    }))
  }

  const secrets = forMode(JWT_WEAK_SECRETS, ctx?.mode)
  const budget = JWT_SECRET_BUDGET[ctx?.mode === 'veteran' ? 'veteran' : 'rookie'] ?? 8
  const foundSecret = secrets.slice(0, budget).find((secret) => verifyHmac(parsed, secret))
  if (foundSecret !== undefined) {
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'jwt-weak-secret',
      title: 'JWT 使用弱 HMAC 密钥',
      severity: 'high',
      confidence: 'high',
      url,
      payload: tokenHint,
      evidence: `令牌 header.alg=${algorithm || '?'}，签名可用字典密钥「${foundSecret}」离线校验通过；claims=${oneLine(JSON.stringify(parsed.payload), 160)}。`,
      cwe: 'CWE-321',
      remediation: '使用长度足够的随机密钥（≥256bit）并定期轮换，禁止使用字典词/默认密钥。',
    }))
  }

  if (parsed.payload.exp === undefined || parsed.payload.exp === null) {
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'jwt-missing-exp',
      title: 'JWT 缺少过期时间声明',
      severity: 'low',
      confidence: 'medium',
      url,
      payload: tokenHint,
      evidence: `令牌 claims 缺少 exp：${oneLine(JSON.stringify(parsed.payload), 200)}。令牌一旦泄露将长期有效。`,
      cwe: meta.cwe,
      remediation: '为令牌设置较短 exp，并实现刷新/吊销机制。',
    }))
  } else if (referenceTime !== null && Number.isFinite(Number(parsed.payload.exp))) {
    const expSeconds = Number(parsed.payload.exp)
    const expMs = expSeconds > 1e12 ? expSeconds : expSeconds * 1000
    if (expMs < referenceTime) {
      const expiredAt = new Date(expMs).toISOString()
      const referenceAt = new Date(referenceTime).toISOString()
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'jwt-expired-token',
        title: '页面中出现已过期 JWT',
        severity: 'low',
        confidence: 'low',
        url,
        payload: tokenHint,
        evidence: `令牌 exp=${expiredAt} 早于响应 Date 头 ${referenceAt}，但该令牌仍出现在响应中；需人工确认服务端是否仍接受。`,
        cwe: meta.cwe,
        remediation: '严格校验 exp/nbf，并拒绝过期令牌。',
      }))
    }
  }

  const kid = String(parsed.header.kid ?? '')
  if (kid.length > 0 && /(?:\.\.\/|\.\.\\|[\\/])/.test(kid)) {
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'jwt-kid-traversal',
      title: 'JWT kid 含路径分隔字符',
      severity: 'low',
      confidence: 'medium',
      url,
      payload: tokenHint,
      evidence: `令牌 header.kid="${oneLine(kid, 80)}" 含路径穿越/分隔字符，若服务端用 kid 拼接密钥路径可能被利用。`,
      cwe: meta.cwe,
      remediation: '对 kid 使用固定白名单映射，不要把它拼进文件路径。',
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
  if (session.remaining <= 0) return []
  /** @type {object[]} */
  const findings = []
  try {
    const response = await session.probe(String(ctx?.target?.url ?? ''), { method: 'GET' })
    if (!response || !isHttpResponse(response)) return []
    const referenceTime = referenceTimeFromHeaders(response)
    /** @type {Set<string>} */
    const seen = new Set()
    for (const token of collectTokens(ctx, response)) {
      if (seen.has(token)) continue
      seen.add(token)
      try {
        findings.push(...analyzeToken(ctx, token, referenceTime))
      } catch (error) {
        handleModuleError(ctx, meta.id, error)
      }
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

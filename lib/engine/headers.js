/**
 * 安全响应头检测（缺失 / 弱配置 / Cookie 属性）。
 *
 * 检测原理：
 * 只发 1 个 GET 请求，检查浏览器侧安全响应头：
 * - Strict-Transport-Security（仅 HTTPS 站点；max-age < 180 天视为弱配置）
 * - Content-Security-Policy（缺失 / 含 unsafe-inline、unsafe-eval）
 * - X-Frame-Options（缺失且 CSP 无 frame-ancestors → 点击劫持风险）
 * - X-Content-Type-Options（缺失或非 nosniff）
 * - Referrer-Policy、Permissions-Policy（缺失）
 * - Set-Cookie 的 Secure / HttpOnly / SameSite 属性
 *
 * 判定是**保守**的：仅对 HTML 响应评估浏览器渲染类响应头（CSP/XFO/
 * Referrer/Permissions），避免对纯 JSON API 产生大量噪声；Cookie 只对
 * session/token 类名字要求 HttpOnly。
 *
 * 局限：响应头只是"防御缺失"，不等同于已可利用漏洞；反向代理可能在边缘
 * 追加响应头，本模块只能看到目标返回的最终头。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/headers
 */

import {
  createSession, isHttpResponse, headerValue, makeFinding, stableSortFindings,
  handleModuleError, oneLine, readyForMode, describeResponse,
} from './util.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'headers',
  title: '安全响应头检测',
  kinds: ['headers', 'misconfiguration'],
  cwe: 'CWE-693',
  defaultSeverity: 'medium',
  minMode: 'rookie',
}

/** HSTS 建议最小 max-age：180 天（秒）。 */
const HSTS_MIN_MAX_AGE = 15552000
/** 需要 HttpOnly 的会话类 Cookie 名特征。 */
const SESSION_COOKIE_RE = /sess|session|sid|token|auth|jwt|login|remember/i
/** Set-Cookie 属性名，避免把 Expires 等属性误当 cookie 名。 */
const COOKIE_ATTRIBUTES = new Set([
  'expires', 'path', 'domain', 'max-age', 'samesite', 'secure', 'httponly', 'priority', 'partitioned',
])

/**
 * 按逗号拆分多个 Set-Cookie（避免把 Expires 中的逗号当分隔符）。
 * @param {string} raw
 * @returns {string[]}
 */
function splitSetCookie(raw) {
  if (raw.length === 0) return []
  return raw
    .split(/,\s*(?=[A-Za-z0-9_.-]+=)/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}

/**
 * 解析单个 Set-Cookie 的名义与属性。
 * @param {string} cookie
 * @returns {{ name: string, attributes: string } | null}
 */
function parseCookie(cookie) {
  const match = /^([^=;\s]+)=/.exec(cookie)
  if (match === null) return null
  const name = match[1]
  if (COOKIE_ATTRIBUTES.has(name.toLowerCase())) return null
  return { name, attributes: cookie.slice(match[0].length) }
}

/**
 * 判断响应是否 HTML（决定是否评估渲染类响应头）。
 * @param {object} response
 * @returns {boolean}
 */
function isHtmlResponse(response) {
  const contentType = headerValue(response, 'content-type').toLowerCase()
  if (contentType.includes('text/html') || contentType.includes('application/xhtml')) return true
  if (contentType.length > 0) return false
  return response.body.trimStart().startsWith('<')
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
    const url = String(ctx?.target?.url ?? '')
    const response = await session.probe(url, { method: 'GET' })
    if (!response || !isHttpResponse(response)) return []
    const isHttps = (() => {
      try {
        return new URL(url).protocol === 'https:'
      } catch {
        return false
      }
    })()
    const html = isHtmlResponse(response)
    const summary = describeResponse(response)
    const push = (input) => {
      findings.push(makeFinding({
        module: meta.id,
        url,
        cwe: meta.cwe,
        ...input,
        evidence: `${summary}；${input.evidence}`,
      }))
    }

    // --- HSTS（仅 HTTPS 有意义）---
    if (isHttps) {
      const hsts = headerValue(response, 'strict-transport-security')
      if (hsts.length === 0) {
        push({
          checkId: 'headers-hsts-missing',
          title: '缺少 HSTS 响应头',
          severity: 'medium',
          confidence: 'high',
          evidence: '未返回 Strict-Transport-Security，浏览器可能被降级到 HTTP。',
          remediation: '对所有 HTTPS 响应设置 Strict-Transport-Security: max-age≥15552000; includeSubDomains。',
        })
      } else {
        const maxAge = /max-age\s*=\s*(\d+)/i.exec(hsts)
        if (maxAge === null || Number(maxAge[1]) < HSTS_MIN_MAX_AGE) {
          push({
            checkId: 'headers-hsts-weak',
            title: 'HSTS max-age 过短或缺失',
            severity: 'low',
            confidence: 'high',
            evidence: `Strict-Transport-Security="${oneLine(hsts, 120)}"，建议 max-age≥${HSTS_MIN_MAX_AGE}。`,
            remediation: '把 HSTS max-age 提升到至少 180 天，并考虑 includeSubDomains、preload。',
          })
        }
      }
    }

    // --- HTML 渲染类响应头 ---
    if (html) {
      const csp = headerValue(response, 'content-security-policy')
      const cspLower = csp.toLowerCase()
      const cspHasFrameAncestors = cspLower.includes('frame-ancestors')
      if (csp.length === 0) {
        push({
          checkId: 'headers-csp-missing',
          title: '缺少 Content-Security-Policy 响应头',
          severity: 'medium',
          confidence: 'high',
          evidence: '未返回 Content-Security-Policy，缺少对脚本/资源来源的浏览器侧限制。',
          remediation: '按最小权限配置 CSP（限制 script-src/style-src/object-src），逐步去掉 unsafe-*。',
        })
      } else if (cspLower.includes("'unsafe-inline'") || cspLower.includes("'unsafe-eval'")) {
        push({
          checkId: 'headers-csp-weak',
          title: 'CSP 含 unsafe-inline/unsafe-eval',
          severity: 'low',
          confidence: 'high',
          evidence: `Content-Security-Policy="${oneLine(csp, 200)}" 含 unsafe-inline 或 unsafe-eval，XSS 防护被显著削弱。`,
          remediation: '移除 unsafe-inline/unsafe-eval，改用 nonce/hash 与外部脚本。',
        })
      }

      const xfo = headerValue(response, 'x-frame-options')
      if (xfo.length === 0) {
        if (!cspHasFrameAncestors) {
          push({
            checkId: 'headers-xfo-missing',
            title: '缺少 X-Frame-Options / frame-ancestors',
            severity: 'medium',
            confidence: 'high',
            evidence: '未返回 X-Frame-Options，且 CSP 未声明 frame-ancestors，页面可能被第三方 iframe 嵌套（点击劫持）。',
            remediation: '设置 X-Frame-Options: DENY 或 SAMEORIGIN，或在 CSP 声明 frame-ancestors。',
          })
        }
      } else {
        const normalized = xfo.trim().toLowerCase()
        const valid = normalized === 'deny' || normalized === 'sameorigin'
        if (!valid) {
          push({
            checkId: 'headers-xfo-invalid',
            title: 'X-Frame-Options 取值不规范',
            severity: 'low',
            confidence: 'high',
            evidence: `X-Frame-Options="${oneLine(xfo, 80)}"，仅 DENY/SAMEORIGIN 被现代浏览器可靠支持。`,
            remediation: '改用 X-Frame-Options: DENY 或 SAMEORIGIN（ALLOW-FROM 已废弃）。',
          })
        }
      }

      if (headerValue(response, 'referrer-policy').length === 0) {
        push({
          checkId: 'headers-referrer-missing',
          title: '缺少 Referrer-Policy 响应头',
          severity: 'low',
          confidence: 'high',
          evidence: '未返回 Referrer-Policy，跨站跳转时可能泄露完整 URL 中的敏感参数。',
          remediation: '设置 Referrer-Policy: strict-origin-when-cross-origin 或更严格策略。',
        })
      }

      if (headerValue(response, 'permissions-policy').length === 0) {
        push({
          checkId: 'headers-permissions-missing',
          title: '缺少 Permissions-Policy 响应头',
          severity: 'low',
          confidence: 'medium',
          evidence: '未返回 Permissions-Policy，摄像头/麦克风/地理位置等浏览器能力默认可能对页面开放。',
          remediation: '按业务需要声明 Permissions-Policy，默认拒绝不需要的能力。',
        })
      }
    }

    // --- X-Content-Type-Options（所有响应都适用）---
    const xcto = headerValue(response, 'x-content-type-options').trim().toLowerCase()
    if (xcto !== 'nosniff') {
      push({
        checkId: 'headers-xcto-missing',
        title: '缺少 X-Content-Type-Options: nosniff',
        severity: 'low',
        confidence: 'high',
        evidence: xcto.length === 0 ? '未返回 X-Content-Type-Options。' : `X-Content-Type-Options="${oneLine(xcto, 60)}"，应为 nosniff。`,
        remediation: '设置 X-Content-Type-Options: nosniff，避免 MIME 嗅探导致的脚本执行。',
      })
    }

    // --- Set-Cookie 属性 ---
    const setCookie = headerValue(response, 'set-cookie')
    const cookies = splitSetCookie(setCookie)
      .map(parseCookie)
      .filter((cookie) => cookie !== null)
    if (cookies.length > 0) {
      const names = cookies.map((cookie) => cookie.name)
      const insecure = cookies.filter((cookie) => !/;\s*secure\b/i.test(cookie.attributes) && !/^\s*secure\s*$/i.test(cookie.attributes))
      const noHttpOnly = cookies.filter((cookie) => SESSION_COOKIE_RE.test(cookie.name) && !/;\s*httponly\b/i.test(cookie.attributes))
      const noSameSite = cookies.filter((cookie) => !/;\s*samesite\s*=/i.test(cookie.attributes))

      if (isHttps && insecure.length > 0) {
        push({
          checkId: 'headers-cookie-secure',
          title: 'Cookie 缺少 Secure 属性',
          severity: 'low',
          confidence: 'high',
          evidence: `HTTPS 站点的 Cookie（${oneLine(insecure.map((cookie) => cookie.name).join(', '), 120)}）未设置 Secure，可能通过明文 HTTP 泄露。`,
          remediation: '为所有 Cookie 设置 Secure 属性。',
        })
      }
      if (noHttpOnly.length > 0) {
        push({
          checkId: 'headers-cookie-httponly',
          title: '会话类 Cookie 缺少 HttpOnly',
          severity: 'low',
          confidence: 'medium',
          evidence: `会话类 Cookie（${oneLine(noHttpOnly.map((cookie) => cookie.name).join(', '), 120)}）未设置 HttpOnly，可能被 XSS 读取。`,
          remediation: '为会话/令牌 Cookie 设置 HttpOnly。',
        })
      }
      if (noSameSite.length > 0) {
        push({
          checkId: 'headers-cookie-samesite',
          title: 'Cookie 缺少 SameSite 属性',
          severity: 'low',
          confidence: 'medium',
          evidence: `Cookie（${oneLine(noSameSite.map((cookie) => cookie.name).join(', '), 120)}，共 ${names.length} 个）未显式设置 SameSite，跨站请求防护依赖浏览器默认值。`,
          remediation: '为 Cookie 显式设置 SameSite=Lax 或 Strict（需跨站时用 None+Secure）。',
        })
      }
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

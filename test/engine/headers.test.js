/**
 * headers 引擎模块测试：完整安全头不误报、缺失头命中、Cookie 属性、请求上限、aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/headers.js'

/** @param {Record<string, string | string[]>} [headers] @param {string} [body] */
function response(headers = {}, body = '<html><body>ok</body></html>') {
  return {
    method: 'GET', url: 'https://target.test/', status: 200, headers, body,
    elapsedMs: 1, truncated: false,
  }
}

/**
 * @param {(url: string, init: object) => object} handler
 * @param {{ maxRequests?: number, onProbe?: Function, targetUrl?: string }} [options]
 */
function makeCtx(handler, options = {}) {
  const calls = []
  const controller = new AbortController()
  const url = new URL(options.targetUrl ?? 'https://target.test/')
  return {
    target: { url, origin: url.origin, host: url.hostname },
    params: [],
    mode: 'rookie',
    authorized: true,
    signal: controller.signal,
    log: () => {},
    limits: { timeoutMs: 5000, maxRequests: options.maxRequests ?? 40, maxBodyBytes: 65536 },
    probe: async (requestUrl, init = {}) => {
      calls.push(String(requestUrl))
      options.onProbe?.(String(requestUrl), init, controller)
      return handler(String(requestUrl), init)
    },
    calls,
    controller,
  }
}

const GOOD_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=(), camera=()',
}

test('headers: 安全头齐全不误报', async () => {
  const ctx = makeCtx(() => response(GOOD_HEADERS))
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
})

test('headers: 缺失 HSTS/CSP/XFO 等 → 命中多项', async () => {
  const ctx = makeCtx(() => response({}))
  const findings = await run(ctx)
  const ids = findings.map((finding) => finding.checkId)
  for (const expected of [
    'headers-hsts-missing',
    'headers-csp-missing',
    'headers-xfo-missing',
    'headers-xcto-missing',
    'headers-referrer-missing',
    'headers-permissions-missing',
  ]) {
    assert.ok(ids.includes(expected), `未命中 ${expected}`)
  }
  assert.ok(findings.every((finding) => finding.evidence.length <= 800))
})

test('headers: HTTP 站点不要求 HSTS', async () => {
  const ctx = makeCtx(
    () => response({ 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'", 'x-frame-options': 'SAMEORIGIN' }, '<html></html>'),
    { targetUrl: 'http://target.test/' },
  )
  const findings = await run(ctx)
  assert.equal(findings.some((finding) => finding.checkId.startsWith('headers-hsts')), false)
})

test('headers: Cookie 缺少 Secure/HttpOnly/SameSite → 命中', async () => {
  const ctx = makeCtx(() => response({
    ...GOOD_HEADERS,
    'set-cookie': 'sessionid=abc123; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT',
  }))
  const findings = await run(ctx)
  const ids = findings.map((finding) => finding.checkId)
  assert.ok(ids.includes('headers-cookie-secure'))
  assert.ok(ids.includes('headers-cookie-httponly'))
  assert.ok(ids.includes('headers-cookie-samesite'))
})

test('headers: HSTS max-age 过短 → 弱配置提示', async () => {
  const ctx = makeCtx(() => response({ ...GOOD_HEADERS, 'strict-transport-security': 'max-age=600' }))
  const findings = await run(ctx)
  assert.ok(findings.some((finding) => finding.checkId === 'headers-hsts-weak'))
})

test('headers: 请求数不超过 limits.maxRequests（0 预算直接返回）', async () => {
  const ctx = makeCtx(() => response(GOOD_HEADERS), { maxRequests: 0 })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.equal(ctx.calls.length, 0)
})

test('headers: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response({}), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('headers: meta 形状符合契约', () => {
  assert.equal(meta.id, 'headers')
  assert.equal(meta.cwe, 'CWE-693')
})

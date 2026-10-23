/**
 * cors 引擎模块测试：不误报、Origin 反射+凭据、通配+credentials、请求上限。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/cors.js'

/** @param {Record<string, string | string[]>} [headers] @param {number} [status] */
function response(headers = {}, status = 200) {
  return {
    method: 'GET', url: 'https://target.test/', status, headers,
    body: '<html><body>ok</body></html>', elapsedMs: 1, truncated: false,
  }
}

/**
 * @param {(url: string, init: object) => object} handler
 * @param {{ maxRequests?: number, onProbe?: Function, targetUrl?: string }} [options]
 */
function makeCtx(handler, options = {}) {
  const calls = []
  const controller = new AbortController()
  const url = new URL(options.targetUrl ?? 'https://target.test/api/data')
  return {
    target: { url, origin: url.origin, host: url.hostname },
    params: [],
    mode: 'rookie',
    authorized: true,
    signal: controller.signal,
    log: () => {},
    limits: { timeoutMs: 5000, maxRequests: options.maxRequests ?? 40, maxBodyBytes: 65536 },
    probe: async (requestUrl, init = {}) => {
      calls.push({ url: String(requestUrl), init })
      options.onProbe?.(String(requestUrl), init, controller)
      return handler(String(requestUrl), init)
    },
    calls,
    controller,
  }
}

test('cors: 未返回 CORS 头不误报', async () => {
  const ctx = makeCtx(() => response({ 'content-type': 'application/json' }))
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('cors: Origin 反射 + credentials=true → high', async () => {
  const ctx = makeCtx((_url, init) => {
    const origin = init.headers?.origin ?? ''
    return response({
      'access-control-allow-origin': origin,
      'access-control-allow-credentials': 'true',
      vary: 'Origin',
    })
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].checkId, 'cors-reflected-credentials')
  assert.equal(findings[0].severity, 'high')
  assert.ok(findings[0].evidence.includes('evil.aimy.test'))
})

test('cors: Origin 反射但无凭据 → medium', async () => {
  const ctx = makeCtx((_url, init) => response({
    'access-control-allow-origin': init.headers?.origin ?? '',
  }))
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].checkId, 'cors-reflected-origin')
  assert.equal(findings[0].severity, 'medium')
})

test('cors: 通配 Origin + credentials → low（规范会拦截）', async () => {
  const ctx = makeCtx(() => response({
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  }))
  const findings = await run(ctx)
  assert.ok(findings.length >= 1)
  assert.ok(findings.every((finding) => finding.checkId === 'cors-wildcard-credentials'))
  assert.ok(findings.every((finding) => finding.severity === 'low'))
})

test('cors: null Origin 被接受 → medium', async () => {
  const ctx = makeCtx((_url, init) => response({
    'access-control-allow-origin': init.headers?.origin === 'null' ? 'null' : '',
  }))
  const findings = await run(ctx)
  assert.ok(findings.some((finding) => finding.checkId === 'cors-null-origin'))
})

test('cors: 请求数不超过 limits.maxRequests', async () => {
  const ctx = makeCtx((_url, init) => response({ 'access-control-allow-origin': init.headers?.origin ?? '*' }), { maxRequests: 2 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 2)
})

test('cors: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response({}), { onProbe: (_url, _init, controller) => controller.abort() })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('cors: meta 形状符合契约', () => {
  assert.equal(meta.id, 'cors')
  assert.equal(meta.cwe, 'CWE-942')
})

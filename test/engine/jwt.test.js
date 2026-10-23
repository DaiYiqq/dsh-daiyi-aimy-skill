/**
 * jwt 引擎模块测试：弱 HMAC 密钥、alg=none、缺 exp、正常不误报、请求上限、aborted。
 * 全部离线，token 由 node:crypto 在测试里生成。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { run, meta } from '../../lib/engine/jwt.js'

/**
 * @param {object} payload
 * @param {object} [header]
 * @param {string} [secret]
 * @returns {string}
 */
function makeToken(payload, header = { alg: 'HS256', typ: 'JWT' }, secret = 'secret') {
  const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const head = encode(header)
  const body = encode(payload)
  const signature = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url')
  return `${head}.${body}.${signature}`
}

/** @param {Record<string, string | string[]>} [headers] @param {string} [body] */
function response(headers = {}, body = '') {
  return {
    method: 'GET', url: 'https://target.test/', status: 200, headers, body,
    elapsedMs: 1, truncated: false,
  }
}

/**
 * @param {(url: string, init: object) => object} handler
 * @param {{ maxRequests?: number, onProbe?: Function }} [options]
 */
function makeCtx(handler, options = {}) {
  const calls = []
  const controller = new AbortController()
  const targetUrl = 'https://target.test/account'
  const url = new URL(targetUrl)
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

test('jwt: 页面无 JWT 不误报', async () => {
  const ctx = makeCtx(() => response({}, '<html><body>hello</body></html>'))
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('jwt: 弱 HMAC 密钥可离线校验 → 命中', async () => {
  const token = makeToken({ sub: 'admin', exp: 9999999999 })
  const ctx = makeCtx(() => response({}, `<html><script>window.__token="${token}"</script></html>`))
  const findings = await run(ctx)
  const weak = findings.find((finding) => finding.checkId === 'jwt-weak-secret')
  assert.ok(weak, '应命中 jwt-weak-secret')
  assert.equal(weak.severity, 'high')
  assert.equal(weak.confidence, 'high')
  assert.ok(weak.evidence.includes('secret'))
  assert.ok(weak.evidence.length <= 800)
})

test('jwt: alg=none 令牌 → 命中', async () => {
  const header = { alg: 'none', typ: 'JWT' }
  const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  const token = `${encode(header)}.${encode({ sub: 'admin', exp: 9999999999 })}.`
  const ctx = makeCtx(() => response({}, `<html>${token}</html>`))
  const findings = await run(ctx)
  assert.ok(findings.some((finding) => finding.checkId === 'jwt-alg-none'))
})

test('jwt: 强密钥且 claims 正常 → 不误报', async () => {
  const token = makeToken(
    { sub: 'user', exp: 9999999999 },
    { alg: 'HS256', typ: 'JWT' },
    'Zx9!this-is-a-long-random-secret-not-in-the-dictionary',
  )
  const ctx = makeCtx(() => response({}, `<html>${token}</html>`))
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('jwt: 缺少 exp → low 提示', async () => {
  const token = makeToken(
    { sub: 'user' },
    { alg: 'HS256', typ: 'JWT' },
    'Zx9!this-is-a-long-random-secret-not-in-the-dictionary',
  )
  const ctx = makeCtx(() => response({}, `<html>${token}</html>`))
  const findings = await run(ctx)
  assert.ok(findings.some((finding) => finding.checkId === 'jwt-missing-exp'))
})

test('jwt: 请求数不超过 limits.maxRequests', async () => {
  const token = makeToken({ sub: 'admin', exp: 9999999999 })
  const ctx = makeCtx(() => response({}, `<html>${token}</html>`), { maxRequests: 1 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 1)
})

test('jwt: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response({}, '<html></html>'), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('jwt: meta 形状符合契约', () => {
  assert.equal(meta.id, 'jwt')
  assert.equal(meta.minMode, 'rookie')
})

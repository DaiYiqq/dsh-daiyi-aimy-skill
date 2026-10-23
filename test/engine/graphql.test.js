/**
 * graphql 引擎模块测试：无端点不误报、introspection 命中、GET 查询、请求上限、aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/graphql.js'

/** @param {Record<string, string | string[]>} [headers] @param {string} [body] @param {number} [status] */
function response(body = '', headers = {}, status = 200) {
  return {
    method: 'GET', url: 'https://target.test/', status, headers, body,
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
      calls.push({ url: String(requestUrl), init })
      options.onProbe?.(String(requestUrl), init, controller)
      return handler(String(requestUrl), init)
    },
    calls,
    controller,
  }
}

test('graphql: 无 GraphQL 端点不误报', async () => {
  const ctx = makeCtx(() => response('not found', { 'content-type': 'text/plain' }, 404))
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('graphql: introspection 返回 schema → 命中', async () => {
  const ctx = makeCtx((requestUrl, init) => {
    const path = new URL(requestUrl).pathname
    if (path === '/graphql' && init.method === 'POST') {
      return response(JSON.stringify({ data: { __schema: { types: [{ name: 'Query' }, { name: 'User' }] } } }), { 'content-type': 'application/json' })
    }
    return response('not found', {}, 404)
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  const [finding] = findings
  assert.equal(finding.checkId, 'graphql-introspection')
  assert.equal(finding.severity, 'medium')
  assert.ok(finding.evidence.includes('/graphql'))
  assert.ok(finding.evidence.length <= 800)
})

test('graphql: 端点接受 GET 查询 → low 提示', async () => {
  const ctx = makeCtx((requestUrl, init) => {
    const parsed = new URL(requestUrl)
    if (parsed.pathname !== '/graphql') return response('not found', {}, 404)
    if (init.method === 'POST') {
      return response(JSON.stringify({ errors: [{ message: 'GraphQL introspection is disabled' }] }), { 'content-type': 'application/json' })
    }
    return response(JSON.stringify({ data: { __typename: 'Query' } }), { 'content-type': 'application/json' })
  }, { targetUrl: 'https://target.test/graphql' })
  const findings = await run(ctx)
  assert.ok(findings.some((finding) => finding.checkId === 'graphql-get-query'))
})

test('graphql: 请求数不超过 limits.maxRequests', async () => {
  const ctx = makeCtx(() => response('not found', {}, 404), { maxRequests: 1 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 1)
})

test('graphql: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response('not found', {}, 404), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('graphql: meta 形状符合契约', () => {
  assert.equal(meta.id, 'graphql')
})

/**
 * ssti 引擎模块测试：不误报、marker 被求值命中、请求上限、aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/ssti.js'

/** @param {Record<string, string | string[]>} [headers] @param {string} [body] @param {number} [status] */
function response(body = '', headers = {}, status = 200) {
  return {
    method: 'GET', url: 'https://target.test/', status, headers, body,
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
  const targetUrl = 'https://target.test/greet'
  const url = new URL(targetUrl)
  return {
    target: { url, origin: url.origin, host: url.hostname },
    params: [{ name: 'name', location: 'query', sample: 'world' }],
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

test('ssti: 原样回显表达式不误报', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('name') ?? ''
    return response(`<html><body>Hello ${value}</body></html>`)
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('ssti: marker 表达式被服务端求值 → 命中', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('name') ?? ''
    if (value.includes('{{7*7}}')) {
      return response('<html><body>Hello aimy133749</body></html>')
    }
    return response(`<html><body>Hello ${value}</body></html>`)
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  const [finding] = findings
  assert.equal(finding.checkId, 'ssti-eval')
  assert.equal(finding.param, 'name')
  assert.equal(finding.severity, 'high')
  assert.ok(finding.evidence.includes('aimy133749'))
  assert.ok(finding.evidence.length <= 800)
})

test('ssti: 请求数不超过 limits.maxRequests', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('name') ?? ''
    return response(`<html><body>${value}</body></html>`)
  }, { maxRequests: 2 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 2)
})

test('ssti: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response('<html></html>'), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('ssti: meta 形状符合契约', () => {
  assert.equal(meta.id, 'ssti')
  assert.equal(meta.cwe, 'CWE-94')
})

/**
 * tech-fingerprint 引擎模块测试：fingerprint() 导出形状、run() findings、无匹配、aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, fingerprint, meta } from '../../lib/engine/tech-fingerprint.js'

/** @param {Record<string, string | string[]>} [headers] @param {string} [body] */
function response(headers = {}, body = '<html><body>ok</body></html>') {
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
  const url = new URL('https://target.test/')
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

test('tech-fingerprint: fingerprint() 返回 [{name,confidence,evidence}]', async () => {
  const ctx = makeCtx(() => response({
    server: 'nginx/1.24.0',
    'x-powered-by': 'PHP/8.2.7',
    'set-cookie': 'PHPSESSID=abc123; path=/; HttpOnly',
  }))
  const items = await fingerprint(ctx)
  assert.ok(Array.isArray(items))
  assert.ok(items.length >= 2)
  for (const item of items) {
    assert.equal(typeof item.name, 'string')
    assert.ok(['low', 'medium', 'high'].includes(item.confidence))
    assert.equal(typeof item.evidence, 'string')
    assert.ok(item.evidence.length <= 800)
  }
  const names = items.map((item) => item.name)
  assert.ok(names.includes('nginx'))
  assert.ok(names.includes('PHP'))
  assert.equal(ctx.calls.length, 1)
})

test('tech-fingerprint: run() 返回指纹 finding + 版本泄露提示', async () => {
  const ctx = makeCtx(() => response({ server: 'nginx/1.24.0' }))
  const findings = await run(ctx)
  const ids = findings.map((finding) => finding.checkId)
  assert.ok(ids.includes('tech-fingerprint'))
  assert.ok(ids.includes('tech-version-disclosure'))
  assert.ok(findings.every((finding) => finding.evidence.length <= 800))
})

test('tech-fingerprint: 无特征不误报', async () => {
  const ctx = makeCtx(() => response({}, '<html><body>plain</body></html>'))
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
})

test('tech-fingerprint: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response({ server: 'nginx' }), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  const items = await fingerprint(ctx)
  assert.deepEqual(items, [])
})

test('tech-fingerprint: meta 形状符合契约', () => {
  assert.equal(meta.id, 'tech-fingerprint')
  assert.ok(meta.kinds.includes('recon'))
})

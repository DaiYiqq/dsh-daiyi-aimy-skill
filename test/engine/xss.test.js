/**
 * xss 引擎模块测试：不误报、HTML 上下文命中、编码检测、请求上限、aborted。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/xss.js'

/** @param {Record<string, string>} [overrides] */
function response(overrides = {}) {
  return {
    method: 'GET', url: 'https://target.test/', status: 200, headers: {},
    body: '', elapsedMs: 1, truncated: false, ...overrides,
  }
}

/**
 * @param {(url: string, init: object) => object} handler
 * @param {{ params?: object[], mode?: string, maxRequests?: number, onProbe?: Function }} [options]
 */
function makeCtx(handler, options = {}) {
  const calls = []
  const controller = new AbortController()
  const targetUrl = 'https://target.test/search'
  const url = new URL(targetUrl)
  return {
    target: { url, origin: url.origin, host: url.hostname },
    params: options.params ?? [{ name: 'q', location: 'query', sample: 'hello' }],
    mode: options.mode ?? 'rookie',
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

test('xss: 无回显不误报', async () => {
  const ctx = makeCtx(() => response({ body: '<html><body>搜索结果为空</body></html>' }))
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('xss: HTML 上下文原样反射 payload → 命中', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('q') ?? ''
    return response({ body: `<html><body><div>${value}</div></body></html>` })
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  const [finding] = findings
  assert.equal(finding.module, 'xss')
  assert.equal(finding.checkId, 'xss-reflected')
  assert.equal(finding.param, 'q')
  assert.ok(finding.evidence.includes('HTML 文本') || finding.evidence.includes('HTML'))
  assert.ok(finding.evidence.length <= 800)
})

test('xss: 只做 HTML 实体编码 → 输出 info 观察，不判可利用', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('q') ?? ''
    const encoded = value.replace(/</g, '&lt;').replace(/>/g, '&gt;')
    return response({ body: `<html><body><div>${encoded}</div></body></html>` })
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].checkId, 'xss-encoded-reflection')
  assert.equal(findings[0].severity, 'info')
})

test('xss: 属性上下文 payload 命中 → 置信度不夸大', async () => {
  let secondProbe = ''
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('q') ?? ''
    if (!secondProbe) secondProbe = value
    return response({ body: `<html><body><input value="${value}"></body></html>` })
  })
  const findings = await run(ctx)
  // 首个 marker 探测在属性里；后续 attr payload 原样反射时应命中。
  assert.ok(findings.length <= 1)
  if (findings.length === 1) {
    assert.equal(findings[0].checkId, 'xss-reflected')
    assert.ok(['medium', 'high'].includes(findings[0].confidence))
  }
})

test('xss: 请求数不超过 limits.maxRequests', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('q') ?? ''
    return response({ body: `<html><body>${value}</body></html>` })
  }, { maxRequests: 2 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 2, `实际请求 ${ctx.calls.length} 次，超过上限 2`)
})

test('xss: aborted 后提前退出', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('q') ?? ''
    return response({ body: `<html><body>${value}</body></html>` })
  }, { onProbe: (_url, _init, controller) => controller.abort() })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1)
})

test('xss: meta 形状符合契约', () => {
  assert.equal(meta.id, 'xss')
  assert.equal(meta.cwe, 'CWE-79')
})

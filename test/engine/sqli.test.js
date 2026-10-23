/**
 * sqli 引擎模块测试：正常不误报、错误型命中、布尔型命中、请求上限、aborted 提前退出。
 * 全部使用假 probe，不发真实网络请求。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { run, meta } from '../../lib/engine/sqli.js'

/**
 * @param {Record<string, string>} [overrides]
 */
function response(overrides = {}) {
  return {
    method: 'GET',
    url: 'https://target.test/',
    status: 200,
    headers: {},
    body: '',
    elapsedMs: 1,
    truncated: false,
    ...overrides,
  }
}

/**
 * 构造假 ProbeContext。
 * @param {(url: string, init: object) => object} handler
 * @param {{ params?: object[], mode?: string, maxRequests?: number, onProbe?: Function, targetUrl?: string }} [options]
 */
function makeCtx(handler, options = {}) {
  const calls = []
  const controller = new AbortController()
  const targetUrl = options.targetUrl ?? 'https://target.test/item'
  const url = new URL(targetUrl)
  const ctx = {
    target: { url, origin: url.origin, host: url.hostname },
    params: options.params ?? [{ name: 'id', location: 'query', sample: '1' }],
    mode: options.mode ?? 'rookie',
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
  return ctx
}

/** 正常页面：与注入无关。 */
function benignHandler() {
  return response({ body: `<html><body>${'正常内容 '.repeat(50)}</body></html>` })
}

test('sqli: 正常页面不误报', async () => {
  const ctx = makeCtx(benignHandler)
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
  assert.ok(ctx.calls.length > 0)
})

test('sqli: 两个不同数据库错误特征 → 错误型命中', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('id') ?? ''
    if (value.includes("'") || value.includes('"')) {
      return response({
        status: 500,
        body: `Warning: SQL syntax check near '"' MySQL<br>Unclosed quotation mark after the character string 'x'`,
      })
    }
    return benignHandler()
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  const [finding] = findings
  assert.equal(finding.module, 'sqli')
  assert.equal(finding.checkId, 'sqli-error')
  assert.equal(finding.param, 'id')
  assert.equal(finding.severity, 'high')
  assert.ok(finding.evidence.includes('mysql-syntax') || finding.evidence.includes('mssql-unclosed'))
  assert.ok(finding.evidence.length <= 800)
})

test('sqli: 单个错误特征不判定（保守）', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('id') ?? ''
    if (value.includes("'")) {
      return response({ status: 500, body: 'SQL syntax error near MySQL only one signature' })
    }
    return benignHandler()
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 0)
})

test('sqli: 真值接近基线、假值明显偏离 → 布尔型命中', async () => {
  const longBody = `<html><body>${'普通记录 '.repeat(80)}</body></html>`
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('id') ?? ''
    if (value.includes("'1'='2") || value.includes('"1"="2')) {
      return response({ body: '<html><body>无结果</body></html>' })
    }
    return response({ body: longBody })
  })
  const findings = await run(ctx)
  assert.equal(findings.length, 1)
  assert.equal(findings[0].checkId, 'sqli-boolean')
  assert.equal(findings[0].confidence, 'medium')
})

test('sqli: 请求数不超过 limits.maxRequests', async () => {
  const ctx = makeCtx((requestUrl) => {
    const value = new URL(requestUrl).searchParams.get('id') ?? ''
    return response({ body: value.includes("'") ? `<html>${'a'.repeat(300)}</html>` : `<html>${'b'.repeat(100)}</html>` })
  }, { maxRequests: 3 })
  const findings = await run(ctx)
  assert.ok(Array.isArray(findings))
  assert.ok(ctx.calls.length <= 3, `实际请求 ${ctx.calls.length} 次，超过上限 3`)
})

test('sqli: aborted 后提前退出', async () => {
  const ctx = makeCtx(benignHandler, {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const findings = await run(ctx)
  assert.deepEqual(findings, [])
  assert.ok(ctx.calls.length <= 1, `aborted 后仍发了 ${ctx.calls.length} 次请求`)
})

test('sqli: meta 形状符合契约', () => {
  assert.equal(meta.id, 'sqli')
  assert.ok(Array.isArray(meta.kinds) && meta.kinds.includes('sqli'))
  assert.equal(meta.cwe, 'CWE-89')
  assert.ok(['rookie', 'veteran'].includes(meta.minMode))
})

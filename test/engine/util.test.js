/**
 * util 公共层测试：参数拼装、同源判断、稳定排序、相似度、请求预算与取消、Finding 裁剪。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import {
  withParam, sameOrigin, stableSort, similarity, createSession, makeFinding,
  isInternalHost, clipText, EVIDENCE_MAX, setQueryParam, decodeHtmlEntities,
  referenceTimeFromHeaders, safeJsonParse,
} from '../../lib/engine/util.js'

/** @param {Record<string, unknown>} [overrides] */
function response(overrides = {}) {
  return {
    method: 'GET', url: 'https://target.test/', status: 200, headers: {}, body: '',
    elapsedMs: 1, truncated: false, ...overrides,
  }
}

test('util.withParam: query/body/json 三种位置', () => {
  const query = withParam('https://target.test/search?x=1', 'q', 'a b', 'query')
  assert.equal(new URL(query.url).searchParams.get('q'), 'a b')
  assert.equal(new URL(query.url).searchParams.get('x'), '1')
  assert.equal(query.init, undefined)

  const body = withParam('https://target.test/form', 'name', 'a b', 'body')
  assert.equal(body.url, 'https://target.test/form')
  assert.equal(body.init.method, 'POST')
  assert.equal(body.init.body, 'name=a%20b')

  const json = withParam('https://target.test/api', 'id', { $ne: '' }, 'json')
  assert.equal(json.init.method, 'POST')
  assert.deepEqual(JSON.parse(json.init.body), { id: { $ne: '' } })
})

test('util.sameOrigin: 同源/跨源/端口差异', () => {
  assert.equal(sameOrigin('https://a.test/x', 'https://a.test/y'), true)
  assert.equal(sameOrigin('https://a.test/x', 'http://a.test/y'), false)
  assert.equal(sameOrigin('https://a.test:444/x', 'https://a.test/y'), false)
  assert.equal(sameOrigin('bad url', 'https://a.test'), false)
})

test('util.stableSort: 按 key 排序且相同 key 保持原顺序', () => {
  const items = [
    { id: 'b', order: 2 },
    { id: 'a', order: 1 },
    { id: 'c', order: 1 },
  ]
  const sorted = stableSort(items, (item) => item.order)
  assert.deepEqual(sorted.map((item) => item.id), ['a', 'c', 'b'])
  assert.equal(items[0].id, 'b', '不应修改入参顺序')
})

test('util.similarity: 相同为 1，差异明显更低', () => {
  const base = '<html><body>hello world this is a page</body></html>'
  assert.equal(similarity(base, base), 1)
  const other = '<html><body>完全不同的错误页面</body></html>'
  assert.ok(similarity(base, other) < 0.5)
})

test('util.createSession: 请求预算生效且超过后返回 null', async () => {
  let count = 0
  const ctx = {
    target: { url: new URL('https://target.test/'), origin: 'https://target.test', host: 'target.test' },
    params: [],
    mode: 'rookie',
    authorized: true,
    signal: new AbortController().signal,
    log: () => {},
    limits: { timeoutMs: 1000, maxRequests: 2, maxBodyBytes: 1024 },
    probe: async () => {
      count += 1
      return response()
    },
  }
  const session = createSession(ctx)
  assert.equal(session.maxRequests, 2)
  const first = await session.probe('https://target.test/1')
  const second = await session.probe('https://target.test/2')
  const third = await session.probe('https://target.test/3')
  assert.ok(first !== null && second !== null)
  assert.equal(third, null)
  assert.equal(count, 2)
  assert.equal(session.used, 2)
})

test('util.createSession: aborted 后不再请求', async () => {
  const controller = new AbortController()
  let count = 0
  const ctx = {
    target: { url: new URL('https://target.test/'), origin: 'https://target.test', host: 'target.test' },
    params: [],
    mode: 'rookie',
    authorized: true,
    signal: controller.signal,
    log: () => {},
    limits: { timeoutMs: 1000, maxRequests: 10, maxBodyBytes: 1024 },
    probe: async () => {
      count += 1
      controller.abort()
      return response()
    },
  }
  const session = createSession(ctx)
  const first = await session.probe('https://target.test/1')
  assert.equal(first, null)
  const second = await session.probe('https://target.test/2')
  assert.equal(second, null)
  assert.equal(count, 1)
  assert.equal(session.aborted, true)
})

test('util.createSession: 预算/取消类全局异常向上抛出', async () => {
  const error = Object.assign(new Error('budget'), { code: 'BUDGET_EXCEEDED' })
  const ctx = {
    target: { url: new URL('https://target.test/'), origin: 'https://target.test', host: 'target.test' },
    params: [],
    mode: 'rookie',
    authorized: true,
    signal: new AbortController().signal,
    log: () => {},
    limits: { timeoutMs: 1000, maxRequests: 5, maxBodyBytes: 1024 },
    probe: async () => {
      throw error
    },
  }
  const session = createSession(ctx)
  await assert.rejects(() => session.probe('https://target.test/'), /budget/)
})

test('util.makeFinding: evidence 截断到 800 字符且保留契约字段', () => {
  const finding = makeFinding({
    module: 'sqli',
    checkId: 'sqli-error',
    title: 'test',
    severity: 'high',
    confidence: 'high',
    url: 'https://target.test/',
    param: 'id',
    payload: "x".repeat(500),
    evidence: 'e'.repeat(2000),
  })
  assert.equal(finding.module, 'sqli')
  assert.equal(finding.checkId, 'sqli-error')
  assert.equal(finding.evidence.length, EVIDENCE_MAX)
  assert.ok(finding.payload.length <= 200)
})

test('util.isInternalHost: 回环/私网/公网判断', () => {
  for (const host of ['127.0.0.1', 'localhost', '10.1.2.3', '192.168.1.1', '172.16.0.1', '169.254.169.254', '::1']) {
    assert.equal(isInternalHost(host), true, host)
  }
  for (const host of ['example.com', '8.8.8.8', '203.0.113.5']) {
    assert.equal(isInternalHost(host), false, host)
  }
})

test('util 其他纯函数：clipText/setQueryParam/decodeHtmlEntities/safeJsonParse/参考时间', () => {
  assert.equal(clipText('abcdef', 4), 'a...')
  assert.equal(new URL(setQueryParam('https://a.test/?a=1', 'b', '2')).searchParams.get('b'), '2')
  assert.equal(decodeHtmlEntities('&lt;img&gt;&#39;x&#39;&quot;'), '<img>\'x\'"')
  assert.deepEqual(safeJsonParse('{"a":1}'), { a: 1 })
  assert.equal(safeJsonParse('{bad'), null)
  const reference = referenceTimeFromHeaders(response({ headers: { date: 'Thu, 01 Jan 2026 00:00:00 GMT' } }))
  assert.equal(reference, Date.parse('Thu, 01 Jan 2026 00:00:00 GMT'))
  assert.equal(referenceTimeFromHeaders(response()), null)
})

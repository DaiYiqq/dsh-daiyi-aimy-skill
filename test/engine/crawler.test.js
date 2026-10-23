/**
 * crawler 引擎模块测试：同源 BFS、深度/页数上限、表单与参数提取、JS 端点、run() 敏感端点提示。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { crawl, run, meta } from '../../lib/engine/crawler.js'

/** @param {string} body @param {Record<string, string | string[]>} [headers] @param {number} [status] */
function response(body = '', headers = {}, status = 200) {
  return {
    method: 'GET', url: 'https://target.test/', status, headers, body,
    elapsedMs: 1, truncated: false,
  }
}

/**
 * @param {(url: string, init: object) => { status: number, body: string, headers: object, url?: string }} handler
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
      const urlString = String(requestUrl)
      calls.push(urlString)
      options.onProbe?.(urlString, init, controller)
      const result = handler(urlString, init)
      return { ...result, url: result.url ?? urlString }
    },
    calls,
    controller,
  }
}

const ROOT_HTML = `
<html><head><title>首页</title></head><body>
  <a href="/a?x=1">a</a>
  <a href="https://other.test/page">external</a>
  <a href="/style.css">css</a>
  <form action="/login" method="post">
    <input name="username">
    <input name="password" type="password">
    <input type="submit" name="submit">
  </form>
  <script>fetch('/api/users')</script>
</body></html>`

const PAGE_A = '<html><head><title>页面 A</title></head><body><a href="/b">b</a></body></html>'

test('crawler: 同源 BFS 提取链接/表单/参数/JS 端点', async () => {
  const ctx = makeCtx((urlString) => {
    const path = new URL(urlString).pathname
    if (path === '/') return response(ROOT_HTML)
    if (path === '/a') return response(PAGE_A)
    if (path === '/login') return response('<html>login</html>')
    return response('<html>ok</html>')
  })
  const result = await crawl(ctx, { maxPages: 5, maxDepth: 1, includeForms: true, includeJs: true })

  assert.equal(result.pages.length, 2, '根页 + /a 两页')
  assert.ok(result.urls.some((url) => url.endsWith('/a?x=1')))
  assert.equal(result.urls.some((url) => url.includes('other.test')), false, '不应爬取非同源链接')
  assert.equal(result.urls.some((url) => url.includes('style.css')), false, '不应爬取静态资源')

  assert.equal(result.forms.length, 1)
  assert.equal(result.forms[0].action.endsWith('/login'), true)
  assert.equal(result.forms[0].method, 'POST')
  assert.ok(result.forms[0].inputs.includes('username'))
  assert.equal(result.forms[0].inputs.includes('submit'), false, '提交按钮不应当作参数')

  const paramKeys = result.params.map((param) => `${param.name}:${param.location}`)
  assert.ok(paramKeys.includes('x:query'))
  assert.ok(paramKeys.includes('username:body'))
  assert.ok(paramKeys.includes('password:body'))

  assert.ok(result.jsEndpoints.some((endpoint) => endpoint.endsWith('/api/users')))
  assert.ok(result.requests >= 1 && result.requests <= ctx.limits.maxRequests)
})

test('crawler: maxDepth=0 只抓根页', async () => {
  const ctx = makeCtx(() => response(ROOT_HTML))
  const result = await crawl(ctx, { maxDepth: 0, maxPages: 5 })
  assert.equal(result.pages.length, 1)
})

test('crawler: maxPages 限制生效', async () => {
  const ctx = makeCtx((urlString) => response(urlString === 'https://target.test/' ? ROOT_HTML : PAGE_A))
  const result = await crawl(ctx, { maxPages: 1, maxDepth: 2 })
  assert.equal(result.pages.length, 1)
})

test('crawler: 遵守 limits.maxRequests', async () => {
  const ctx = makeCtx(() => response(ROOT_HTML), { maxRequests: 1 })
  const result = await crawl(ctx, { maxPages: 10, maxDepth: 2 })
  assert.ok(result.requests <= 1)
  assert.equal(result.pages.length, 1)
})

test('crawler: aborted 后提前退出', async () => {
  const ctx = makeCtx(() => response(ROOT_HTML), {
    onProbe: (_url, _init, controller) => controller.abort(),
  })
  const result = await crawl(ctx, { maxPages: 5, maxDepth: 2 })
  assert.ok(result.requests <= 1)
  assert.equal(result.pages.length, 0)
})

test('crawler: run() 把爬到的敏感端点作为低置信提示', async () => {
  const ctx = makeCtx((urlString) => {
    const path = new URL(urlString).pathname
    if (path === '/') {
      return response('<html><body><a href="/.git/HEAD">git</a><a href="/.env">env</a></body></html>')
    }
    return response('<html>ok</html>')
  })
  const findings = await run(ctx)
  assert.ok(findings.length >= 2)
  assert.ok(findings.every((finding) => finding.checkId === 'crawler-risky-endpoint'))
  assert.ok(findings.every((finding) => finding.confidence === 'low'))
})

test('crawler: meta 形状符合契约', () => {
  assert.equal(meta.id, 'crawler')
  assert.equal(typeof crawl, 'function')
})

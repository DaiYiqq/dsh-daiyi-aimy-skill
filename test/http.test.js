import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { BudgetError, CancelledError, ProbeClient, ScopeError, mapLimit } from '../lib/http.js'
import { ScopeStore } from '../lib/scope.js'
import { normalizeConfig } from '../lib/config.js'

/**
 * 起一个本地测试服务器（仅回环，仅测试用）。
 * @returns {Promise<{ server: http.Server, base: string, close: () => Promise<void> }>}
 */
async function startServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/ok') {
      res.writeHead(200, { 'content-type': 'text/plain', 'x-test': 'yes' })
      res.end('hello aimy')
      return
    }
    if (url.pathname === '/big') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('A'.repeat(4096))
      return
    }
    if (url.pathname === '/redirect') {
      res.writeHead(302, { location: '/ok' })
      res.end()
      return
    }
    if (url.pathname === '/redirect-out') {
      res.writeHead(302, { location: 'http://not-in-scope.test/' })
      res.end()
      return
    }
    if (url.pathname === '/slow') {
      setTimeout(() => {
        res.writeHead(200)
        res.end('slow')
      }, 400)
      return
    }
    res.writeHead(404)
    res.end('nope')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = /** @type {{ port: number }} */ (server.address())
  return {
    server,
    base: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}

/**
 * @param {Record<string, unknown>} [overrides]
 * @returns {Promise<{ client: ProbeClient, scope: ScopeStore }>}
 */
async function makeClient(overrides = {}) {
  const scope = new ScopeStore({ persist: false, allowPrivateNetworks: true })
  await scope.add({ target: '127.0.0.1', authorization: '本地单元测试靶场 127.0.0.1' })
  const { config } = normalizeConfig({ allowPrivateNetworks: true, timeoutMs: 2000, ...overrides })
  return { client: new ProbeClient({ scope, config }), scope }
}

test('HTTP：正常请求返回状态/头/体/耗时', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient()
    const response = await client.request(`${server.base}/ok`)
    assert.equal(response.status, 200)
    assert.equal(response.body, 'hello aimy')
    assert.equal(response.headers['x-test'], 'yes')
    assert.equal(response.headers['content-type'], 'text/plain')
    assert.ok(response.elapsedMs >= 0)
    assert.equal(response.truncated, false)
    assert.equal(client.requestCount, 1)
  } finally {
    await server.close()
  }
})

test('HTTP：范围外目标抛 ScopeError，且不计入请求预算', async () => {
  const { client } = await makeClient()
  await assert.rejects(() => client.request('http://93.184.216.34/'), (error) => {
    assert.ok(error instanceof ScopeError)
    assert.ok(['SCOPE_DENIED', 'NO_MATCH', 'NO_SCOPE'].includes(error.code), `unexpected code ${error.code}`)
    assert.match(error.message, /不在授权范围内|没有任何授权范围/)
    return true
  })
  assert.equal(client.requestCount, 0)
})

test('HTTP：没有登记范围时一律拒绝', async () => {
  const emptyScope = new ScopeStore({ persist: false })
  const { config } = normalizeConfig({})
  const client = new ProbeClient({ scope: emptyScope, config })
  await assert.rejects(() => client.request('http://127.0.0.1/'), /没有任何授权范围/)
})

test('HTTP：响应体按 maxBodyBytes 截断', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient({ maxBodyBytes: 64 })
    const response = await client.request(`${server.base}/big`)
    assert.equal(response.status, 200)
    assert.equal(response.truncated, true)
    assert.ok(Buffer.byteLength(response.body) <= 64)
  } finally {
    await server.close()
  }
})

test('HTTP：超过请求预算抛 BudgetError', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient({ maxRequests: 1 })
    await client.request(`${server.base}/ok`)
    await assert.rejects(() => client.request(`${server.base}/ok`), (error) => {
      assert.ok(error instanceof BudgetError)
      assert.equal(error.code, 'BUDGET_EXCEEDED')
      return true
    })
  } finally {
    await server.close()
  }
})

test('HTTP：默认不跟随重定向，开启后在同源内跟随', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient()
    const manual = await client.request(`${server.base}/redirect`)
    assert.equal(manual.status, 302)
    assert.equal(manual.headers.location, '/ok')

    const followed = await client.request(`${server.base}/redirect`, { followRedirects: true })
    assert.equal(followed.status, 200)
    assert.equal(followed.body, 'hello aimy')
    assert.equal(followed.url, `${server.base}/ok`)
  } finally {
    await server.close()
  }
})

test('HTTP：跨主机重定向被拒绝，防止被带出授权范围', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient()
    const response = await client.request(`${server.base}/redirect-out`, { followRedirects: true })
    assert.equal(response.status, 302)
    assert.match(String(response.error), /重定向目标被拒绝/)
  } finally {
    await server.close()
  }
})

test('HTTP：超时返回 status=0 与错误说明，而不是抛异常', async () => {
  const server = await startServer()
  try {
    const { client } = await makeClient({ timeoutMs: 60 })
    const response = await client.request(`${server.base}/slow`)
    assert.equal(response.status, 0)
    assert.match(String(response.error), /超时/)
  } finally {
    await server.close()
  }
})

test('HTTP：外部取消信号抛 CancelledError', async () => {
  const server = await startServer()
  try {
    const controller = new AbortController()
    const scope = new ScopeStore({ persist: false, allowPrivateNetworks: true })
    await scope.add({ target: '127.0.0.1', authorization: '本地单元测试靶场 127.0.0.1' })
    const { config } = normalizeConfig({ allowPrivateNetworks: true, timeoutMs: 2000 })
    const client = new ProbeClient({ scope, config, signal: controller.signal })
    controller.abort()
    await assert.rejects(() => client.request(`${server.base}/ok`), (error) => {
      assert.ok(error instanceof CancelledError)
      return true
    })
  } finally {
    await server.close()
  }
})

test('HTTP：method/body 与 UA 头生效', async () => {
  const seen = { method: '', ua: '', body: '' }
  const server = http.createServer((req, res) => {
    seen.method = req.method ?? ''
    seen.ua = String(req.headers['user-agent'] ?? '')
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
    })
    req.on('end', () => {
      seen.body = data
      res.writeHead(201)
      res.end('created')
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = /** @type {{ port: number }} */ (server.address()).port
  try {
    const { client } = await makeClient()
    const response = await client.request(`http://127.0.0.1:${port}/submit`, {
      method: 'POST',
      body: 'a=1&b=2',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    })
    assert.equal(response.status, 201)
    assert.equal(seen.method, 'POST')
    assert.equal(seen.body, 'a=1&b=2')
    assert.match(seen.ua, /dsh-daiyi-aimy-skill/)
  } finally {
    await new Promise((resolve) => server.close(() => resolve()))
  }
})

test('mapLimit：受控并发且保序', async () => {
  let active = 0
  let peak = 0
  const items = Array.from({ length: 12 }, (_, index) => index)
  const results = await mapLimit(items, 3, async (item) => {
    active += 1
    peak = Math.max(peak, active)
    await new Promise((resolve) => setTimeout(resolve, 5))
    active -= 1
    return item * 2
  })
  assert.deepEqual(results, items.map((item) => item * 2))
  assert.ok(peak <= 3, `并发峰值 ${peak} 应不超过 3`)
  assert.ok(peak >= 2, '应真的并发执行')
})

test('mapLimit：worker 抛错时整体失败并停止调度', async () => {
  const items = Array.from({ length: 8 }, (_, index) => index)
  let calls = 0
  await assert.rejects(
    () =>
      mapLimit(items, 2, async (item) => {
        calls += 1
        if (item === 2) throw new Error('boom')
        return item
      }),
    /boom/,
  )
  assert.ok(calls < items.length, `失败后应停止调度，实际调用 ${calls}`)
})

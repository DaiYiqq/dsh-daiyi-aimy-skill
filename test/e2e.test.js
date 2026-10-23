/**
 * 端到端集成测试：起一个本地靶场，用**真实宿主 defineTool** 加载插件，
 * 然后把 8 个工具里的 6 个真正跑一遍（scope/recon/crawl/dir_fuzz/web_scan/port_scan/report）。
 *
 * 只在能解析到宿主 `@deepseek-ai/dsh-tools` 的开发机上执行，CI 上自动 skip。
 * 网络目标全部是 127.0.0.1 临时端口，属于回环靶场，不接触外网。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'

import { describeUnavailable, loadDshTools } from './helpers/dsh-tools.mjs'

const host = await loadDshTools()
const hostAvailable = host.ok === true
const plugin = hostAvailable ? await import('../lib/index.js') : null
const skipReason = hostAvailable ? false : describeUnavailable(host)

const PAGE = `<!doctype html><html><head><title>Aimy Test Range</title></head>
<body><h1>range</h1>
<a href="/login">login</a> <a href="/admin">admin</a> <a href="/api/users">api</a>
<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
</body></html>`

/**
 * 起本地靶场。
 * @returns {Promise<{ base: string, port: number, close: () => Promise<void> }>}
 */
async function startRange() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.18.0', 'x-powered-by': 'Express' })
      res.end(PAGE)
      return
    }
    if (url.pathname === '/item') {
      const value = url.searchParams.get('id') ?? ''
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(`<html><body><div>id=${value}</div><p>you searched ${value}</p></body></html>`)
      return
    }
    if (url.pathname === '/login') {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<html><body>login form</body></html>')
      return
    }
    if (url.pathname === '/admin') {
      res.writeHead(403, { 'content-type': 'text/html' })
      res.end('<html><body>forbidden</body></html>')
      return
    }
    if (url.pathname === '/api/users') {
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' })
      res.end(JSON.stringify({ users: [] }))
      return
    }
    res.writeHead(404, { 'content-type': 'text/html' })
    res.end('<html><body>not found</body></html>')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = /** @type {{ port: number }} */ (server.address()).port
  return {
    base: `http://127.0.0.1:${port}`,
    port,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}

/**
 * @param {Record<string, unknown>} [config]
 * @returns {Promise<{ byName: Record<string, any>, exec: { signal: AbortSignal } }>}
 */
async function mount(config = {}) {
  const tools = []
  const ctx = {
    tools: { register: (tool) => tools.push(tool) },
    skills: { register: () => {} },
    logger: () => ({ debug: () => {}, info: () => {}, warn: () => {} }),
  }
  await plugin.apply(ctx, {
    mode: 'rookie',
    persistScope: false,
    allowPrivateNetworks: true,
    maxRequests: 80,
    timeoutMs: 4000,
    ...config,
  })
  return {
    byName: Object.fromEntries(tools.map((tool) => [tool.name, tool])),
    exec: { signal: new AbortController().signal },
  }
}

test('端到端：侦察 → 爬取 → 目录 → 漏洞检测 → 端口 → 报告', { skip: skipReason }, async () => {
  const range = await startRange()
  try {
    const { byName, exec } = await mount()
    const added = await byName.aimy_scope.execute(
      { action: 'add', target: '127.0.0.1', authorization: '本地 e2e 靶场 127.0.0.1' },
      exec,
    )
    assert.equal(added.ok, true)

    // 侦察：HTTP 基线 + 指纹 + 安全响应头
    const recon = await byName.aimy_recon.execute({ target: range.base, checks: ['http', 'headers', 'tech', 'robots'] }, exec)
    assert.equal(recon.http.status, 200)
    assert.match(String(recon.http.title), /Aimy Test Range/)
    assert.ok(recon.requests >= 2)
    assert.ok(Array.isArray(recon.tech))
    assert.ok(recon.tech.some((entry) => /nginx|express/i.test(entry.name)), '应识别出 nginx/express 之一')
    assert.ok(
      recon.findings.some((finding) => finding.module === 'headers'),
      '应产出安全响应头缺失类 finding',
    )

    // 爬取：页面/表单/参数
    const crawl = await byName.aimy_crawl.execute({ target: range.base, maxPages: 6, maxDepth: 2 }, exec)
    assert.ok(crawl.pages.length >= 2, `应抓到多个页面，实际 ${crawl.pages.length}`)
    assert.ok(crawl.forms.length >= 1, '应解析出表单')
    assert.ok(crawl.params.some((param) => param.name === 'username'), '应发现表单参数')

    // 目录枚举
    const dir = await byName.aimy_dir_fuzz.execute(
      { target: range.base, wordlist: ['admin', 'login', 'api/users', 'aimy-not-exist'], maxPaths: 12 },
      exec,
    )
    assert.ok(dir.tested >= 4)
    const paths = dir.found.map((entry) => entry.path)
    assert.ok(paths.includes('/admin'), '/admin 应命中 403')
    assert.ok(paths.includes('/api/users'), '/api/users 应命中 200')
    assert.ok(!paths.includes('/aimy-not-exist'), '不存在的路径不应命中')

    // Web 检测：XSS 反射 + 响应头
    const scan = await byName.aimy_web_scan.execute(
      {
        target: `${range.base}/item?id=1`,
        checks: ['xss', 'cors', 'headers'],
        params: [{ name: 'id', location: 'query', sample: '1' }],
      },
      exec,
    )
    assert.equal(scan.skipped.length, 0, `不应有被跳过的检查：${JSON.stringify(scan.skipped)}`)
    const modules = scan.findings.map((finding) => finding.module)
    assert.ok(modules.includes('xss'), `应检出反射型 XSS，实际模块：${modules.join(',')}`)
    assert.ok(scan.requests >= 4)

    // 端口探测（目标就是刚才的临时端口）
    const ports = await byName.aimy_port_scan.execute(
      { target: '127.0.0.1', ports: [range.port, 1], timeoutMs: 900 },
      exec,
    )
    assert.deepEqual(ports.open.map((entry) => entry.port).filter((port) => port === range.port), [range.port])

    // 报告
    const summary = await byName.aimy_report.execute({ action: 'summary' }, exec)
    assert.ok(summary.counts.total >= 2)
    const markdown = await byName.aimy_report.execute({ action: 'report', format: 'md' }, exec)
    assert.match(markdown.content, /授权安全检测报告/)
    const sarif = await byName.aimy_report.execute({ action: 'report', format: 'sarif' }, exec)
    assert.equal(JSON.parse(sarif.content).runs[0].results.length, summary.counts.total)
  } finally {
    await range.close()
  }
})

test('端到端：rookie 模式不跑时间盲注，范围外请求被拒绝', { skip: skipReason }, async () => {
  const range = await startRange()
  try {
    const { byName, exec } = await mount({ mode: 'rookie' })
    await assert.rejects(
      () => byName.aimy_crawl.execute({ target: range.base, maxPages: 2 }, exec),
      /没有任何授权范围/,
      '未登记范围时必须拒绝',
    )
    await byName.aimy_scope.execute({ action: 'add', target: '127.0.0.1', authorization: '本地 e2e 靶场 127.0.0.1' }, exec)
    const scan = await byName.aimy_web_scan.execute(
      { target: `${range.base}/item?id=1`, checks: ['sqli'], params: [{ name: 'id', location: 'query', sample: '1' }] },
      exec,
    )
    // rookie 模式下时间盲注不应产生 confirmed finding
    assert.ok(
      scan.findings.every((finding) => finding.checkId !== 'sqli-time-based'),
      'rookie 模式不应执行时间盲注',
    )
  } finally {
    await range.close()
  }
})

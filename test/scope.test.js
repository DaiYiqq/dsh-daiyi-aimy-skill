import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

import {
  ScopeStore,
  classifyAddress,
  describeScope,
  effectivePort,
  isIPv4,
  parseScopeTarget,
  toUrl,
} from '../lib/scope.js'

const AUTH = '客户授权函 #A-1024，范围 example.com'

test('parseScopeTarget：裸域名 / 端口 / 协议 / 路径 / 通配', () => {
  assert.deepEqual(parseScopeTarget('example.com'), {
    target: 'example.com',
    host: 'example.com',
    port: null,
    scheme: null,
    pathPrefix: null,
    wildcard: false,
  })
  assert.equal(parseScopeTarget('example.com:8443').port, 8443)
  assert.equal(parseScopeTarget('https://example.com/app').scheme, 'https')
  assert.equal(parseScopeTarget('https://example.com/app').pathPrefix, '/app')
  assert.equal(parseScopeTarget('*.example.com').wildcard, true)
  assert.equal(parseScopeTarget('*.example.com').host, 'example.com')
  assert.equal(parseScopeTarget('[::1]:8080').host, '::1')
  assert.equal(parseScopeTarget('[::1]:8080').port, 8080)
})

test('parseScopeTarget：拒绝非法输入', () => {
  // 注意 `example.com/app` 是合法写法（主机 + 路径前缀），不在此列
  for (const bad of ['', '   ', '*', 'exa mple.com', 'user:pass@example.com', '*.', 'a*b.com']) {
    assert.throws(() => parseScopeTarget(bad), /./, `应拒绝 ${JSON.stringify(bad)}`)
  }
  assert.throws(() => parseScopeTarget('example.com:0'), /端口非法/)
  assert.throws(() => parseScopeTarget('example.com:99999'), /端口非法/)
})

test('classifyAddress 与 isIPv4', () => {
  assert.equal(isIPv4('10.1.2.3'), true)
  assert.equal(isIPv4('10.1.2'), false)
  assert.equal(classifyAddress('127.0.0.1'), 'loopback')
  assert.equal(classifyAddress('localhost'), 'loopback')
  assert.equal(classifyAddress('10.2.3.4'), 'private')
  assert.equal(classifyAddress('172.20.0.1'), 'private')
  assert.equal(classifyAddress('192.168.1.1'), 'private')
  assert.equal(classifyAddress('169.254.1.1'), 'link-local')
  assert.equal(classifyAddress('224.0.0.1'), 'multicast')
  assert.equal(classifyAddress('0.0.0.0'), 'reserved')
  assert.equal(classifyAddress('8.8.8.8'), 'public')
  assert.equal(classifyAddress('::1'), 'loopback')
  assert.equal(classifyAddress('fe80::1'), 'link-local')
  assert.equal(classifyAddress('fd00::1'), 'private')
})

test('effectivePort / toUrl / describeScope 基础行为', () => {
  assert.equal(effectivePort(new URL('https://example.com/x')), 443)
  assert.equal(effectivePort(new URL('http://example.com:8080/x')), 8080)
  assert.equal(toUrl('example.com').href, 'http://example.com/')
  assert.equal(toUrl('https://a.test', 'https').href, 'https://a.test/')
  assert.match(describeScope([]), /空/)
  assert.match(
    describeScope([{ target: 'example.com', authorization: AUTH, expired: false, wildcard: false }]),
    /example\.com · 客户授权函/,
  )
})

test('deny-by-default：没有任何范围时拒绝一切目标', async () => {
  const store = new ScopeStore({ persist: false })
  const verdict = store.check('https://example.com/')
  assert.equal(verdict.ok, false)
  assert.equal(verdict.code, 'NO_SCOPE')
})

test('登记、匹配与范围语义（精确 / 通配 / 端口 / 路径 / 协议）', async () => {
  const store = new ScopeStore({ persist: false })
  const added = await store.add({ target: 'example.com', authorization: AUTH })
  assert.equal(added.ok, true)
  assert.equal(store.check('https://example.com/').ok, true)
  assert.equal(store.check('http://example.com:8080/x').ok, true)

  const wildcard = await store.add({ target: '*.example.org', authorization: 'CTF 靶场 example.org' })
  assert.equal(wildcard.ok, true)
  assert.equal(store.check('https://a.example.org/').ok, true)
  assert.equal(store.check('https://a.b.example.org/').ok, true)
  assert.equal(store.check('https://example.org/').ok, false, '通配不匹配 apex')

  const scoped = new ScopeStore({ persist: false })
  await scoped.add({ target: 'https://api.example.net/v1', authorization: '内部授权：api.example.net v1 联调' })
  assert.equal(scoped.check('https://api.example.net/v1/users').ok, true)
  assert.equal(scoped.check('https://api.example.net/v2/users').ok, false)
  assert.equal(scoped.check('http://api.example.net/v1/users').ok, false, '登记了 https 就不放行 http')

  const portStore = new ScopeStore({ persist: false })
  await portStore.add({ target: 'example.io:8443', authorization: '授权：example.io 8443 管理口' })
  assert.equal(portStore.check('https://example.io:8443/x').ok, true)
  assert.equal(portStore.check('https://example.io/x').ok, false)
})

test('authorization 太短或缺失时拒绝登记', async () => {
  const store = new ScopeStore({ persist: false })
  const short = await store.add({ target: 'example.com', authorization: '测试' })
  assert.equal(short.ok, false)
  assert.match(short.error, /至少/)
  const empty = await store.add({ target: 'example.com', authorization: '' })
  assert.equal(empty.ok, false)
})

test('回环与内网地址默认拒绝，显式开启后才能登记', async () => {
  const strict = new ScopeStore({ persist: false })
  const blocked = await strict.add({ target: '127.0.0.1', authorization: '本地 DVWA 靶场 127.0.0.1' })
  assert.equal(blocked.ok, false)
  assert.match(blocked.error, /allowPrivateNetworks/)

  const loose = new ScopeStore({ persist: false, allowPrivateNetworks: true })
  const allowed = await loose.add({ target: '127.0.0.1', authorization: '本地 DVWA 靶场 127.0.0.1' })
  assert.equal(allowed.ok, true)
  assert.equal(loose.check('http://127.0.0.1:8080/login').ok, true)

  // 即使登记了，check 也要拦住组播/保留地址
  const verdict = loose.check('http://224.0.0.1/')
  assert.equal(verdict.ok, false)
})

test('过期范围不再放行', async () => {
  let now = Date.parse('2026-01-01T00:00:00.000Z')
  const store = new ScopeStore({ persist: false, now: () => now })
  const added = await store.add({ target: 'example.com', authorization: '短期演练授权 example.com', expiresInHours: 1 })
  assert.equal(added.ok, true)
  assert.equal(store.check('https://example.com/').ok, true)
  now += 2 * 3600 * 1000
  const verdict = store.check('https://example.com/')
  assert.equal(verdict.ok, false)
  assert.equal(verdict.code, 'EXPIRED')
})

test('列出 / 移除 / 清空', async () => {
  const store = new ScopeStore({ persist: false })
  await store.add({ target: 'a.example.com', authorization: '授权 A：a.example.com 演练' })
  await store.add({ target: 'b.example.com', authorization: '授权 B：b.example.com 演练' })
  assert.equal(store.list().length, 2)

  const removed = store.remove('a.example.com')
  assert.equal(removed.ok, true)
  assert.equal(store.list().length, 1)
  assert.equal(store.remove('not-there.test').ok, false)
  assert.equal(store.clear(), 1)
  assert.equal(store.list().length, 0)
})

test('磁盘持久化：add 后 save，重新创建仍能读到', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'aimy-scope-'))
  const file = path.join(dir, 'nested', 'scope.json')
  try {
    const store = await ScopeStore.create({ file, persist: true })
    const added = await store.add({ target: 'example.com', authorization: '持久化测试授权 example.com' })
    assert.equal(added.ok, true)
    assert.equal(await store.save(), null)

    const raw = JSON.parse(await readFile(file, 'utf8'))
    assert.equal(raw.version, 1)
    assert.equal(raw.entries.length, 1)

    const reopened = await ScopeStore.create({ file, persist: true })
    assert.equal(reopened.list().length, 1)
    assert.equal(reopened.list()[0].target, 'example.com')
    assert.equal(reopened.check('https://example.com/').ok, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('存储文件损坏时按空范围启动并记录 loadError', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'aimy-scope-bad-'))
  const file = path.join(dir, 'scope.json')
  try {
    const { writeFile } = await import('node:fs/promises')
    await writeFile(file, '{ not json', 'utf8')
    const store = await ScopeStore.create({ file, persist: true })
    assert.equal(store.list().length, 0)
    assert.notEqual(store.loadError, null)
    assert.equal(store.check('https://example.com/').ok, false)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('审计日志记录 add/remove/clear', async () => {
  const store = new ScopeStore({ persist: false })
  await store.add({ target: 'example.com', authorization: '审计测试授权 example.com' })
  store.remove('example.com')
  store.clear()
  const actions = store.auditLog.map((entry) => entry.action)
  assert.ok(actions.includes('scope.add'))
  assert.ok(actions.includes('scope.remove'))
  assert.ok(actions.includes('scope.clear'))
})

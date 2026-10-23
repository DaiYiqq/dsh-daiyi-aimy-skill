/**
 * 插件级行为测试：用宿主**真实**的 `defineTool` 挂载插件并执行工具。
 *
 * 与 test/contract/*（纯契约断言）互补：这里验证的是"装上以后真的能干活"——
 * 工具注册数、授权闸门、JWT 审计、报告导出、以及服务缺失时的降级行为。
 *
 * 宿主实现不可用（没有 DSH 运行时、也没解包源码）时整体 skip，不把环境缺失判成失败。
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { createHmac } from 'node:crypto'

import { describeUnavailable, loadDshTools } from './helpers/dsh-tools.mjs'

const host = await loadDshTools()
const hostAvailable = host.ok === true
const plugin = hostAvailable ? await import('../lib/index.js') : null
const skipReason = hostAvailable ? false : describeUnavailable(host)

/**
 * 构造假 Cordis ctx，收集注册结果。
 * @returns {{ ctx: object, tools: object[], skills: object[], logs: string[] }}
 */
function makeCtx() {
  const tools = []
  const skills = []
  const logs = []
  const record = (level) => (message) => logs.push(`${level}:${String(message)}`)
  return {
    tools,
    skills,
    logs,
    ctx: {
      tools: { register: (tool) => tools.push(tool) },
      skills: { register: (skill) => skills.push(skill) },
      logger: () => ({ debug: record('debug'), info: record('info'), warn: record('warn') }),
    },
  }
}

/**
 * @param {Record<string, unknown>} [config]
 * @returns {Promise<{ tools: object[], skills: object[], logs: string[], byName: Record<string, any> }>}
 */
async function mount(config = {}) {
  const { ctx, tools, skills, logs } = makeCtx()
  await plugin.apply(ctx, { mode: 'veteran', persistScope: false, allowPrivateNetworks: true, ...config })
  return { tools, skills, logs, byName: Object.fromEntries(tools.map((tool) => [tool.name, tool])) }
}

const exec = { signal: new AbortController().signal }

test('apply：注册 8 个工具与 8 个技能，且不抛异常', { skip: skipReason }, async () => {
  const { tools, skills, logs } = await mount()
  assert.equal(tools.length, 8)
  assert.equal(skills.length, 8)
  assert.equal(plugin.name, 'daiyi-aimy-skill')
  assert.deepEqual(plugin.inject, ['tools', 'skills'])
  assert.ok(logs.some((line) => line.startsWith('info:') && line.includes('工具 8 个')))
})

test('apply：重复挂载与缺少服务时都降级而不抛错', { skip: skipReason }, async () => {
  const first = await mount()
  const second = await mount()
  assert.equal(first.tools.length, second.tools.length)

  const bare = {}
  await plugin.apply(bare, { persistScope: false })
  const emptyCtx = { tools: undefined, skills: undefined }
  await plugin.apply(emptyCtx, { persistScope: false })
  await plugin.apply({ tools: { register: () => { throw new Error('boom') } }, skills: { register: () => { throw new Error('boom') } }, logger: () => ({ warn: () => {}, info: () => {}, debug: () => {} }) }, { persistScope: false })
})

test('工具定义：命名规范、参数/输出 schema 已被宿主编译', { skip: skipReason }, async () => {
  const { tools } = await mount()
  const names = tools.map((tool) => tool.name)
  assert.deepEqual(names, [
    'aimy_scope',
    'aimy_recon',
    'aimy_port_scan',
    'aimy_dir_fuzz',
    'aimy_crawl',
    'aimy_web_scan',
    'aimy_jwt_audit',
    'aimy_report',
  ])
  assert.equal(new Set(names).size, names.length)
  for (const tool of tools) {
    assert.match(tool.name, /^aimy_[a-z0-9_]+$/, `${tool.name} 命名不规范`)
    assert.equal(typeof tool.description, 'string')
    assert.ok(tool.description.length > 10, `${tool.name} 描述过短`)
    assert.equal(tool.parameters.type, 'object')
    assert.equal(typeof tool.parameters.properties, 'object')
    assert.equal(tool.output.schema.type, 'object')
    assert.equal(typeof tool.execute, 'function')
    assert.equal(typeof tool.presentCall, 'function')
    // required 只能出现在真的必填上
    for (const [param, schema] of Object.entries(tool.parameters.properties)) {
      if (schema.required !== undefined) assert.equal(schema.required, true, `${tool.name}.${param} required 只能为 true 或缺省`)
    }
    const rendered = tool.output.render({}, buildSampleOutput(tool.name))
    assert.ok(Array.isArray(rendered))
    assert.equal(rendered[0].type, 'text')
    assert.equal(typeof rendered[0].text, 'string')
  }
})

test('aimy_scope：登记后放行，范围外一律拒绝', { skip: skipReason }, async () => {
  const { byName } = await mount()
  const rejected = await byName.aimy_recon.execute({ target: 'http://example.com/', checks: ['http'] }, exec).then(
    () => null,
    (error) => error,
  )
  assert.ok(rejected instanceof Error, '未登记范围时应拒绝')
  assert.match(rejected.message, /没有任何授权范围/)

  const added = await byName.aimy_scope.execute(
    { action: 'add', target: '127.0.0.1', authorization: '本地回归测试 127.0.0.1' },
    exec,
  )
  assert.equal(added.ok, true)
  assert.equal(added.entries.length, 1)

  const check = await byName.aimy_scope.execute({ action: 'check', target: 'http://127.0.0.1:8080/login' }, exec)
  assert.equal(check.check.ok, true)

  const outside = await byName.aimy_scope.execute({ action: 'check', target: 'https://example.com/' }, exec)
  assert.equal(outside.check.ok, false)
  assert.equal(outside.check.code, 'NO_MATCH')

  const tooShort = await byName.aimy_scope.execute({ action: 'add', target: 'example.com', authorization: '测试' }, exec)
  assert.equal(tooShort.ok, false)

  const list = await byName.aimy_scope.execute({ action: 'list' }, exec)
  assert.equal(list.entries.length, 1)
  const cleared = await byName.aimy_scope.execute({ action: 'clear' }, exec)
  assert.equal(cleared.entries.length, 0)
})

test('aimy_jwt_audit：识别弱 HMAC 密钥与 alg=none', { skip: skipReason }, async () => {
  const { byName } = await mount()
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const head = b64({ alg: 'HS256', typ: 'JWT' })
  const body = b64({ sub: '1', role: 'admin', iat: 1700000000, exp: Math.floor(Date.now() / 1000) + 3600 })
  const sig = createHmac('sha256', 'secret').update(`${head}.${body}`).digest('base64url')
  const result = await byName.aimy_jwt_audit.execute({ token: `${head}.${body}.${sig}` }, exec)
  assert.equal(result.crackedSecret, 'secret')
  assert.ok(result.issues.some((issue) => issue.checkId === 'jwt-weak-hmac-secret'))
  assert.ok(result.issues.some((issue) => issue.checkId === 'jwt-client-readable-authorization'))
  assert.match(result.summary, /发现/)

  const noneHead = b64({ alg: 'none', typ: 'JWT' })
  const none = await byName.aimy_jwt_audit.execute({ token: `${noneHead}.${body}.` }, exec)
  assert.ok(none.issues.some((issue) => issue.checkId === 'jwt-alg-none'))

  await assert.rejects(() => byName.aimy_jwt_audit.execute({ token: 'not-a-jwt' }, exec), /不是合法 JWT/)
})

test('aimy_report：summary / md / sarif / 写文件 / 清空', { skip: skipReason }, async () => {
  const { byName } = await mount()
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const head = b64({ alg: 'HS256' })
  const body = b64({ sub: '1', exp: 1 })
  await byName.aimy_jwt_audit.execute({ token: `${head}.${body}.` }, exec)

  const summary = await byName.aimy_report.execute({ action: 'summary' }, exec)
  assert.ok(summary.counts.total >= 1)
  assert.match(summary.summary, /./)

  const md = await byName.aimy_report.execute({ action: 'report', format: 'md' }, exec)
  assert.match(md.content, /授权安全检测报告/)

  const sarif = await byName.aimy_report.execute({ action: 'report', format: 'sarif' }, exec)
  assert.equal(JSON.parse(sarif.content).version, '2.1.0')

  const findings = await byName.aimy_report.execute({ action: 'findings', severity: ['critical', 'high', 'medium', 'low', 'info'] }, exec)
  assert.ok(Array.isArray(findings.findings))

  const dir = await mkdtemp(path.join(tmpdir(), 'aimy-report-'))
  try {
    const target = path.join(dir, 'nested', 'report.md')
    const written = await byName.aimy_report.execute({ action: 'report', format: 'md', outputPath: target }, exec)
    assert.equal(written.written, true)
    assert.equal(written.path, target)
    const text = await readFile(target, 'utf8')
    assert.match(text, /授权安全检测报告/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }

  const cleared = await byName.aimy_report.execute({ action: 'clear' }, exec)
  assert.equal(cleared.counts.total, 0)
})

test('技能注册：name/description/content/invocation 完整', { skip: skipReason }, async () => {
  const { skills } = await mount()
  for (const skill of skills) {
    assert.match(skill.name, /^aimy-[a-z0-9-]+$/)
    assert.ok(skill.description.length > 10)
    assert.ok(skill.content.length > 200, `${skill.name} 正文过短`)
    assert.deepEqual(skill.invocation, { modelInvocable: true, userInvocable: true })
  }
  assert.equal(new Set(skills.map((skill) => skill.name)).size, skills.length)
})

/**
 * 给 output.render 提供最小可渲染样本，确保渲染函数不会对空对象抛错。
 * @param {string} toolName
 * @returns {object}
 */
function buildSampleOutput(toolName) {
  switch (toolName) {
    case 'aimy_scope':
      return { action: 'list', ok: true, entries: [], message: '空' }
    case 'aimy_recon':
      return { target: {}, checks: [], findings: [], requests: 0 }
    case 'aimy_port_scan':
      return { target: 'x', ports: [], open: [], findings: [], requests: 0 }
    case 'aimy_dir_fuzz':
      return { target: 'x', tested: 0, found: [], findings: [], requests: 0 }
    case 'aimy_crawl':
      return { target: 'x', pages: [], urls: [], forms: [], params: [], jsEndpoints: [], findings: [], requests: 0 }
    case 'aimy_web_scan':
      return { target: 'x', checks: [], skipped: [], params: [], findings: [], requests: 0 }
    case 'aimy_jwt_audit':
      return { header: {}, payload: {}, issues: [], summary: 'ok', recommendations: [] }
    case 'aimy_report':
      return { action: 'summary', format: 'md', counts: {}, summary: 'ok' }
    default:
      return {}
  }
}

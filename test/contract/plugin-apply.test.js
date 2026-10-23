/**
 * 契约测试：插件入口 `apply(ctx, config)` 的注册行为。
 *
 * 用 test/helpers/fake-ctx.mjs 构造的假 Cordis 上下文，断言：
 *   - `lib/index.js` 导出 name/inject/apply/default；
 *   - `apply(fakeCtx, {})` 不抛异常，注册 8 个工具、8 个技能；
 *   - 同一 ctx 上重复 apply 不抛异常（真实工具注册表对重名会抛错，插件必须自行吞掉）；
 *   - 宿主缺少 tools 或 skills 服务时也不抛异常（CONTRACT.md §0）。
 *
 * 需要真实 `defineTool`（lib/tools/define.js 的裸说明符由 import map 指到宿主实现），
 * 因此宿主不可用时整组 skip。
 *
 * @module test/contract/plugin-apply
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

import { REPO_ROOT, describeUnavailable, loadDshTools } from '../helpers/dsh-tools.mjs'
import { createFakeCtx } from '../helpers/fake-ctx.mjs'
import { assertRegisteredSkill, assertToolDefinition, findDuplicateNames } from '../helpers/tool-assertions.mjs'

/** 契约：插件向宿主注册的工具/技能数量。 */
const EXPECTED_TOOL_COUNT = 8
const EXPECTED_SKILL_COUNT = 8

const host = await loadDshTools()
const hostSkip = host.ok ? false : describeUnavailable(host)

const pluginIndexFile = path.join(REPO_ROOT, 'lib', 'index.js')
const pluginIndexSkip = !existsSync(pluginIndexFile) ? `未找到 ${pluginIndexFile}（lib/index.js 尚未完成）` : false
const fixturePluginFile = path.join(REPO_ROOT, 'test', 'helpers', 'fixtures', 'plugin-minimal.mjs')

test('fake-ctx 复刻真实宿主的关键失败语义', async () => {
  const fake = createFakeCtx()
  const definition = {
    name: 'aimy_unit_test',
    description: '单元测试用',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'object' }, render: () => '' },
    async execute() { return {} },
  }
  const dispose = fake.ctx.tools.register(definition)
  assert.equal(fake.tools.length, 1)
  assert.equal(fake.ctx.tools.has('aimy_unit_test'), true)
  // 真实 ToolRuntime 对同层重名会抛错，假 ctx 必须一致。
  assert.throws(() => fake.ctx.tools.register(definition), /already registered/)
  // 缺 output.render 的定义在真实注册表里也会被拒绝。
  assert.throws(() => fake.ctx.tools.register({ name: 'aimy_bad', output: {} }), /output \{ schema, render \}/)

  fake.ctx.skills.register({ name: 'aimy-unit-skill', description: 'd', content: 'c' })
  // 技能重名：warn + 不抛错（与 @deepseek-ai/dsh-skill 一致）。
  fake.ctx.skills.register({ name: 'aimy-unit-skill', description: 'd', content: 'c' })
  assert.equal(fake.skills.length, 1)
  assert.ok(fake.logs.some((entry) => entry.level === 'warn' && entry.message.includes('already registered')))

  // 两种 logger 形态都要兼容（真实 Cordis 是 ctx.logger(name) 函数形态）。
  fake.ctx.logger('scope-a').warn('函数形态')
  fake.ctx.logger.warn('对象形态')
  assert.ok(fake.logs.some((entry) => entry.message === '函数形态'))
  assert.ok(fake.logs.some((entry) => entry.message === '对象形态'))

  // disposer 生效
  dispose()
  assert.equal(fake.tools.length, 0)
  await fake.ctx.dispose()
})

test('夹具插件：apply 注册 2 工具 2 技能，重复 apply 不抛错', { skip: hostSkip }, async () => {
  const fixture = await import(pathToFileURL(fixturePluginFile).href)
  const fake = createFakeCtx()
  await fixture.apply(fake.ctx, {})
  assert.equal(fake.tools.length, 2)
  assert.equal(fake.skills.length, 2)
  await assert.doesNotReject(() => fixture.apply(fake.ctx, {}))
  assert.equal(fake.tools.length, 2, '重复 apply 不应重复注册工具')
  assert.equal(fake.skills.length, 2, '重复 apply 不应重复注册技能')
})

test('lib/index.js 导出 Cordis 插件契约（name/inject/apply/default）', {
  skip: hostSkip || pluginIndexSkip,
}, async () => {
  const plugin = await import(pathToFileURL(pluginIndexFile).href)
  assert.equal(plugin.name, 'daiyi-aimy-skill')
  assert.ok(Array.isArray(plugin.inject), 'inject 必须是数组')
  assert.ok(plugin.inject.includes('tools'), "inject 必须包含 'tools'")
  assert.ok(plugin.inject.includes('skills'), "inject 必须包含 'skills'")
  assert.equal(typeof plugin.apply, 'function', 'apply 必须是函数')
  assert.equal(plugin.default, plugin.apply, 'default 导出必须就是 apply')
})

test(`apply(fakeCtx, {}) 不抛错并注册 ${EXPECTED_TOOL_COUNT} 工具 / ${EXPECTED_SKILL_COUNT} 技能`, {
  skip: hostSkip || pluginIndexSkip,
}, async (t) => {
  // 隔离 DSH_HOME，避免读写测试者真实的 ~/.dsh 授权范围文件。
  const dshHome = mkdtempSync(path.join(os.tmpdir(), 'aimy-contract-home-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = dshHome
  t.after(() => {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    rmSync(dshHome, { recursive: true, force: true })
  })

  const plugin = await import(pathToFileURL(pluginIndexFile).href)
  const fake = createFakeCtx()
  await assert.doesNotReject(() => plugin.apply(fake.ctx, {}), 'apply 必须永不抛错')

  t.diagnostic(`注册工具：${fake.tools.map((tool) => tool.name).join(', ') || '(none)'}`)
  t.diagnostic(`注册技能：${fake.skills.map((skill) => skill.name).join(', ') || '(none)'}`)

  assert.equal(fake.tools.length, EXPECTED_TOOL_COUNT, `应注册 ${EXPECTED_TOOL_COUNT} 个工具，实际 ${fake.tools.length}`)
  assert.equal(fake.skills.length, EXPECTED_SKILL_COUNT, `应注册 ${EXPECTED_SKILL_COUNT} 个技能，实际 ${fake.skills.length}`)
  assert.deepEqual(findDuplicateNames(fake.tools), [], '工具名必须唯一')
  assert.deepEqual(findDuplicateNames(fake.skills), [], '技能名必须唯一')

  // 注册定义必须仍然是真实 defineTool 结果（schema 合法、错误参数被拒绝）。
  const toolFailures = []
  for (let index = 0; index < fake.tools.length; index += 1) {
    try {
      await assertToolDefinition(fake.tools[index], host, { index })
    } catch (error) {
      toolFailures.push(`- ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  assert.deepEqual(toolFailures, [], `注册的工具定义未通过真实 defineTool 校验：\n${toolFailures.join('\n')}`)

  for (let index = 0; index < fake.skills.length; index += 1) {
    assertRegisteredSkill(fake.skills[index], { index })
  }

  const registeredNames = fake.tools.map((tool) => tool.name).sort()
  assert.deepEqual(registeredNames, [
    'aimy_crawl',
    'aimy_dir_fuzz',
    'aimy_jwt_audit',
    'aimy_port_scan',
    'aimy_recon',
    'aimy_report',
    'aimy_scope',
    'aimy_web_scan',
  ], '工具名必须与 CONTRACT/任务清单一致')

  assert.ok(fake.logs.some((entry) => entry.level === 'info'), 'apply 结束应输出一条 info 汇总日志')

  // 重复 apply：真实工具注册表对重名抛错，插件必须自行 catch + warn，整体不抛。
  const logsBefore = fake.logs.length
  await assert.doesNotReject(() => plugin.apply(fake.ctx, {}), '重复 apply 也不能抛异常')
  assert.equal(fake.tools.length, EXPECTED_TOOL_COUNT, '重复 apply 后工具数不应变化')
  assert.equal(fake.skills.length, EXPECTED_SKILL_COUNT, '重复 apply 后技能数不应变化')
  const newWarnings = fake.logs.slice(logsBefore).filter((entry) => entry.level === 'warn')
  assert.ok(newWarnings.length > 0, '重复注册被宿主拒绝时应记录 warn（暴露注册失败而不是静默）')
})

test('宿主缺少 tools 服务时 apply 不抛错（技能仍注册）', {
  skip: hostSkip || pluginIndexSkip,
}, async () => {
  const plugin = await import(pathToFileURL(pluginIndexFile).href)
  const fake = createFakeCtx()
  fake.ctx.tools = undefined
  await assert.doesNotReject(() => plugin.apply(fake.ctx, { persistScope: false }))
  assert.equal(fake.skills.length, EXPECTED_SKILL_COUNT, '缺 tools 服务时技能仍应注册')
})

test('宿主缺少 skills 服务时 apply 不抛错（工具仍注册）', {
  skip: hostSkip || pluginIndexSkip,
}, async () => {
  const plugin = await import(pathToFileURL(pluginIndexFile).href)
  const fake = createFakeCtx()
  fake.ctx.skills = undefined
  await assert.doesNotReject(() => plugin.apply(fake.ctx, { persistScope: false }))
  assert.equal(fake.tools.length, EXPECTED_TOOL_COUNT, '缺 skills 服务时工具仍应注册')
})

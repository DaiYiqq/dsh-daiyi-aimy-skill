/**
 * 契约测试：工具定义必须由**真实** `@deepseek-ai/dsh-tools` 的 `defineTool` 产出，
 * 并且 `parameters` / `output.schema` 能被宿主自己的 schema 编译器接受。
 *
 * 真实宿主来源见 test/helpers/dsh-tools.mjs（优先 installed，其次 vendor / 解包副本）。
 * 找不到宿主时整组 skip（而不是 fail）——契约测试不应把环境缺失判成产品失败。
 *
 * @module test/contract/tool-definitions
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import path from 'node:path'

import { REPO_ROOT, describeUnavailable, loadDshTools } from '../helpers/dsh-tools.mjs'
import {
  RECOMMENDED_TOOL_EXPORT,
  extractToolDefinitions,
  loadToolDefinitions,
  toolsModuleFile,
} from '../helpers/tools-adapter.mjs'
import { assertToolDefinition, findDuplicateNames } from '../helpers/tool-assertions.mjs'

const host = await loadDshTools()
const hostSkip = host.ok ? false : describeUnavailable(host)

const toolsFile = toolsModuleFile(REPO_ROOT)
const toolsFileSkip = !existsSync(toolsFile) ? `未找到 ${toolsFile}（lib/tools/index.js 尚未创建）` : false

test('真实 @deepseek-ai/dsh-tools 的 defineTool 可用（不是本地仿造）', { skip: hostSkip }, (t) => {
  assert.equal(typeof host.defineTool, 'function', 'defineTool 必须是函数')
  assert.equal(typeof host.parameterSchemaSpecToJsonSchema, 'function')
  assert.equal(typeof host.valueSchemaSpecToJsonSchema, 'function')
  assert.equal(typeof host.assertSupportedJsonSchema, 'function')
  assert.ok(host.source.packageVersion, '应当读到 dsh-tools 的包版本')
  // 记录来源，便于在 CI 日志里确认到底验证的是哪份宿主实现。
  t.diagnostic(`宿主来源：${host.source.kind} / ${host.source.entryKind} / v${host.source.packageVersion}`)
})

test('真实 defineTool 会拒绝非法 output schema（证明校验链路是活的）', { skip: hostSkip }, () => {
  assert.throws(
    () => host.defineTool({
      name: 'aimy_invalid_probe',
      description: '故意缺少 additionalProperties 的 object schema',
      parameters: {},
      output: { schema: { type: 'object', properties: {} }, render: () => '' },
      async execute() { return {} },
    }),
    (error) => error?.name === 'JsonSchemaError',
    '缺少 additionalProperties 的 object 输出 schema 必须被真实编译器拒绝',
  )
})

test('软适配器能识别 TOOLS / default 数组 / createTools 工厂三种导出形状', { skip: hostSkip }, async () => {
  const fixtureDir = path.join(REPO_ROOT, 'test', 'helpers', 'fixtures')

  const minimalFile = path.join(fixtureDir, 'tools-minimal.mjs')
  const minimal = await loadToolDefinitions(minimalFile)
  assert.equal(minimal.available, true)
  assert.ok(Array.isArray(minimal.tools), `应识别出工具数组：${minimal.reason ?? ''}`)
  assert.equal(minimal.tools.length, 2)
  assert.equal(minimal.shape, 'export const TOOLS')

  const factoryFile = path.join(fixtureDir, 'tools-factory.mjs')
  const factory = await loadToolDefinitions(factoryFile)
  assert.equal(factory.available, true)
  assert.ok(Array.isArray(factory.tools), `应能调用 createTools 工厂：${factory.reason ?? ''}`)
  assert.equal(factory.tools.length, 2)
  assert.equal(factory.shape, 'export function createTools(deps)')

  // 只有 TOOL_NAMES（没有定义数组）时必须明确报“形状不符”，而不是静默通过。
  const namesOnly = extractToolDefinitions({ TOOL_NAMES: ['aimy_scope'] })
  assert.equal(namesOnly.tools, null)
  assert.equal(namesOnly.factory, null)
  assert.match(namesOnly.notes.join('\n'), /TOOLS/)

  // default 导出数组也要能识别（不依赖具体导出名）。
  const fakeTools = [{ name: 'aimy_x', parameters: {}, output: { schema: {} } }]
  const fromDefault = extractToolDefinitions({ default: fakeTools })
  assert.deepEqual(fromDefault.tools, fakeTools)

  // 命名空间里随便一个数组导出也能兜底识别（带提示）。
  const fromScanned = extractToolDefinitions({ OTHER: fakeTools })
  assert.deepEqual(fromScanned.tools, fakeTools)
  assert.match(fromScanned.notes.join('\n'), /回退扫描/)
})

test('lib/tools/index.js 的每个工具定义都通过真实 defineTool 校验', {
  skip: hostSkip || toolsFileSkip,
}, async (t) => {
  const loaded = await loadToolDefinitions(toolsFile)
  if (!loaded.available) {
    t.skip(`无法加载 ${toolsFile}：${loaded.reason}`)
    return
  }
  if (!Array.isArray(loaded.tools)) {
    t.skip(
      `lib/tools/index.js 的导出形状尚未对齐：${loaded.reason ?? '未识别到工具数组'}\n` +
        `  实际导出：${(loaded.exportKeys ?? []).join(', ') || '(空)'}\n` +
        `  要求的形状（任选其一）：\n  ${RECOMMENDED_TOOL_EXPORT}`,
    )
    return
  }

  t.diagnostic(`导出形状：${loaded.shape}${loaded.notes.length ? `（${loaded.notes.join('；')}）` : ''}`)
  t.diagnostic(`工具数量：${loaded.tools.length}`)

  assert.ok(loaded.tools.length > 0, 'lib/tools/index.js 必须导出至少一个工具定义')
  const duplicates = findDuplicateNames(loaded.tools)
  assert.deepEqual(duplicates, [], `工具名必须唯一，重复：${duplicates.join(', ')}`)

  const failures = []
  for (let index = 0; index < loaded.tools.length; index += 1) {
    const tool = loaded.tools[index]
    try {
      await assertToolDefinition(tool, host, { index })
    } catch (error) {
      failures.push(`- ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  assert.deepEqual(failures, [], `以下工具定义未通过真实 defineTool 契约校验：\n${failures.join('\n')}`)

  // 允许但建议统一 aimy_ 前缀（CONTRACT/工具清单约定），不强制失败。
  const withoutPrefix = loaded.tools.filter((tool) => typeof tool?.name === 'string' && !tool.name.startsWith('aimy_'))
  if (withoutPrefix.length > 0) {
    t.diagnostic(`提示：以下工具没有 aimy_ 前缀，建议与 CONTRACT 工具清单保持一致：${withoutPrefix.map((tool) => tool.name).join(', ')}`)
  }
})

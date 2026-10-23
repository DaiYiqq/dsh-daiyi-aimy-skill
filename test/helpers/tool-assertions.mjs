/**
 * 工具/技能定义的共享断言。
 *
 * 关键点：这些断言基于**真实** `@deepseek-ai/dsh-tools` 的 schema 编译器
 * （`assertSupportedJsonSchema`）与 `defineTool` 的运行时行为（非法参数必须被
 * execute 包装层拒绝），而不是自己复刻一份 JSON Schema 子集校验。
 *
 * @module test/helpers/tool-assertions
 */
import assert from 'node:assert/strict'

/** 工具名：snake_case（首字符小写字母，后续小写字母/数字，下划线分段）。 */
export const TOOL_NAME_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/

/** 技能名：kebab-case（CONTRACT.md §3）。 */
export const SKILL_NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

/** 把工具定义压成一句可读标签，便于断言失败时定位。 */
function toolLabel(tool, fallback) {
  if (tool !== null && typeof tool === 'object' && typeof tool.name === 'string' && tool.name.length > 0) return tool.name
  return fallback
}

/**
 * 校验一个工具定义是真实 `defineTool` 结果并且 schema 合法。
 *
 * @param {object} tool 工具定义
 * @param {object} host loadDshTools() 的成功结果（提供 assertSupportedJsonSchema）
 * @param {{index?: number}} [meta]
 */
export async function assertToolDefinition(tool, host, meta = {}) {
  const fallback = `tools[${meta.index ?? '?'}]`
  const label = toolLabel(tool, fallback)
  assert.equal(typeof tool, 'object', `${fallback} 必须是对象，实际 ${typeof tool}`)
  assert.notEqual(tool, null, `${fallback} 不能为 null`)
  assert.equal(typeof tool.name, 'string', `${fallback} 缺少字符串 name`)
  assert.match(tool.name, TOOL_NAME_PATTERN, `工具名 "${label}" 必须是 snake_case（实际 ${JSON.stringify(tool.name)}）`)
  assert.equal(typeof tool.description, 'string', `工具 "${label}" 缺少字符串 description`)
  assert.ok(tool.description.trim().length > 0, `工具 "${label}" 的 description 不能为空`)

  // defineTool 把 parameters 编译成 object-rooted raw JSON Schema。
  assert.equal(typeof tool.parameters, 'object', `工具 "${label}" 缺少 parameters`)
  assert.notEqual(tool.parameters, null, `工具 "${label}" 的 parameters 不能为 null`)
  assert.equal(tool.parameters.type, 'object', `工具 "${label}" 的 parameters 根类型必须是 object`)
  host.assertSupportedJsonSchema(tool.parameters)

  assert.equal(typeof tool.output, 'object', `工具 "${label}" 缺少 output`)
  assert.notEqual(tool.output, null, `工具 "${label}" 的 output 不能为 null`)
  assert.equal(typeof tool.output.schema, 'object', `工具 "${label}" 缺少 output.schema`)
  assert.notEqual(tool.output.schema, null, `工具 "${label}" 的 output.schema 不能为 null`)
  host.assertSupportedJsonSchema(tool.output.schema)
  assert.equal(typeof tool.output.render, 'function', `工具 "${label}" 的 output.render 必须是函数`)
  if (tool.output.presentationMeta !== undefined) {
    assert.equal(typeof tool.output.presentationMeta, 'function', `工具 "${label}" 的 output.presentationMeta 必须是函数`)
  }

  assert.equal(typeof tool.execute, 'function', `工具 "${label}" 的 execute 必须是函数`)

  // presentCall / presentResult / isConcurrencySafe 由 defineTool 包装：非法参数软失败。
  for (const callbackName of ['presentCall', 'presentResult', 'isConcurrencySafe']) {
    const callback = tool[callbackName]
    if (callback === undefined) continue
    assert.equal(typeof callback, 'function', `工具 "${label}" 的 ${callbackName} 必须是函数`)
    if (callbackName === 'isConcurrencySafe') {
      assert.equal(callback(null), false, `工具 "${label}" 的 isConcurrencySafe(非法参数) 必须返回 false`)
    } else {
      const softResult = callbackName === 'presentCall' ? callback(null) : callback(null, null)
      assert.equal(softResult, undefined, `工具 "${label}" 的 ${callbackName}(非法参数) 必须软失败返回 undefined（不能抛错）`)
    }
  }

  // execute 包装层必须拒绝非法参数（证明定义真的经过 defineTool，而不是手写对象）。
  await assert.rejects(
    () => tool.execute(null, {}),
    (error) => {
      assert.equal(error?.code, 'INVALID_ARGS', `工具 "${label}" 的非法参数错误码应为 INVALID_ARGS，实际 ${JSON.stringify(error?.code)}`)
      return true
    },
    `工具 "${label}" 的 execute 必须拒绝非法参数`,
  )

  // 编译产物必须可 JSON 序列化（宿主会把它写进模型工具清单）。
  JSON.stringify(tool.parameters)
  JSON.stringify(tool.output.schema)
}

/**
 * 校验一个已注册技能定义（`ctx.skills.register({...})` 的入参）。
 *
 * @param {object} skill
 * @param {{index?: number, expectAimyPrefix?: boolean}} [meta]
 */
export function assertRegisteredSkill(skill, meta = {}) {
  const fallback = `skills[${meta.index ?? '?'}]`
  assert.equal(typeof skill, 'object', `${fallback} 必须是对象`)
  assert.notEqual(skill, null, `${fallback} 不能为 null`)
  assert.equal(typeof skill.name, 'string', `${fallback} 缺少字符串 name`)
  assert.match(skill.name, SKILL_NAME_PATTERN, `技能名 "${skill.name}" 必须是 kebab-case`)
  if (meta.expectAimyPrefix !== false) {
    assert.ok(skill.name.startsWith('aimy-'), `技能名 "${skill.name}" 必须以 aimy- 开头（CONTRACT.md §3）`)
  }
  assert.equal(typeof skill.description, 'string', `技能 "${skill.name}" 缺少字符串 description`)
  assert.ok(skill.description.trim().length > 0, `技能 "${skill.name}" 的 description 不能为空`)
  assert.equal(typeof skill.content, 'string', `技能 "${skill.name}" 缺少字符串 content`)
  assert.ok(skill.content.trim().length > 0, `技能 "${skill.name}" 的 content 不能为空`)
  if (skill.whenToUse !== undefined) {
    assert.equal(typeof skill.whenToUse, 'string', `技能 "${skill.name}" 的 whenToUse 必须是字符串`)
  }
  if (skill.invocation !== undefined) {
    assert.equal(typeof skill.invocation, 'object', `技能 "${skill.name}" 的 invocation 必须是对象`)
    assert.notEqual(skill.invocation, null, `技能 "${skill.name}" 的 invocation 不能为 null`)
  }
}

/** 断言名字集合唯一，返回重复项列表。 */
export function findDuplicateNames(items) {
  const seen = new Set()
  const duplicates = new Set()
  for (const item of items) {
    const name = item?.name
    if (typeof name !== 'string') continue
    if (seen.has(name)) duplicates.add(name)
    else seen.add(name)
  }
  return [...duplicates]
}

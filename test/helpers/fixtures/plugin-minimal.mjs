/**
 * 测试夹具：一个最小可用的 Cordis 插件，用来验证 fake-ctx 与 apply 契约测试脚手架
 * 本身是对的（与 lib/index.js 无关）。
 *
 * 注意：
 *   - 夹具刻意模仿 CONTRACT.md §0 的“永不抛错”写法——单个注册失败只 warn。
 *   - 宿主不可用时用动态 import 兜底，避免 `node --test` 默认发现机制把夹具当测试文件
 *     执行时因裸说明符解析失败而报错；此时 apply 只记录 warn，不做注册。
 *
 * @module test/helpers/fixtures/plugin-minimal
 */

/** @type {Function | null} */
let defineTool = null
try {
  ;({ defineTool } = await import('@deepseek-ai/dsh-tools'))
} catch {
  defineTool = null
}

export const name = 'daiyi-aimy-fixture'

export const inject = ['tools', 'skills']

/**
 * 夹具：注册 2 个工具 + 2 个技能。
 * @param {object} ctx
 */
export async function apply(ctx) {
  const log = (message) => {
    const logger = typeof ctx?.logger === 'function' ? ctx.logger(name) : undefined
    if (typeof logger?.warn === 'function') logger.warn(message)
  }
  if (!defineTool) {
    log('宿主 @deepseek-ai/dsh-tools 不可用，夹具插件跳过注册')
    return
  }
  const toolNames = ['aimy_fixture_alpha', 'aimy_fixture_beta']
  for (const toolName of toolNames) {
    try {
      ctx.tools.register(defineTool({
        name: toolName,
        description: `夹具工具 ${toolName}`,
        parameters: { target: { type: 'string', required: true } },
        output: {
          schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean' } } },
          render: () => 'ok',
        },
        async execute() {
          return { ok: true }
        },
      }))
    } catch (error) {
      log(`注册工具 ${toolName} 失败：${error instanceof Error ? error.message : String(error)}`)
    }
  }
  for (const skillName of ['aimy-fixture-alpha', 'aimy-fixture-beta']) {
    try {
      ctx.skills.register({
        name: skillName,
        description: `夹具技能 ${skillName}`,
        whenToUse: '仅用于测试',
        content: '# 夹具\n\n仅用于测试。',
        invocation: { modelInvocable: true, userInvocable: true },
      })
    } catch (error) {
      log(`注册技能 ${skillName} 失败：${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

export default apply

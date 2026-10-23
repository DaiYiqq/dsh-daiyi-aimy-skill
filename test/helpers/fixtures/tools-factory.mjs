/**
 * 测试夹具：工厂导出形状 `createTools(deps)`（与当前 lib/tools/index.js 一致的形状）。
 *
 * 与 tools-minimal.mjs 一样用动态 import + 兜底，避免默认测试发现机制在缺宿主环境报错。
 *
 * @module test/helpers/fixtures/tools-factory
 */

/** @type {Function | null} */
let defineTool = null
try {
  ;({ defineTool } = await import('@deepseek-ai/dsh-tools'))
} catch {
  defineTool = null
}

/**
 * @param {object} deps 构造期不读取，只证明工厂形状可被适配器调用
 * @returns {object[]} defineTool 结果（宿主不可用时为空数组）
 */
export function createTools(deps) {
  const label = deps && typeof deps === 'object' ? 'deps' : 'no-deps'
  if (!defineTool) return []
  return [
    defineTool({
      name: 'aimy_fixture_factory_one',
      description: `夹具工厂工具（${label}）`,
      parameters: {},
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean' } } },
        render: () => 'ok',
      },
      async execute() {
        return { ok: true }
      },
    }),
    defineTool({
      name: 'aimy_fixture_factory_two',
      description: '夹具工厂工具 2',
      parameters: { count: { type: 'integer' } },
      output: {
        schema: { type: 'object', additionalProperties: false, properties: { ok: { type: 'boolean' } } },
        render: () => 'ok',
      },
      async execute() {
        return { ok: true }
      },
    }),
  ]
}

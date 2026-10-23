/**
 * 测试夹具：两种静态导出形状（TOOLS / tools / default）的最小工具模块。
 *
 * 只有在安装了 import map（test/helpers/dsh-tools.mjs）之后才能解析裸说明符
 * `@deepseek-ai/dsh-tools`。为了让 `node --test` 的默认发现机制（它会把 test/ 下
 * 所有 .mjs 当测试文件执行）不至于因为环境缺宿主而报错，这里用**动态 import + 兜底**：
 * 宿主可用时导出真实 defineTool 结果，不可用时导出空数组（依赖真实宿主的测试会 skip）。
 *
 * @module test/helpers/fixtures/tools-minimal
 */

/** @type {Function | null} */
let defineTool = null
try {
  ;({ defineTool } = await import('@deepseek-ai/dsh-tools'))
} catch {
  defineTool = null
}

/**
 * 构造一个 schema 合规的最小工具。
 * @param {string} name
 * @param {string} title
 * @returns {object} defineTool 结果
 */
function makeTool(name, title) {
  return defineTool({
    name,
    description: `夹具工具 ${title}`,
    parameters: {
      target: { type: 'string', required: true, description: '目标' },
      verbose: { type: 'boolean', description: '是否详细输出（可选）' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean', required: true },
          message: { type: 'string' },
        },
      },
      render: (_args, value) => `ok=${value.ok}${value.message ? ` ${value.message}` : ''}`,
    },
    presentCall: (args) => ({ card: 'generic', title, rawInput: args.target }),
    async execute(args) {
      return { ok: true, message: String(args.target) }
    },
  })
}

/** 首选导出形状（宿主不可用时为空数组）。 */
export const TOOLS = defineTool ? [makeTool('aimy_fixture_alpha', '夹具 Alpha'), makeTool('aimy_fixture_beta', '夹具 Beta')] : []
/** 备选导出名。 */
export const tools = TOOLS
/** 再备选：default 数组。 */
export default TOOLS

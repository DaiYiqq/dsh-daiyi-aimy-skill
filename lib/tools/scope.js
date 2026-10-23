/**
 * 工具 aimy_scope：授权范围登记与查询。
 *
 * 这是所有网络工具的前置闸门。没有登记范围时，其余工具一律拒绝执行。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/scope
 */

import { defineTool } from './define.js'
import { renderText } from './shared.js'
import { describeScope } from '../scope.js'

/**
 * @param {{ scope: import('../scope.js').ScopeStore, config: object, log: Function }} deps
 * @returns {object} 注册用工具定义
 */
export function createScopeTool(deps) {
  return defineTool({
    name: 'aimy_scope',
    description:
      '管理授权测试范围（deny-by-default 的强制闸门）。在对任何目标发起网络请求前，必须先用 action="add" 登记目标并写明授权依据；' +
      '其余 aimy_* 工具只接受已登记范围内的目标，越界会直接拒绝。action 取值：add（登记）、list（查看）、remove（移除）、clear（清空）、check（试判某个目标是否放行）。',
    parameters: {
      action: {
        type: 'string',
        required: true,
        enum: ['add', 'list', 'remove', 'clear', 'check'],
        description: 'add=登记范围；list=列出现有范围；remove=移除；clear=清空；check=判定目标是否在范围内',
      },
      target: {
        type: 'string',
        description:
          '目标写法：example.com、*.example.com（含子域）、example.com:8443、https://example.com/app（限定路径前缀）、127.0.0.1。add/remove/check 需要。',
      },
      authorization: {
        type: 'string',
        description: 'add 必填：授权依据，至少 8 个字符，例如「客户授权函 #A-1024，范围 example.com 全端口」或「CTF 靶场 dvwa，本机 docker」。',
      },
      expiresInHours: {
        type: 'integer',
        description: '可选：多少小时后自动过期（默认长期有效）。演练场景建议设置。',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string', required: true },
          ok: { type: 'boolean', required: true },
          entries: { type: 'json' },
          removed: { type: 'json' },
          check: { type: 'json' },
          message: { type: 'string' },
          error: { type: 'string' },
          hint: { type: 'string' },
        },
      },
      render: (_args, value) => {
        if (value.ok !== true) return renderText(`授权范围操作失败：${value.error ?? '未知错误'}`, { hint: value.hint })
        if (value.action === 'check') {
          const check = /** @type {Record<string, unknown> | null} */ (value.check ?? null)
          const allowed = check?.ok === true
          return renderText(allowed ? '目标在授权范围内，可以测试' : `目标被拒绝：${String(check?.reason ?? '')}`)
        }
        const count = Array.isArray(value.entries) ? value.entries.length : 0
        return renderText(value.message ?? `当前已登记 ${count} 条授权范围`, { 范围: count })
      },
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `授权范围 · ${args.action}`,
      kind: 'other',
      rawInput: args.target ?? args.action,
    }),
    async execute(args) {
      const action = args.action
      if (action === 'list') {
        const entries = deps.scope.list()
        return {
          action,
          ok: true,
          entries,
          message: entries.length === 0 ? '尚未登记任何授权范围；请先 add 一个目标再执行扫描。' : describeScope(entries).replace(/\n/g, ' / '),
          hint: '范围之外的目标一律拒绝。演练结束后建议 remove 或 clear。',
        }
      }

      if (action === 'add') {
        const result = await deps.scope.add({
          target: args.target ?? '',
          authorization: args.authorization ?? '',
          expiresInHours: args.expiresInHours ?? null,
        })
        if (result.ok !== true) {
          return {
            action,
            ok: false,
            error: result.error,
            hint: '授权依据要能追溯到具体授权文件或靶场编号；不接受「测试」「随便」这类填写。',
          }
        }
        const saveError = await deps.scope.save()
        return {
          action,
          ok: true,
          entries: deps.scope.list(),
          message: result.warning ?? `已登记授权范围：${result.entry.target}`,
          ...(saveError === null ? {} : { error: `范围已加入内存但落盘失败：${String(saveError)}` }),
        }
      }

      if (action === 'remove') {
        const result = deps.scope.remove(args.target ?? '')
        if (result.ok !== true) return { action, ok: false, error: result.error }
        await deps.scope.save()
        return {
          action,
          ok: true,
          removed: result.removed.map((entry) => entry.target),
          entries: deps.scope.list(),
          message: `已移除 ${result.removed.length} 条授权范围`,
        }
      }

      if (action === 'clear') {
        const count = deps.scope.clear()
        await deps.scope.save()
        return {
          action,
          ok: true,
          entries: [],
          message: `已清空 ${count} 条授权范围；此后所有网络工具都会拒绝执行。`,
        }
      }

      // check
      const verdict = deps.scope.check(args.target ?? '')
      return {
        action,
        ok: true,
        check: verdict,
        message: verdict.ok === true ? '目标在授权范围内' : '目标不在授权范围内',
      }
    },
  })
}

/**
 * 工具 aimy_report：会话发现汇总与报告导出。
 *
 * 报告只读会话内的 findings/runs，不重新探测，因此可以反复导出不同格式。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/report
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'
import { defineTool } from './define.js'
import { renderText } from './shared.js'
import { renderReport, summarize } from '../report.js'
import { PLUGIN_ID, PLUGIN_VERSION } from '../config.js'

/**
 * @param {{ store: import('../store.js').FindingsStore, scope: import('../scope.js').ScopeStore, config: object, log: Function }} deps
 */
export function createReportTool(deps) {
  return defineTool({
    name: 'aimy_report',
    description:
      '汇总本次会话的安全测试结果：查看统计摘要、列出带证据的发现、导出 Markdown/JSON/SARIF 报告，或清空记录。' +
      '导出时可写入文件并返回路径。报告只包含已登记授权范围内的结果。',
    parameters: {
      action: {
        type: 'string',
        enum: ['summary', 'findings', 'report', 'runs', 'clear'],
        description: 'summary=统计摘要（默认）；findings=列出发现；report=导出报告；runs=运行记录；clear=清空会话数据',
      },
      format: {
        type: 'string',
        enum: ['md', 'json', 'sarif'],
        description: 'report 动作的输出格式，默认 md',
      },
      severity: {
        type: 'array',
        description: '只保留这些严重度：critical/high/medium/low/info',
        items: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      },
      outputPath: {
        type: 'string',
        description: 'report 动作可选：把报告写入该路径（相对当前工作目录或绝对路径）',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string', required: true },
          format: { type: 'string', required: true },
          counts: { type: 'json', required: true },
          summary: { type: 'string', required: true },
          findings: { type: 'json' },
          runs: { type: 'json' },
          content: { type: 'string' },
          path: { type: 'string' },
          written: { type: 'boolean' },
          message: { type: 'string' },
        },
      },
      render: (_args, value) => {
        if (value.action === 'clear') return renderText('会话记录已清空')
        if (value.action === 'runs') {
          const runs = Array.isArray(value.runs) ? value.runs : []
          return renderText(`共 ${runs.length} 条运行记录`, { 请求: value.counts?.requests })
        }
        const path = typeof value.path === 'string' ? `已写入 ${value.path}` : undefined
        return renderText(value.summary ?? '汇总完成', { 严重度分布: JSON.stringify(value.counts), 文件: path })
      },
    },
    presentCall: (args) => ({ card: 'generic', title: `测试报告 · ${args.action ?? 'summary'}`, kind: 'other', rawInput: args.action ?? 'summary' }),
    async execute(args) {
      const action = args.action ?? 'summary'
      const format = args.format ?? 'md'
      const severity = Array.isArray(args.severity) && args.severity.length > 0 ? args.severity : undefined

      const snapshot = () =>
        deps.store.snapshot({
          plugin: { name: PLUGIN_ID, version: PLUGIN_VERSION, mode: deps.config.mode },
          scopeEntries: deps.scope.list().map((entry) => ({
            target: entry.target,
            authorization: entry.authorization,
            expiresAt: entry.expiresAt,
          })),
        })

      if (action === 'clear') {
        deps.store.clear()
        return { action, format, counts: deps.store.counts(), summary: '已清空本次会话的发现与运行记录' }
      }

      if (action === 'findings') {
        const findings = deps.store.list({ severity })
        return {
          action,
          format,
          counts: deps.store.counts(),
          summary: `共 ${findings.length} 条发现：${summarize(snapshot())}`,
          findings,
        }
      }

      if (action === 'runs') {
        const report = snapshot()
        return {
          action,
          format,
          counts: report.stats.findings,
          summary: `共 ${report.runs.length} 条运行记录，累计 ${report.stats.requests} 次请求`,
          runs: report.runs,
        }
      }

      const report = snapshot()
      const filtered = severity === undefined ? report : { ...report, findings: report.findings.filter((finding) => severity.includes(finding.severity)) }
      const content = renderReport(format, filtered, { redactSecrets: deps.config.redactSecrets })

      if (typeof args.outputPath === 'string' && args.outputPath.trim().length > 0) {
        const target = path.resolve(args.outputPath.trim())
        try {
          await fs.mkdir(path.dirname(target), { recursive: true })
          await fs.writeFile(target, content.endsWith('\n') ? content : `${content}\n`, 'utf8')
        } catch (error) {
          throw new Error(`写入报告失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
        }
        return {
          action,
          format,
          counts: report.stats.findings,
          summary: summarize(report),
          written: true,
          path: target,
          content: action === 'report' && format === 'json' ? undefined : content,
        }
      }

      return {
        action,
        format,
        counts: report.stats.findings,
        summary: summarize(report),
        written: false,
        ...(action === 'report' ? { content } : {}),
      }
    },
  })
}

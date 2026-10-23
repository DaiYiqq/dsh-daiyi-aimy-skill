/**
 * 工具 aimy_crawl：同源爬取与攻击面盘点。
 *
 * 产出页面、链接、表单、参数与前端 JS 里出现的端点，供 aimy_web_scan 直接消费。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/crawl
 */

import { defineTool } from './define.js'
import { buildEngineContext, createProbeClient, renderText, requireScope, startRun } from './shared.js'
import { crawl } from '../engine/index.js'

/**
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createCrawlTool(deps) {
  return defineTool({
    name: 'aimy_crawl',
    description:
      '对**已授权**站点做同源爬取：收集页面、站内链接、表单、查询参数与前端 JS 中出现的接口路径，' +
      '用于盘点攻击面并给 aimy_web_scan 提供参数。目标必须先用 aimy_scope 登记。',
    parameters: {
      target: { type: 'string', required: true, description: '起始 URL，例如 https://example.com/' },
      maxPages: { type: 'integer', description: '最多抓取页面数，默认 20，上限 60' },
      maxDepth: { type: 'integer', description: '最大跳转深度，默认 2，上限 4' },
      includeForms: { type: 'boolean', description: '是否解析表单，默认 true' },
      includeJs: { type: 'boolean', description: '是否从内联/外链 JS 中提取接口路径，默认 true' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          target: { type: 'string', required: true },
          pages: { type: 'json', required: true },
          urls: { type: 'json', required: true },
          forms: { type: 'json', required: true },
          params: { type: 'json', required: true },
          jsEndpoints: { type: 'json', required: true },
          findings: { type: 'json', required: true },
          requests: { type: 'integer', required: true },
          notes: { type: 'json' },
        },
      },
      render: (_args, value) => {
        const pages = Array.isArray(value.pages) ? value.pages : []
        const params = Array.isArray(value.params) ? value.params : []
        return renderText(`爬取完成：${pages.length} 个页面，${params.length} 个参数`, {
          参数: params.slice(0, 10).map((param) => `${param.name}(${param.location})`).join(', '),
        })
      },
    },
    presentCall: (args) => ({ card: 'generic', title: '站点爬取', kind: 'other', rawInput: args.target }),
    async execute(args, exec) {
      const url = requireScope(deps.scope, args.target)
      const client = createProbeClient({ scope: deps.scope, config: deps.config, signal: exec.signal, log: deps.log })
      const run = startRun(deps, 'aimy_crawl', url.toString())
      const engineCtx = buildEngineContext({ url, client, params: [], config: deps.config, signal: exec.signal, log: deps.log })

      try {
        const result = await crawl(engineCtx, {
          maxPages: Math.max(1, Math.min(60, args.maxPages ?? 20)),
          maxDepth: Math.max(1, Math.min(4, args.maxDepth ?? 2)),
          includeForms: args.includeForms !== false,
          includeJs: args.includeJs !== false,
        })
        const findings = Array.isArray(result.findings) ? result.findings : []
        const accepted = deps.store.add(findings)
        const record = run.finish({ requests: client.requestCount, findings: accepted.added })
        return {
          target: url.toString(),
          pages: result.pages ?? [],
          urls: result.urls ?? [],
          forms: result.forms ?? [],
          params: result.params ?? [],
          jsEndpoints: result.jsEndpoints ?? [],
          findings: accepted.accepted,
          requests: client.requestCount,
          notes: [`runId=${record.id}`, `预算 ${deps.config.maxRequests} 请求`],
        }
      } catch (error) {
        run.finish({ requests: client.requestCount, findings: 0, note: 'failed' })
        throw error
      }
    },
  })
}

/**
 * 工具 aimy_web_scan：一次调用跑一组 Web 检测模块。
 *
 * 与上游「一个 py 脚本一个检测」不同，这里是一个统一入口：指定 checks 与参数，
 * 并发跑引擎模块，汇总去重后写入会话 findings。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/web-scan
 */

import { defineTool } from './define.js'
import { buildEngineContext, createProbeClient, renderText, requireScope, startRun } from './shared.js'
import { listChecks, runChecks } from '../engine/index.js'
import { crawl } from '../engine/index.js'

const DEFAULT_CHECKS = ['sqli', 'xss', 'cors', 'headers']

/**
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createWebScanTool(deps) {
  const available = listChecks()
  return defineTool({
    name: 'aimy_web_scan',
    description:
      '对**已授权**的单个 URL 执行一组 Web 漏洞检测：' +
      available.map((entry) => `${entry.id}（${entry.title}）`).join('、') +
      '。省略 params 时会先爬取目标自动发现参数；每项检查只做无害探测，命中即产出带证据的 finding。目标必须先用 aimy_scope 登记。',
    parameters: {
      target: { type: 'string', required: true, description: '目标 URL（可带查询参数），例如 https://example.com/item?id=1' },
      checks: {
        type: 'array',
        description: `要跑的检查项，可选 ${available.map((entry) => entry.id).join('/')}；默认 ${DEFAULT_CHECKS.join('/')}`,
        items: { type: 'string', enum: available.map((entry) => entry.id) },
      },
      params: {
        type: 'array',
        description: '被测参数（不传则自动发现）。每项 { name, location, sample }，location 取 query/body/json',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            name: { type: 'string', required: true },
            location: { type: 'string', enum: ['query', 'body', 'json'] },
            sample: { type: 'string' },
          },
        },
      },
      method: { type: 'string', enum: ['GET', 'POST'], description: '请求方法，默认 GET' },
      timeoutMs: { type: 'integer', description: '单请求超时（毫秒），默认取配置值' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          target: { type: 'string', required: true },
          checks: { type: 'json', required: true },
          skipped: { type: 'json', required: true },
          params: { type: 'json', required: true },
          findings: { type: 'json', required: true },
          requests: { type: 'integer', required: true },
          notes: { type: 'json' },
        },
      },
      render: (_args, value) => {
        const findings = Array.isArray(value.findings) ? value.findings : []
        const skipped = Array.isArray(value.skipped) ? value.skipped : []
        return renderText(`扫描完成：${findings.length} 条发现`, {
          检查项: Array.isArray(value.checks) ? value.checks.join('/') : undefined,
          跳过: skipped.length === 0 ? undefined : skipped.map((entry) => `${entry.check}:${entry.reason}`).join('; '),
        })
      },
    },
    presentCall: (args) => ({ card: 'generic', title: 'Web 漏洞检测', kind: 'other', rawInput: args.target }),
    async execute(args, exec) {
      const url = requireScope(deps.scope, args.target)
      const checks = normalizeChecks(args.checks)
      const config =
        args.timeoutMs === undefined || args.timeoutMs === null
          ? deps.config
          : { ...deps.config, timeoutMs: Math.max(1000, Math.min(60000, args.timeoutMs)) }
      const client = createProbeClient({ scope: deps.scope, config, signal: exec.signal, log: deps.log })
      const run = startRun(deps, 'aimy_web_scan', url.toString())
      const notes = []
      /** @type {Array<{ check: string, reason: string }>} */
      const skipped = []

      try {
        const params = await resolveParams({ args, url, client, config, signal: exec.signal, deps, notes })
        const engineCtx = buildEngineContext({ url, client, params, config, signal: exec.signal, log: deps.log })
        const engineFindings = await runChecks(engineCtx, checks, {
          onSkip: (check, reason) => skipped.push({ check, reason }),
        })
        // method 参数目前只作为提示写进结果：引擎按参数位置自行选择 GET/POST
        if (args.method === 'POST') notes.push('已指定 POST：表单参数会以 application/x-www-form-urlencoded 提交')
        const accepted = deps.store.add(engineFindings)
        const record = run.finish({ requests: client.requestCount, findings: accepted.added })
        deps.log('info', `aimy_web_scan ${url.toString()}：${client.requestCount} 请求 / ${accepted.added} 新发现`)
        return {
          target: url.toString(),
          checks,
          skipped,
          params,
          findings: accepted.accepted,
          requests: client.requestCount,
          notes: [...notes, `runId=${record.id}`, `模式=${config.mode}`],
        }
      } catch (error) {
        run.finish({ requests: client.requestCount, findings: 0, note: 'failed' })
        throw error
      }
    },
  })
}

/**
 * @param {unknown} raw
 * @returns {string[]}
 */
function normalizeChecks(raw) {
  const all = listChecks().map((entry) => entry.id)
  if (!Array.isArray(raw) || raw.length === 0) return all.filter((id) => DEFAULT_CHECKS.includes(id))
  const chosen = raw.filter((item) => typeof item === 'string' && all.includes(item))
  return chosen.length === 0 ? all.filter((id) => DEFAULT_CHECKS.includes(id)) : [...new Set(chosen)]
}

/**
 * 解析被测参数：优先用调用方给的，其次从 URL 与爬取结果推导。
 * @param {object} options
 * @returns {Promise<Array<{ name: string, location: 'query' | 'body' | 'json', sample: string }>>}
 */
async function resolveParams(options) {
  const { args, url, client, config, signal, deps, notes } = options
  if (Array.isArray(args.params) && args.params.length > 0) {
    return args.params
      .filter((param) => param !== null && typeof param === 'object' && typeof param.name === 'string' && param.name.length > 0)
      .map((param) => ({
        name: param.name,
        location: param.location === 'body' || param.location === 'json' ? param.location : 'query',
        sample: typeof param.sample === 'string' && param.sample.length > 0 ? param.sample : '1',
      }))
  }

  /** @type {Map<string, { name: string, location: 'query' | 'body' | 'json', sample: string }>} */
  const collected = new Map()
  for (const [name, value] of url.searchParams.entries()) {
    collected.set(`query:${name}`, { name, location: 'query', sample: value.length > 0 ? value : '1' })
  }
  if (collected.size > 0) return [...collected.values()]

  // 没有查询参数时爬一遍，取第一个有参数的表单/链接
  try {
    const engineCtx = buildEngineContext({ url, client, params: [], config, signal, log: deps.log })
    const result = await crawl(engineCtx, { maxPages: 5, maxDepth: 2, includeForms: true, includeJs: false })
    for (const param of result.params ?? []) {
      const key = `${param.location}:${param.name}`
      if (!collected.has(key)) collected.set(key, { name: param.name, location: param.location, sample: param.sample || '1' })
    }
    notes.push(`自动发现 ${collected.size} 个参数（来自 ${result.pages?.length ?? 0} 个页面）`)
  } catch (error) {
    notes.push(`参数自动发现失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
  }
  return [...collected.values()]
}

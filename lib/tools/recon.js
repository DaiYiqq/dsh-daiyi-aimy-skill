/**
 * 工具 aimy_recon：被动/半被动侦察（DNS、HTTP 基线、安全响应头、技术指纹、robots）。
 *
 * 对应上游 aimy-sikll 的爬虫 + 指纹 + 信息收集能力，但改为：
 * 单次调用内并发受限、全部经护栏探针、结构化输出且可复现。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/recon
 */

import { promises as dns } from 'node:dns'
import { defineTool } from './define.js'
import { buildEngineContext, createProbeClient, renderText, requireScope, startRun } from './shared.js'
import { fingerprint, runChecks } from '../engine/index.js'
import { mapLimit } from '../http.js'

const DEFAULT_CHECKS = ['dns', 'http', 'headers', 'tech', 'robots']
const ALL_CHECKS = ['dns', 'http', 'headers', 'tech', 'robots', 'tls']

/**
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createReconTool(deps) {
  return defineTool({
    name: 'aimy_recon',
    description:
      '对一个**已授权**目标做侦察：DNS 记录、HTTP 基线（状态码/标题/服务器/耗时）、安全响应头缺失、技术栈指纹、robots.txt。' +
      '返回结构化结果并自动把缺失安全响应头、版本泄露等写成 finding。目标必须先用 aimy_scope 登记。',
    parameters: {
      target: { type: 'string', required: true, description: '目标 URL 或主机名，例如 https://example.com 或 example.com' },
      checks: {
        type: 'array',
        description: `要执行的检查项，可选 ${ALL_CHECKS.join('/')}；默认 ${DEFAULT_CHECKS.join('/')}`,
        items: { type: 'string', enum: ALL_CHECKS },
      },
      timeoutMs: { type: 'integer', description: '单请求超时（毫秒），默认取配置值' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          target: { type: 'json', required: true },
          checks: { type: 'json', required: true },
          dns: { type: 'json' },
          http: { type: 'json' },
          tls: { type: 'json' },
          tech: { type: 'json' },
          robots: { type: 'json' },
          findings: { type: 'json', required: true },
          requests: { type: 'integer', required: true },
          notes: { type: 'json' },
        },
      },
      render: (_args, value) => {
        const findings = Array.isArray(value.findings) ? value.findings : []
        const http = /** @type {Record<string, unknown>} */ (value.http ?? {})
        return renderText(
          `侦察完成：${value.requests} 次请求，${findings.length} 条发现`,
          {
            HTTP: http.status === undefined ? undefined : `${http.status} · ${String(http.title ?? '')}`.trim(),
            技术栈: Array.isArray(value.tech) ? value.tech.map((entry) => entry.name).slice(0, 6).join(', ') : undefined,
          },
        )
      },
    },
    presentCall: (args) => ({ card: 'generic', title: '目标侦察', kind: 'other', rawInput: args.target }),
    async execute(args, exec) {
      const url = requireScope(deps.scope, args.target)
      const checks = normalizeChecks(args.checks)
      const config = args.timeoutMs === undefined || args.timeoutMs === null
        ? deps.config
        : { ...deps.config, timeoutMs: Math.max(1000, Math.min(60000, args.timeoutMs)) }
      const run = startRun(deps, 'aimy_recon', url.toString())
      const client = createProbeClient({ scope: deps.scope, config, signal: exec.signal, log: deps.log })
      const notes = []
      /** @type {unknown[]} */ let findings = []
      /** @type {Record<string, unknown> | undefined} */ let dnsResult
      /** @type {Record<string, unknown> | undefined} */ let httpResult
      /** @type {Record<string, unknown> | undefined} */ let tlsResult
      /** @type {Record<string, unknown> | undefined} */ let robotsResult
      /** @type {Array<{ name: string, confidence: string, evidence: string }> | undefined} */ let techResult

      try {
        if (checks.includes('dns')) {
          dnsResult = await collectDns(url, config.timeoutMs)
        }

        if (checks.includes('http') || checks.includes('headers') || checks.includes('tech')) {
          const response = await client.request(url, { method: 'GET' })
          if (response.status === 0) {
            notes.push(`HTTP 基线请求失败：${response.error ?? '未知错误'}`)
          } else {
            httpResult = {
              status: response.status,
              finalUrl: response.url,
              elapsedMs: response.elapsedMs,
              contentType: response.headers['content-type'] ?? null,
              server: response.headers.server ?? null,
              poweredBy: response.headers['x-powered-by'] ?? null,
              title: extractTitle(response.body),
              length: Buffer.byteLength(response.body, 'utf8'),
              truncated: response.truncated,
            }
          }
        }

        if (checks.includes('tls') && url.protocol === 'https:') {
          tlsResult = { note: 'Node 内置 fetch 不暴露证书链详情；请用外部工具复核证书有效期与 SAN。', protocol: 'https' }
        }

        if (checks.includes('headers') || checks.includes('tech')) {
          const engineCtx = buildEngineContext({ url, client, params: [], config, signal: exec.signal, log: deps.log })
          if (checks.includes('headers')) {
            const headerFindings = await runChecks(engineCtx, ['headers'])
            findings = [...findings, ...headerFindings]
          }
          if (checks.includes('tech')) {
            // 指纹是"信息"而不是漏洞：列表直接回传，同时让引擎模块补充版本泄露类 finding
            techResult = await fingerprint(engineCtx)
            const techFindings = await runChecks(engineCtx, ['tech-fingerprint'])
            findings = [...findings, ...techFindings]
          }
        }

        if (checks.includes('robots')) {
          robotsResult = await collectRobots(client, url)
        }

        const accepted = deps.store.add(findings)
        const record = run.finish({ requests: client.requestCount, findings: accepted.added })
        deps.log('info', `aimy_recon ${url.origin}：${client.requestCount} 请求 / ${accepted.added} 新发现`)

        return {
          target: { url: url.toString(), origin: url.origin, host: url.hostname },
          checks,
          ...(dnsResult === undefined ? {} : { dns: dnsResult }),
          ...(httpResult === undefined ? {} : { http: httpResult }),
          ...(tlsResult === undefined ? {} : { tls: tlsResult }),
          ...(robotsResult === undefined ? {} : { robots: robotsResult }),
          ...(techResult === undefined ? {} : { tech: techResult }),
          findings: accepted.accepted,
          requests: client.requestCount,
          notes: [...notes, `runId=${record.id}`],
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
  if (!Array.isArray(raw) || raw.length === 0) return [...DEFAULT_CHECKS]
  const allowed = raw.filter((item) => typeof item === 'string' && ALL_CHECKS.includes(item))
  return allowed.length === 0 ? [...DEFAULT_CHECKS] : [...new Set(allowed)]
}

/**
 * 采集 DNS 记录。IP 目标直接跳过，避免无意义的反查。
 * @param {URL} url
 * @param {number} timeoutMs
 * @returns {Promise<Record<string, unknown>>}
 */
async function collectDns(url, timeoutMs) {
  const host = url.hostname.replace(/^\[|\]$/g, '')
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
    return { host, skipped: true, reason: '目标是 IP 字面量，跳过 DNS 查询' }
  }
  /** @type {Record<string, unknown>} */
  const out = { host }
  const queries = [
    ['a', () => dns.resolve4(host)],
    ['aaaa', () => dns.resolve6(host)],
    ['cname', () => dns.resolveCname(host)],
    ['mx', () => dns.resolveMx(host)],
    ['ns', () => dns.resolveNs(host)],
    ['txt', () => dns.resolveTxt(host)],
  ]
  const settled = await mapLimit(queries, 6, async ([key, fn]) => {
    try {
      const value = await withTimeout(Promise.resolve().then(fn), timeoutMs)
      return [key, value]
    } catch (error) {
      const code = /** @type {{ code?: string }} */ (error)?.code
      if (code === 'ENOTFOUND' || code === 'ENODATA') return [key, null]
      return [key, null, String(code ?? error)]
    }
  })
  for (const row of settled) {
    const [key, value, error] = row
    if (value !== null && value !== undefined) out[key] = key === 'txt' ? value.map((entry) => entry.join('')) : value
    else if (error !== undefined) out[`${key}Error`] = error
  }
  return out
}

/**
 * 读取 robots.txt 中的 Disallow 与 Sitemap。
 * @param {import('../http.js').ProbeClient} client
 * @param {URL} url
 * @returns {Promise<Record<string, unknown>>}
 */
async function collectRobots(client, url) {
  const robotsUrl = new URL('/robots.txt', url.origin)
  const response = await client.request(robotsUrl, { method: 'GET' })
  if (response.status === 0) return { url: robotsUrl.toString(), error: response.error ?? '请求失败' }
  if (response.status !== 200) return { url: robotsUrl.toString(), status: response.status }
  const disallow = []
  const allow = []
  const sitemap = []
  for (const line of response.body.split(/\r?\n/)) {
    const trimmed = line.trim()
    const disallowMatch = /^disallow:\s*(\S*)/i.exec(trimmed)
    if (disallowMatch !== null) disallow.push(disallowMatch[1])
    const allowMatch = /^allow:\s*(\S*)/i.exec(trimmed)
    if (allowMatch !== null) allow.push(allowMatch[1])
    const sitemapMatch = /^sitemap:\s*(\S+)/i.exec(trimmed)
    if (sitemapMatch !== null) sitemap.push(sitemapMatch[1])
  }
  return {
    url: robotsUrl.toString(),
    status: response.status,
    disallow: disallow.slice(0, 50),
    allow: allow.slice(0, 50),
    sitemap: sitemap.slice(0, 10),
  }
}

/**
 * @param {string} body
 * @returns {string | null}
 */
function extractTitle(body) {
  const match = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(body)
  if (match === null) return null
  return match[1].replace(/\s+/g, ' ').trim().slice(0, 200)
}

/**
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @returns {Promise<T>}
 */
function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout ${timeoutMs}ms`)), Math.max(1, timeoutMs))
    if (typeof timer.unref === 'function') timer.unref()
    promise.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (error) => {
        clearTimeout(timer)
        reject(error)
      },
    )
  })
}

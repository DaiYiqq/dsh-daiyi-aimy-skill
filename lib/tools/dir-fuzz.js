/**
 * 工具 aimy_dir_fuzz：Web 路径枚举。
 *
 * 相比上游 Python 版本的改进：
 * - 先打一个随机不存在路径做「软 404」基线，避免把自定义 404 页面全当成命中；
 * - 并发受控、全走护栏探针、按状态码/长度/重定向差异过滤；
 * - 命中结果直接产 finding（备份文件、源码泄露、管理入口）。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/dir-fuzz
 */

import { defineTool } from './define.js'
import { createProbeClient, renderText, requireScope, startRun } from './shared.js'

/** 内置字典：按"高价值少而准"原则挑选。 */
export const DEFAULT_WORDLIST = [
  'admin', 'login', 'logout', 'register', 'dashboard', 'console', 'manage', 'manager',
  'api', 'api/v1', 'api/v2', 'swagger', 'swagger-ui', 'swagger.json', 'openapi.json', 'api-docs',
  'robots.txt', 'sitemap.xml', 'humans.txt', 'security.txt', '.well-known/security.txt',
  '.git/HEAD', '.git/config', '.svn/entries', '.env', '.env.local', '.env.production', '.DS_Store',
  'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test', 'dev', 'staging', 'demo',
  'config', 'config.json', 'config.php', 'settings', 'web.config', 'appsettings.json',
  'upload', 'uploads', 'files', 'download', 'downloads', 'static', 'assets', 'public',
  'phpinfo.php', 'info.php', 'test.php', 'shell.php', 'index.php', 'index.html', 'index.jsp',
  'wp-admin', 'wp-login.php', 'wp-config.php', 'xmlrpc.php', 'administrator',
  'server-status', 'server-info', 'status', 'health', 'healthz', 'metrics', 'actuator',
  'actuator/env', 'actuator/heapdump', 'debug', 'trace', 'docs', 'redoc',
  'user', 'users', 'account', 'accounts', 'profile', 'admin/users', 'graphql', 'graphiql',
  'console/login', 'jmx-console', 'manager/html', 'druid/index.html',
  'db', 'database', 'dump.sql', 'backup.zip', 'backup.tar.gz', 'www.zip', 'web.zip', 'source.zip',
  'log', 'logs', 'error.log', 'access.log', 'debug.log',
]

const DEFAULT_STATUS = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]

/**
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createDirFuzzTool(deps) {
  return defineTool({
    name: 'aimy_dir_fuzz',
    description:
      '对**已授权** Web 目标做路径枚举：用内置字典或自定义词表逐个请求，按状态码/响应长度/重定向过滤误报，' +
      '命中敏感路径（源码、配置、备份、管理后台）时产出 finding。目标必须先用 aimy_scope 登记。',
    parameters: {
      target: { type: 'string', required: true, description: '目标基址，例如 https://example.com 或 https://example.com/app/' },
      wordlist: { type: 'array', description: '自定义路径列表（不带前导 /）；省略则用内置字典', items: { type: 'string' } },
      extensions: { type: 'array', description: '要追加的后缀，例如 ["php","bak","zip"]', items: { type: 'string' } },
      statusFilter: { type: 'array', description: `视为命中的状态码，默认 ${DEFAULT_STATUS.join(',')}`, items: { type: 'integer' } },
      maxPaths: { type: 'integer', description: '最多请求多少条路径，默认 120，上限 400' },
      followRedirects: { type: 'boolean', description: '是否跟随重定向，默认 false（保留 3xx 便于判断）' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          target: { type: 'string', required: true },
          tested: { type: 'integer', required: true },
          found: { type: 'json', required: true },
          baseline: { type: 'json' },
          findings: { type: 'json', required: true },
          requests: { type: 'integer', required: true },
          notes: { type: 'json' },
        },
      },
      render: (_args, value) => {
        const found = Array.isArray(value.found) ? value.found : []
        return renderText(`路径枚举完成：请求 ${value.tested} 条，命中 ${found.length} 条`, {
          命中: found.slice(0, 8).map((entry) => `${entry.path}[${entry.status}]`).join(', '),
        })
      },
    },
    presentCall: (args) => ({ card: 'generic', title: '路径枚举', kind: 'other', rawInput: args.target }),
    async execute(args, exec) {
      const baseUrl = requireScope(deps.scope, args.target)
      const maxPaths = Math.max(1, Math.min(400, args.maxPaths ?? 120))
      const statusFilter = new Set(
        Array.isArray(args.statusFilter) && args.statusFilter.length > 0
          ? args.statusFilter.filter((code) => Number.isInteger(code))
          : DEFAULT_STATUS,
      )
      const wordlist = Array.isArray(args.wordlist) && args.wordlist.length > 0 ? args.wordlist : DEFAULT_WORDLIST
      const extensions = (Array.isArray(args.extensions) ? args.extensions : [])
        .map((ext) => String(ext).replace(/^\./, '').trim())
        .filter((ext) => ext.length > 0)

      const candidates = buildCandidates(wordlist, extensions, maxPaths)
      const client = createProbeClient({ scope: deps.scope, config: deps.config, signal: exec.signal, log: deps.log })
      const run = startRun(deps, 'aimy_dir_fuzz', baseUrl.toString())

      // 软 404 基线：随机路径必须不被当成命中
      const baseline = await establishBaseline(client, baseUrl)
      deps.log('info', `aimy_dir_fuzz ${baseUrl.origin}：${candidates.length} 条候选，基线 ${baseline.status}/${baseline.length}`)

      /** @type {Array<{ path: string, url: string, status: number, length: number, redirectTo?: string }>} */
      const found = []
      let tested = 0
      let cursor = 0
      const concurrency = Math.max(1, Math.min(8, deps.config.concurrency))
      const workers = Array.from({ length: Math.min(concurrency, candidates.length) }, async () => {
        for (;;) {
          if (exec.signal?.aborted === true) return
          const index = cursor
          cursor += 1
          if (index >= candidates.length) return
          const path = candidates[index]
          tested += 1
          const url = joinPath(baseUrl, path)
          let response
          try {
            response = await client.request(url, { method: 'GET', followRedirects: args.followRedirects === true })
          } catch (error) {
            // 预算耗尽：停止调度，保留已有结果
            if (/** @type {{ code?: string }} */ (error)?.code === 'BUDGET_EXCEEDED') return
            if (/** @type {{ code?: string }} */ (error)?.code === 'SCOPE_DENIED') return
            throw error
          }
          if (response.status === 0) continue
          if (!statusFilter.has(response.status)) continue
          const length = Buffer.byteLength(response.body, 'utf8')
          if (isSoft404(response, length, baseline)) continue
          found.push({
            path: `/${path}`,
            url: url.toString(),
            status: response.status,
            length,
            ...(response.headers.location === undefined ? {} : { redirectTo: response.headers.location }),
          })
        }
      })
      await Promise.all(workers)

      found.sort((a, b) => a.path.localeCompare(b.path))
      const findings = classifyFindings(found, baseUrl.origin)
      const accepted = deps.store.add(findings)
      const record = run.finish({ requests: client.requestCount, findings: accepted.added })
      return {
        target: baseUrl.toString(),
        tested,
        found,
        baseline,
        findings: accepted.accepted,
        requests: client.requestCount,
        notes: [`runId=${record.id}`, found.length >= maxPaths ? '达到 maxPaths 上限，可增大或换词表' : '完整执行'],
      }
    },
  })
}

/**
 * 生成候选路径（词表 × 后缀，去重并保序）。
 * @param {string[]} wordlist
 * @param {string[]} extensions
 * @param {number} maxPaths
 * @returns {string[]}
 */
export function buildCandidates(wordlist, extensions, maxPaths) {
  /** @type {string[]} */
  const out = []
  const seen = new Set()
  const push = (value) => {
    const cleaned = String(value ?? '').replace(/^\/+/, '').trim()
    if (cleaned.length === 0 || seen.has(cleaned)) return
    seen.add(cleaned)
    out.push(cleaned)
  }
  for (const word of wordlist) push(word)
  if (extensions.length > 0) {
    for (const word of wordlist) {
      if (/\.[a-z0-9]{1,6}$/i.test(word)) continue
      for (const ext of extensions) push(`${word}.${ext}`)
    }
  }
  return out.slice(0, maxPaths)
}

/**
 * @param {URL} baseUrl
 * @param {string} path
 * @returns {URL}
 */
function joinPath(baseUrl, path) {
  const base = baseUrl.toString().endsWith('/') ? baseUrl.toString() : `${baseUrl.toString()}/`
  return new URL(path.replace(/^\/+/, ''), base)
}

/**
 * 用随机路径建立软 404 基线。
 * @param {import('../http.js').ProbeClient} client
 * @param {URL} baseUrl
 * @returns {Promise<{ status: number, length: number, randomPath: string }>}
 */
async function establishBaseline(client, baseUrl) {
  const randomPath = `aimy-not-exist-${Math.random().toString(36).slice(2, 10)}`
  try {
    const response = await client.request(joinPath(baseUrl, randomPath), { method: 'GET' })
    return { status: response.status, length: Buffer.byteLength(response.body, 'utf8'), randomPath }
  } catch {
    return { status: 404, length: 0, randomPath }
  }
}

/**
 * 响应与基线过于相似即判为软 404。
 * @param {{ status: number, body: string }} response
 * @param {number} length
 * @param {{ status: number, length: number }} baseline
 * @returns {boolean}
 */
function isSoft404(response, length, baseline) {
  if (baseline.status !== 200) return false
  if (response.status !== 200) return false
  if (baseline.length === 0) return false
  const delta = Math.abs(length - baseline.length)
  return delta <= Math.max(24, Math.round(baseline.length * 0.02))
}

/**
 * 按路径特征产出 finding。
 * @param {Array<{ path: string, url: string, status: number, length: number }>} found
 * @param {string} origin
 * @returns {unknown[]}
 */
function classifyFindings(found, origin) {
  /** @type {unknown[]} */
  const findings = []
  const push = (entry, spec) => {
    findings.push({
      module: 'dir-brute',
      checkId: spec.checkId,
      title: spec.title,
      severity: spec.severity,
      confidence: 'high',
      url: entry.url,
      evidence: `GET ${entry.url} → ${entry.status}，响应 ${entry.length} 字节。`,
      cwe: spec.cwe,
      remediation: spec.remediation,
    })
  }
  for (const entry of found) {
    if (/\.git\/|\.svn\/|\.hg\//.test(entry.path)) {
      push(entry, {
        checkId: 'vcs-exposure',
        title: '版本控制目录可访问',
        severity: 'high',
        cwe: 'CWE-538',
        remediation: '在 Web 服务器上禁止访问 .git/.svn 目录，并从发布包中移除。',
      })
      continue
    }
    if (/^\/\.env|^\/config\.(json|php)|^\/web\.config|^\/appsettings\.json/.test(entry.path)) {
      push(entry, {
        checkId: 'config-exposure',
        title: '配置文件可访问',
        severity: 'critical',
        cwe: 'CWE-538',
        remediation: '将配置文件移出 Web 根目录，并在网关层拦截点文件与配置后缀。',
      })
      continue
    }
    if (/(\.zip|\.tar\.gz|\.sql|\.bak|dump\.sql)$/.test(entry.path)) {
      push(entry, {
        checkId: 'backup-exposure',
        title: '备份/导出文件可下载',
        severity: 'high',
        cwe: 'CWE-538',
        remediation: '备份文件不要放在 Web 根目录，下载需要鉴权。',
      })
      continue
    }
    if (/^\/actuator|^\/server-status|^\/server-info|^\/jmx-console|^\/manager\/html|^\/druid/.test(entry.path)) {
      push(entry, {
        checkId: 'management-endpoint',
        title: '管理/监控端点暴露',
        severity: 'high',
        cwe: 'CWE-284',
        remediation: '管理端点应限制来源 IP 或仅内网可达，并启用认证。',
      })
      continue
    }
    if (entry.status === 401 || entry.status === 403) {
      push(entry, {
        checkId: 'protected-path',
        title: '受保护路径存在（可继续验证越权）',
        severity: 'info',
        cwe: 'CWE-284',
        remediation: '确认该路径的鉴权实现，并检查是否存在绕过或越权访问。',
      })
    }
  }
  // 同一 checkId 只保留前 10 条，避免报告被刷屏
  const counts = new Map()
  return findings.filter((finding) => {
    const key = /** @type {{ checkId: string }} */ (finding).checkId
    const next = (counts.get(key) ?? 0) + 1
    counts.set(key, next)
    return next <= 10
  })
}

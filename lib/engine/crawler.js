/**
 * 同源爬虫（BFS）。
 *
 * 对外接口：
 * - `crawl(ctx, options)` → `{ pages, urls, forms, params, jsEndpoints, requests }`
 *   options: `{ maxPages, maxDepth, includeForms, includeJs }`
 * - `run(ctx)` → Finding[]（只把爬到的**疑似敏感端点**作为低置信提示，可为空）
 *
 * 约束：
 * - 只访问与目标同源的 http/https URL；
 * - 每页 1 次 ctx.probe，页数不超过剩余请求预算与 maxPages；
 * - 每次 await 后都检查 ctx.signal.aborted；
 * - 跳过图片/样式/字体/压缩包等静态资源；
 * - 不提交表单、不点击链接，只做 GET。
 *
 * 局限：静态 HTML 解析（无 DOM），动态渲染/前端路由生成的链接会漏；
 * 表单只取 input/select/textarea 的 name，不处理 JS 动态字段。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/crawler
 */

import {
  createSession, isHttpResponse, makeFinding, stableSortFindings, handleModuleError,
  queryParamNames, oneLine, readyForMode, asString,
} from './util.js'
import { MARKER } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'crawler',
  title: '同源爬虫',
  kinds: ['crawler', 'recon'],
  cwe: 'CWE-200',
  defaultSeverity: 'info',
  minMode: 'rookie',
}

/** 不爬取的静态资源扩展名。 */
const IGNORE_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
  '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot',
  '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
])

/** 预设的爬取上限（也会被剩余请求预算钳制）。 */
const DEFAULT_MAX_PAGES = 10
const DEFAULT_MAX_DEPTH = 2

/**
 * 读取标签属性值（双引号/单引号/裸值）。
 * @param {string} tag
 * @param {string} name
 * @returns {string}
 */
function attrValue(tag, name) {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')
  const match = pattern.exec(tag)
  if (match === null) return ''
  return asString(match[1] ?? match[2] ?? match[3] ?? '')
}

/**
 * 规范化链接并做同源/协议/静态资源过滤；不合法返回 null。
 * @param {string} href
 * @param {string} pageUrl
 * @param {string} origin
 * @returns {string | null}
 */
function normalizeLink(href, pageUrl, origin) {
  const raw = asString(href).trim()
  if (raw.length === 0 || raw.startsWith('#') || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:')) {
    return null
  }
  let url
  try {
    url = new URL(raw, pageUrl)
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  if (url.origin !== origin) return null
  const path = url.pathname.toLowerCase()
  for (const extension of IGNORE_EXTENSIONS) {
    if (path.endsWith(extension)) return null
  }
  url.hash = ''
  return url.toString()
}

/**
 * 提取 `<a href>` / `<link href>` / `<area href>`。
 * @param {string} html
 * @returns {string[]}
 */
function extractLinks(html) {
  /** @type {string[]} */
  const links = []
  const matcher = /<(?:a|area|link)\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi
  let match
  while ((match = matcher.exec(html)) !== null) {
    const href = match[1] ?? match[2] ?? match[3] ?? ''
    if (href.length > 0) links.push(href)
  }
  return links
}

/**
 * 提取 `<title>`。
 * @param {string} html
 * @returns {string}
 */
function extractTitle(html) {
  const match = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html)
  return match === null ? '' : oneLine(match[1], 120)
}

/**
 * 提取表单：action、method、字段名。
 * @param {string} html
 * @param {string} pageUrl
 * @param {string} origin
 * @returns {Array<{ action: string, method: string, inputs: string[] }>}
 */
function extractForms(html, pageUrl, origin) {
  /** @type {Array<{ action: string, method: string, inputs: string[] }>} */
  const forms = []
  const formMatcher = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi
  let match
  while ((match = formMatcher.exec(html)) !== null) {
    const attributes = match[1] ?? ''
    const inner = match[2] ?? ''
    const actionRaw = attrValue(attributes, 'action')
    const action = normalizeLink(actionRaw, pageUrl, origin) ?? pageUrl
    const method = (attrValue(attributes, 'method') || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET'
    /** @type {Set<string>} */
    const inputs = new Set()
    const fieldMatcher = /<(?:input|select|textarea)\b([^>]*)>/gi
    let field
    while ((field = fieldMatcher.exec(inner)) !== null) {
      const attributesOfField = field[1] ?? ''
      const type = attrValue(attributesOfField, 'type').toLowerCase()
      // 提交类控件不是业务参数，跳过（file 输入保留，上传字段本身是参数）。
      if (type === 'submit' || type === 'button' || type === 'reset' || type === 'image') continue
      const name = attrValue(attributesOfField, 'name')
      if (name.length > 0) inputs.add(name)
    }
    forms.push({ action, method, inputs: [...inputs] })
  }
  return forms
}

/**
 * 从 HTML/脚本里提取同源 API 端点（只做链接发现，不请求）。
 * @param {string} html
 * @param {string} pageUrl
 * @param {string} origin
 * @returns {string[]}
 */
function extractJsEndpoints(html, pageUrl, origin) {
  /** @type {Set<string>} */
  const endpoints = new Set()
  const matcher = /["']((?:\/|https?:\/\/)[^"'\s<>]{2,240})["']/gi
  const apiLike = /\/api(?:\/|$)|\/graphql(?:$|[?#/])|\/v[0-9]+\/|\/rest\/|\/internal\//i
  let match
  while ((match = matcher.exec(html)) !== null) {
    const raw = match[1]
    if (!apiLike.test(raw)) continue
    const normalized = normalizeLink(raw, pageUrl, origin)
    if (normalized !== null) endpoints.add(normalized)
  }
  return [...endpoints]
}

/**
 * 同源 BFS 爬取。
 * @param {object} ctx ProbeContext
 * @param {{ maxPages?: number, maxDepth?: number, includeForms?: boolean, includeJs?: boolean }} [options]
 * @returns {Promise<{
 *   pages: Array<{ url: string, status: number, title: string }>,
 *   urls: string[],
 *   forms: Array<{ action: string, method: string, inputs: string[] }>,
 *   params: Array<{ name: string, location: string, sample: string }>,
 *   jsEndpoints: string[],
 *   requests: number
 * }>}
 */
export async function crawl(ctx, options = {}) {
  const session = createSession(ctx)
  const result = {
    pages: /** @type {Array<{ url: string, status: number, title: string }>} */ ([]),
    urls: /** @type {string[]} */ ([]),
    forms: /** @type {Array<{ action: string, method: string, inputs: string[] }>} */ ([]),
    params: /** @type {Array<{ name: string, location: string, sample: string }>} */ ([]),
    jsEndpoints: /** @type {string[]} */ ([]),
    requests: 0,
  }

  let base
  try {
    base = new URL(String(ctx?.target?.url ?? ''))
  } catch {
    return result
  }
  const origin = base.origin
  const startUrl = new URL(base.toString())
  startUrl.hash = ''

  const maxPagesRaw = Number(options.maxPages ?? DEFAULT_MAX_PAGES)
  const maxPages = Math.min(
    Math.max(1, Number.isFinite(maxPagesRaw) ? Math.trunc(maxPagesRaw) : DEFAULT_MAX_PAGES),
    Math.max(0, session.remaining),
  )
  const maxDepthRaw = Number(options.maxDepth ?? DEFAULT_MAX_DEPTH)
  const maxDepth = Number.isFinite(maxDepthRaw) ? Math.max(0, Math.trunc(maxDepthRaw)) : DEFAULT_MAX_DEPTH
  const includeForms = options.includeForms !== false
  const includeJs = options.includeJs !== false

  /** @type {Array<{ url: string, depth: number }>} */
  const queue = [{ url: startUrl.toString(), depth: 0 }]
  const visited = new Set()
  /** @type {Set<string>} */
  const formKeys = new Set()
  /** @type {Map<string, { name: string, location: string, sample: string }>} */
  const params = new Map()

  const addParamsFromUrl = (pageUrl) => {
    for (const name of queryParamNames(pageUrl)) {
      const key = `${name}\u0000query`
      if (!params.has(key)) params.set(key, { name, location: 'query', sample: '1' })
    }
  }

  while (queue.length > 0 && result.pages.length < maxPages && !session.aborted) {
    const current = /** @type {{ url: string, depth: number }} */ (queue.shift())
    if (visited.has(current.url)) continue
    visited.add(current.url)
    addParamsFromUrl(current.url)

    const response = await session.probe(current.url, { method: 'GET' })
    if (!response) break
    if (!isHttpResponse(response)) {
      result.urls.push(current.url)
      continue
    }
    const pageUrl = response.url.length > 0 ? response.url : current.url
    const html = response.body
    result.pages.push({ url: pageUrl, status: response.status, title: extractTitle(html) })
    result.urls.push(current.url)

    if (current.depth < maxDepth) {
      for (const href of extractLinks(html)) {
        const nextUrl = normalizeLink(href, pageUrl, origin)
        if (nextUrl !== null && !visited.has(nextUrl)) queue.push({ url: nextUrl, depth: current.depth + 1 })
      }
    }

    if (includeForms) {
      for (const form of extractForms(html, pageUrl, origin)) {
        const key = `${form.method} ${form.action} ${form.inputs.join(',')}`
        if (formKeys.has(key)) continue
        formKeys.add(key)
        result.forms.push(form)
        for (const name of form.inputs) {
          const location = form.method === 'POST' ? 'body' : 'query'
          const paramKey = `${name}\u0000${location}`
          if (!params.has(paramKey)) params.set(paramKey, { name, location, sample: '1' })
        }
      }
    }

    if (includeJs) {
      for (const endpoint of extractJsEndpoints(html, pageUrl, origin)) {
        if (!result.jsEndpoints.includes(endpoint)) result.jsEndpoints.push(endpoint)
      }
    }
  }

  result.params = [...params.values()]
  result.requests = session.used
  return result
}

/** run() 里只做有限爬取，避免和工具层 crawl 重复消耗大量预算。 */
const RUN_MAX_PAGES = 4

/** 疑似敏感端点规则（仅提示，不验证可访问性）。 */
const RISKY_ENDPOINT_RULES = [
  { re: /(?:^|\/)\.git\//i, label: 'Git 仓库元数据', severity: 'medium' },
  { re: /(?:^|\/)\.env(?:$|[?#])/i, label: '环境变量文件', severity: 'high' },
  { re: /(?:^|\/)(?:server-status|actuator|debug|console)(?:\/|$)/i, label: '调试/管理端点', severity: 'medium' },
  { re: /(?:^|\/)(?:phpinfo|swagger|openapi|graphiql|graphql)(?:\/|$|\.)/i, label: 'API/调试入口', severity: 'low' },
]

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  /** @type {object[]} */
  const findings = []
  try {
    const crawled = await crawl(ctx, {
      maxPages: RUN_MAX_PAGES,
      maxDepth: 1,
      includeForms: true,
      includeJs: true,
    })
    const candidates = [
      ...crawled.urls,
      ...crawled.jsEndpoints,
      ...crawled.forms.map((form) => form.action),
    ]
    /** @type {Set<string>} */
    const seen = new Set()
    for (const candidate of candidates) {
      for (const rule of RISKY_ENDPOINT_RULES) {
        if (!rule.re.test(candidate)) continue
        const key = `${rule.label}\u0000${candidate}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push(makeFinding({
          module: meta.id,
          checkId: 'crawler-risky-endpoint',
          title: `爬取到疑似敏感端点（${rule.label}）`,
          severity: rule.severity,
          confidence: 'low',
          url: candidate,
          evidence: `爬虫链接发现 ${candidate}（${rule.label}）。仅代表 URL 被页面引用，尚未验证可访问性，需人工或用目录探测任务确认。共爬取 ${crawled.pages.length} 页 / ${crawled.requests} 次请求。`,
          cwe: meta.cwe,
          remediation: '确认该端点不应公开后，移除链接/文件并加访问控制。',
        }))
        break
      }
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

// 供其他模块复用的常量（参数挖掘会用到 marker 前缀的确定性测试值）。
export { MARKER as crawlerMarker }

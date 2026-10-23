/**
 * 技术栈指纹识别（响应头 / body / cookie / 路径线索）。
 *
 * 检测原理：
 * 只发 1 个 GET 请求，从响应里匹配**强特征**：
 * - 响应头：Server、X-Powered-By、X-AspNet-Version、X-Generator、X-Jenkins 等；
 * - Cookie 名：PHPSESSID→PHP、JSESSIONID→Java、laravel_session→Laravel 等；
 * - body：WordPress 的 wp-content、Next.js 的 __NEXT_DATA__、Django 的
 *   csrfmiddlewaretoken 等几乎不会出现在无关站点里的固定标记。
 *
 * 对外接口：
 * - `fingerprint(ctx)` → `[{ name, confidence: 'low'|'medium'|'high', evidence }]`
 * - `run(ctx)` → Finding[]（聚合指纹 + 版本号泄露提示）
 *
 * 局限：
 * - 只根据单页响应推断，反向代理/自定义头可能掩盖真实技术栈；
 * - 只报"能自证"的标记，不确定时不猜版本，宁可漏报；
 * - 不探测 favicon hash、不做主动路径枚举（目录任务由工具层负责）。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/tech-fingerprint
 */

import {
  createSession, isHttpResponse, headerValue, makeFinding, stableSortFindings,
  handleModuleError, oneLine, readyForMode,
} from './util.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'tech-fingerprint',
  title: '技术栈指纹识别',
  kinds: ['tech', 'fingerprint', 'recon'],
  cwe: 'CWE-200',
  defaultSeverity: 'info',
  minMode: 'rookie',
}

/** 置信度排序，用于同名指纹去重。 */
const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 }

/**
 * 指纹规则。`source` 指明从哪个位置匹配，便于 evidence 可复核。
 * @type {Array<{
 *   name: string, confidence: 'low'|'medium'|'high',
 *   source: 'header'|'cookie'|'body', key?: string, re: RegExp
 * }>}
 */
const FINGERPRINTS = [
  // 服务器 / 反向代理
  { name: 'nginx', confidence: 'high', source: 'header', key: 'server', re: /nginx(?:\/[\d.]+)?/i },
  { name: 'Apache httpd', confidence: 'high', source: 'header', key: 'server', re: /apache(?:\/[\d.]+)?/i },
  { name: 'Microsoft IIS', confidence: 'high', source: 'header', key: 'server', re: /microsoft-iis(?:\/[\d.]+)?/i },
  { name: 'Caddy', confidence: 'high', source: 'header', key: 'server', re: /caddy/i },
  { name: 'LiteSpeed', confidence: 'high', source: 'header', key: 'server', re: /litespeed/i },
  { name: 'OpenResty', confidence: 'high', source: 'header', key: 'server', re: /openresty/i },
  { name: 'Cloudflare', confidence: 'high', source: 'header', key: 'cf-ray', re: /[a-f0-9]{8,}/i },
  { name: 'Amazon CloudFront', confidence: 'high', source: 'header', key: 'x-amz-cf-id', re: /[\w-]{8,}/ },
  { name: 'Varnish', confidence: 'medium', source: 'header', key: 'x-varnish', re: /\d+/ },

  // 语言 / 框架（响应头）
  { name: 'PHP', confidence: 'high', source: 'header', key: 'x-powered-by', re: /php(?:\/[\d.]+)?/i },
  { name: 'Express', confidence: 'high', source: 'header', key: 'x-powered-by', re: /express/i },
  { name: 'ASP.NET', confidence: 'high', source: 'header', key: 'x-aspnet-version', re: /[\d.]+/ },
  { name: 'ASP.NET', confidence: 'medium', source: 'header', key: 'x-powered-by', re: /asp\.net/i },
  { name: 'Servlet/JSP', confidence: 'medium', source: 'header', key: 'x-powered-by', re: /servlet\/?[\d.]*/i },
  { name: 'Jenkins', confidence: 'high', source: 'header', key: 'x-jenkins', re: /[\d.]+/ },
  { name: 'Drupal', confidence: 'high', source: 'header', key: 'x-generator', re: /drupal(?:\s+[\d.]+)?/i },

  // 会话 Cookie
  { name: 'PHP', confidence: 'high', source: 'cookie', re: /\bphpsessid=/i },
  { name: 'Java', confidence: 'high', source: 'cookie', re: /\bjsessionid=/i },
  { name: 'ASP.NET', confidence: 'high', source: 'cookie', re: /\basp\.net_sessionid=/i },
  { name: 'Laravel', confidence: 'high', source: 'cookie', re: /\blaravel_session=/i },
  { name: 'CodeIgniter', confidence: 'medium', source: 'cookie', re: /\bci_session=/i },
  { name: 'Ruby on Rails', confidence: 'medium', source: 'cookie', re: /\b_rails|_session_id=/i },
  { name: 'Express', confidence: 'medium', source: 'cookie', re: /\bconnect\.sid=/i },
  { name: 'Django', confidence: 'medium', source: 'cookie', re: /\bcsrftoken=/i },

  // body 固定标记
  { name: 'WordPress', confidence: 'medium', source: 'body', re: /wp-content\/|wp-includes\//i },
  { name: 'Drupal', confidence: 'medium', source: 'body', re: /drupal-settings-json|sites\/default\/files/i },
  { name: 'Next.js', confidence: 'medium', source: 'body', re: /__NEXT_DATA__|_next\/static\//i },
  { name: 'React', confidence: 'medium', source: 'body', re: /data-reactroot|react\.production(?:\.min)?\.js/i },
  { name: 'Vue.js', confidence: 'medium', source: 'body', re: /__VUE__|vue(?:\.runtime)?(?:\.min)?\.js/i },
  { name: 'Angular', confidence: 'medium', source: 'body', re: /ng-version=|\/angular(?:\.min)?\.js/i },
  { name: 'Django', confidence: 'medium', source: 'body', re: /csrfmiddlewaretoken/i },
  { name: 'Ruby on Rails', confidence: 'medium', source: 'body', re: /name="csrf-token"/i },
  { name: 'Spring Boot', confidence: 'medium', source: 'body', re: /Whitelabel Error Page|spring-boot/i },
  { name: 'Tomcat', confidence: 'medium', source: 'body', re: /Apache Tomcat\/[\d.]+/i },
  { name: 'Jenkins', confidence: 'medium', source: 'body', re: /jenkins-(?:agent|core)|Jenkins<\/title>/i },
  { name: 'Grafana', confidence: 'medium', source: 'body', re: /grafana(?:\.min)?\.js|"appSubUrl":"[^"]*"/i },
  { name: 'Swagger UI', confidence: 'medium', source: 'body', re: /swagger-ui(?:-bundle)?\.js|swagger-ui\.css/i },
  { name: 'phpMyAdmin', confidence: 'medium', source: 'body', re: /phpmyadmin/i },
]

/**
 * 对响应做指纹分析（内部共用：只请求一次）。
 * @param {object} ctx
 * @returns {Promise<{ items: Array<{ name: string, confidence: string, evidence: string }>, headers: Record<string, string> }>}
 */
async function analyze(ctx) {
  const session = createSession(ctx)
  const empty = { items: /** @type {Array<{ name: string, confidence: string, evidence: string }>} */ ([]), headers: {} }
  if (session.remaining <= 0) return empty
  const response = await session.probe(String(ctx?.target?.url ?? ''), { method: 'GET' })
  if (!response || !isHttpResponse(response)) return empty

  const cookie = headerValue(response, 'set-cookie')
  /** @type {Map<string, { name: string, confidence: string, evidence: string }>} */
  const matched = new Map()

  for (const rule of FINGERPRINTS) {
    let matchText = ''
    let location = ''
    if (rule.source === 'header') {
      const value = headerValue(response, rule.key ?? '')
      const match = rule.re.exec(value)
      if (match !== null) {
        matchText = match[0]
        location = `响应头 ${rule.key}="${oneLine(value, 100)}"`
      }
    } else if (rule.source === 'cookie') {
      const match = rule.re.exec(cookie)
      if (match !== null) {
        matchText = match[0]
        location = `Set-Cookie="${oneLine(cookie, 100)}"`
      }
    } else {
      const match = rule.re.exec(response.body)
      if (match !== null) {
        matchText = match[0]
        location = `响应体命中「${oneLine(matchText, 60)}」`
      }
    }
    if (matchText.length === 0) continue
    const candidate = {
      name: rule.name,
      confidence: rule.confidence,
      evidence: `${location}（匹配「${oneLine(matchText, 60)}」）`,
    }
    const existing = matched.get(rule.name)
    if (existing === undefined || CONFIDENCE_RANK[rule.confidence] > CONFIDENCE_RANK[existing.confidence]) {
      matched.set(rule.name, candidate)
    }
  }

  return { items: [...matched.values()], headers: response.headers }
}

/**
 * 公开指纹接口：返回 `[{ name, confidence, evidence }]`（按名称稳定排序）。
 * @param {object} ctx ProbeContext
 * @returns {Promise<Array<{ name: string, confidence: string, evidence: string }>>}
 */
export async function fingerprint(ctx) {
  try {
    const result = await analyze(ctx)
    return result.items.slice().sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
    return []
  }
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  /** @type {object[]} */
  const findings = []
  try {
    const result = await analyze(ctx)
    const items = result.items.slice().sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
    if (items.length > 0) {
      const summary = items.map((item) => `${item.name}(${item.confidence})`).join('、')
      const detail = items.map((item) => item.evidence).join('；')
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'tech-fingerprint',
        title: '技术栈指纹',
        severity: 'info',
        confidence: 'medium',
        url: String(ctx?.target?.url ?? ''),
        evidence: `识别到：${summary}。依据：${detail}。`,
        cwe: meta.cwe,
        remediation: '移除不必要的版本/框架标识响应头，降低被针对性攻击面。',
      }))
    }

    // 版本号泄露：只在响应头明确带数字版本时提示。
    const versionSources = [
      { key: 'server', value: headerValue({ headers: result.headers }, 'server') },
      { key: 'x-powered-by', value: headerValue({ headers: result.headers }, 'x-powered-by') },
      { key: 'x-aspnet-version', value: headerValue({ headers: result.headers }, 'x-aspnet-version') },
    ].filter((entry) => entry.value.length > 0 && /\d+\.\d+/.test(entry.value))
    if (versionSources.length > 0) {
      const detail = versionSources.map((entry) => `${entry.key}="${oneLine(entry.value, 80)}"`).join('；')
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'tech-version-disclosure',
        title: '响应头泄露中间件/框架版本',
        severity: 'low',
        confidence: 'high',
        url: String(ctx?.target?.url ?? ''),
        evidence: `响应头包含精确版本号：${detail}，便于攻击者匹配已知漏洞。`,
        cwe: meta.cwe,
        remediation: '关闭 server_tokens / 移除 X-Powered-By 等版本标识，或仅暴露产品名。',
      }))
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

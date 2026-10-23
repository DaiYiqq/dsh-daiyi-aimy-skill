/**
 * 引擎公共工具层。
 *
 * 定位：所有检测模块共用的**纯函数**与请求会话脚手架。
 * - 只处理传入的数据，不发起网络请求（网络只能走 ctx.probe）；
 * - 不依赖任何第三方模块，也不 import lib/http.js；
 * - 不使用 Date.now / Math.random 参与判定，保证同一输入同一输出。
 *
 * 主要能力：
 * 1. createSession(ctx)：请求预算（≤ limits.maxRequests）、AbortSignal 检查、
 *    响应归一化；预算耗尽或取消时 probe() 返回 null，模块据此尽快退出。
 * 2. 参数拼装：query / body / json 三种 ParamSpec 位置统一走 sendParamValue()。
 * 3. 文本工具：HTML 实体解码、相似度、片段截取、evidence 截断（≤800 字符）。
 * 4. 结果排序：stableSortFindings() 让 Finding 输出顺序稳定可复现。
 *
 * 局限：相似度使用 bigram Dice 系数，只是**启发式**，不能证明页面语义相同；
 * 判定阈值在模块里显式给出，工具层不得依赖这里的默认值做安全结论。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/util
 */

/** Finding.evidence 的硬性长度上限（见 docs/CONTRACT.md 2.4）。 */
export const EVIDENCE_MAX = 800

/** 运行模式顺序：数值越大越激进。 */
const MODE_RANK = { rookie: 0, veteran: 1 }

/** 不参与注入测试的通用表单字段（提交按钮、CSRF 等）。 */
const SKIP_PARAM_NAMES = new Set([
  'submit', 'button', 'reset', 'image', 'file', 'action', '_method', 'utf8',
  'commit', 'form_id', 'form_build_id', 'form_token', 'authenticity_token',
  'csrf', 'csrf_token', '_token', '__requestverificationtoken', 'g-recaptcha-response',
])

/**
 * 判断当前运行模式是否达到模块要求的最低模式。
 * @param {'rookie' | 'veteran'} [mode]
 * @param {'rookie' | 'veteran'} [minMode]
 * @returns {boolean}
 */
export function modeAtLeast(mode, minMode) {
  return (MODE_RANK[mode] ?? 0) >= (MODE_RANK[minMode] ?? 0)
}

/**
 * 模块入口的保守模式闸门：低于 minMode 直接返回空数组。
 * @param {object} ctx
 * @param {'rookie' | 'veteran'} minMode
 * @returns {boolean}
 */
export function readyForMode(ctx, minMode) {
  return modeAtLeast(ctx?.mode, minMode)
}

/**
 * 统一转字符串，永不抛错。
 * @param {unknown} value
 * @returns {string}
 */
export function asString(value) {
  if (typeof value === 'string') return value
  if (value === null || value === undefined) return ''
  return String(value)
}

/**
 * 截断文本（按字符），用于 evidence 与片段展示。
 * @param {unknown} value
 * @param {number} [max]
 * @returns {string}
 */
export function clipText(value, max = EVIDENCE_MAX) {
  const text = asString(value)
  if (text.length <= max) return text
  if (max <= 3) return text.slice(0, Math.max(0, max))
  return `${text.slice(0, max - 3)}...`
}

/**
 * 把任意文本压成一行，便于写进 evidence。
 * @param {unknown} value
 * @param {number} [max]
 * @returns {string}
 */
export function oneLine(value, max = 160) {
  return clipText(asString(value).replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim(), max)
}

/**
 * 截取 needle 附近的文本片段（默认左右各 50 字符），找不到时返回空串。
 * @param {string} text
 * @param {string} needle
 * @param {number} [radius]
 * @returns {string}
 */
export function snippetAround(text, needle, radius = 50) {
  const haystack = asString(text)
  const target = asString(needle)
  if (target.length === 0) return ''
  const index = haystack.indexOf(target)
  if (index < 0) return ''
  const start = Math.max(0, index - radius)
  const end = Math.min(haystack.length, index + target.length + radius)
  return haystack.slice(start, end).replace(/\s+/g, ' ')
}

/**
 * 小写化响应头 key；数组值用逗号连接，保证可比较。
 * @param {unknown} headers
 * @returns {Record<string, string>}
 */
export function normalizeHeaders(headers) {
  /** @type {Record<string, string>} */
  const out = {}
  if (headers === null || typeof headers !== 'object') return out
  for (const key of Object.keys(headers)) {
    const value = /** @type {Record<string, unknown>} */ (headers)[key]
    if (value === null || value === undefined) continue
    out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(', ') : asString(value)
  }
  return out
}

/**
 * 读取某个响应头（大小写不敏感）。
 * @param {{ headers?: Record<string, string> } | null | undefined} response
 * @param {string} name
 * @returns {string}
 */
export function headerValue(response, name) {
  if (!response || typeof response !== 'object') return ''
  const key = name.toLowerCase()
  const headers = response.headers ?? {}
  if (typeof headers.get === 'function') {
    // 兼容 Headers 实例
    return asString(/** @type {{ get: (k: string) => string | null }} */ (headers).get(key))
  }
  return asString(normalizeHeaders(headers)[key])
}

/**
 * 把探针返回值归一化成契约里的 ProbeResponse 形状；缺失字段用安全默认值。
 * @param {unknown} response
 * @param {string} requestUrl
 * @param {{ method?: string } | undefined} init
 * @returns {{
 *   method: string, url: string, status: number, headers: Record<string, string>,
 *   body: string, elapsedMs: number, truncated: boolean, error?: string
 * }}
 */
export function normalizeResponse(response, requestUrl, init) {
  const raw = response !== null && typeof response === 'object' ? /** @type {Record<string, unknown>} */ (response) : {}
  const status = Number.isFinite(raw.status) ? Number(raw.status) : 0
  const out = {
    method: asString(raw.method || init?.method || 'GET').toUpperCase(),
    url: asString(raw.url || requestUrl),
    status,
    headers: normalizeHeaders(raw.headers),
    body: asString(raw.body),
    elapsedMs: Number.isFinite(raw.elapsedMs) ? Number(raw.elapsedMs) : 0,
    truncated: raw.truncated === true,
  }
  if (raw.error !== undefined && raw.error !== null && asString(raw.error).length > 0) {
    out.error = asString(raw.error)
  }
  return out
}

/**
 * 创建一次模块运行内的请求会话。
 *
 * 语义：
 * - 最多发 limits.maxRequests 次请求（默认 40，见契约）；超预算后 probe() 返回 null；
 * - 每次 await 之后检查 ctx.signal.aborted，一旦取消，后续 probe() 统一返回 null；
 * - 网络层异常折算成 status=0 的响应（与 lib/http.js 的超时语义一致），
 *   但预算/取消/范围这类**全局失败**原样抛出，避免被模块静默吞掉。
 *
 * @param {object} ctx ProbeContext
 * @returns {{
 *   ctx: object,
 *   maxRequests: number,
 *   used: number,
 *   remaining: number,
 *   aborted: boolean,
 *   probe: (url: string | URL, init?: object) => Promise<ReturnType<typeof normalizeResponse> | null>
 * }}
 */
export function createSession(ctx) {
  const limits = ctx?.limits ?? {}
  const maxRequests = Number.isFinite(limits.maxRequests)
    ? Math.max(0, Math.trunc(Number(limits.maxRequests)))
    : 40
  let used = 0
  let stopped = false
  const externalAborted = () => ctx?.signal?.aborted === true

  const session = {
    ctx,
    get maxRequests() {
      return maxRequests
    },
    get used() {
      return used
    },
    get remaining() {
      return Math.max(0, maxRequests - used)
    },
    get aborted() {
      return stopped || externalAborted()
    },
    /**
     * @param {string | URL} url
     * @param {object} [init]
     * @returns {Promise<ReturnType<typeof normalizeResponse> | null>}
     */
    async probe(url, init) {
      if (session.aborted) return null
      if (used >= maxRequests) return null
      if (typeof ctx?.probe !== 'function') {
        stopped = true
        return null
      }
      used += 1
      let raw
      try {
        raw = await ctx.probe(url, init)
      } catch (error) {
        if (externalAborted()) {
          stopped = true
          return null
        }
        const code = asString(error?.code)
        const name = asString(error?.name)
        // 这些是宿主护栏的全局失败，必须冒泡，不能被当成网络错误继续扫。
        if (code === 'BUDGET_EXCEEDED' || code === 'CANCELLED' || code === 'SCOPE_DENIED' || code === 'INVALID_TARGET') {
          throw error
        }
        if (name === 'CancelledError' || name === 'BudgetError' || name === 'ScopeError') throw error
        raw = {
          method: init?.method ?? 'GET',
          url: asString(url),
          status: 0,
          headers: {},
          body: '',
          elapsedMs: 0,
          truncated: false,
          error: asString(error?.message ?? error) || 'probe failed',
        }
      }
      // 契约要求：每次 await 后检查取消信号，取消则立刻退出。
      if (externalAborted()) {
        stopped = true
        return null
      }
      return normalizeResponse(raw, asString(url), init)
    },
  }
  return session
}

/**
 * 取需要测试的参数列表：过滤提交/CSRF 字段，限制数量（控制请求预算）。
 * @param {object} ctx
 * @param {number} [limitPerModule]
 * @returns {Array<{ name: string, location: string, sample: string }>}
 */
export function pickParams(ctx, limitPerModule = 3) {
  const params = Array.isArray(ctx?.params) ? ctx.params : []
  /** @type {Array<{ name: string, location: string, sample: string }>} */
  const picked = []
  for (const spec of params) {
    if (!spec || typeof spec.name !== 'string' || spec.name.length === 0) continue
    if (SKIP_PARAM_NAMES.has(spec.name.toLowerCase())) continue
    picked.push({
      name: spec.name,
      location: spec.location === 'body' || spec.location === 'json' ? spec.location : 'query',
      sample: typeof spec.sample === 'string' && spec.sample.length > 0 ? spec.sample : '1',
    })
    if (picked.length >= Math.max(0, limitPerModule)) break
  }
  return picked
}

/**
 * 在 URL 上设置查询参数（保留其它参数），返回字符串 URL。
 * @param {string | URL} baseUrl
 * @param {string} name
 * @param {string} value
 * @returns {string}
 */
export function setQueryParam(baseUrl, name, value) {
  const url = new URL(asString(baseUrl))
  url.searchParams.set(name, asString(value))
  return url.toString()
}

/**
 * 构造一个"带参数"的请求目标（工具层与模块共用）。
 *
 * - `location === 'query'`：返回 GET 目标，url 已带上参数；
 * - `location === 'body'`：返回 POST + form-urlencoded body；
 * - `location === 'json'`：返回 POST + JSON body。
 *
 * 返回 `{ url, init }`，直接交给 ctx.probe(url, init) 即可。
 *
 * @param {string | URL} url 目标 URL
 * @param {string} name 参数名
 * @param {unknown} value 参数值（json 位置允许对象）
 * @param {'query' | 'body' | 'json'} [location]
 * @returns {{ url: string, init: Record<string, unknown> | undefined }}
 */
export function withParam(url, name, value, location = 'query') {
  const baseUrl = asString(url)
  const paramName = asString(name)
  if (location === 'json') {
    return {
      url: baseUrl,
      init: {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ [paramName]: value }),
      },
    }
  }
  if (location === 'body') {
    return {
      url: baseUrl,
      init: {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: encodeForm({ [paramName]: value }),
      },
    }
  }
  return { url: setQueryParam(baseUrl, paramName, asString(value)), init: undefined }
}

/**
 * 读取 URL 的查询参数名（保持出现顺序、去重）。
 * @param {string | URL} rawUrl
 * @returns {string[]}
 */
export function queryParamNames(rawUrl) {
  /** @type {string[]} */
  const names = []
  try {
    const url = new URL(asString(rawUrl))
    for (const key of url.searchParams.keys()) {
      if (!names.includes(key)) names.push(key)
    }
  } catch {
    return []
  }
  return names
}

/**
 * form-urlencoded 编码（key 顺序按对象插入顺序，保证确定性）。
 * @param {Record<string, unknown>} fields
 * @returns {string}
 */
export function encodeForm(fields) {
  return Object.keys(fields)
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(asString(fields[key]))}`)
    .join('&')
}

/**
 * 构造同位置其它参数的基线值，避免 POST/JSON 请求因为缺少其它必填字段而误判。
 * @param {object} ctx
 * @param {{ name: string, location: string, sample: string }} spec
 * @param {string} location
 * @returns {Record<string, unknown>}
 */
export function siblingFields(ctx, spec, location) {
  /** @type {Record<string, unknown>} */
  const fields = {}
  const params = Array.isArray(ctx?.params) ? ctx.params : []
  for (const param of params) {
    if (!param || typeof param.name !== 'string') continue
    const paramLocation = param.location === 'body' || param.location === 'json' ? param.location : 'query'
    if (paramLocation !== location) continue
    fields[param.name] = typeof param.sample === 'string' && param.sample.length > 0 ? param.sample : '1'
  }
  fields[spec.name] = spec.sample
  return fields
}

/**
 * 按 ParamSpec 的位置发送一次探测请求。
 *
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location?: string, sample?: string }} spec
 * @param {unknown} value 值；json 位置允许传对象
 * @returns {Promise<ReturnType<typeof normalizeResponse> | null>}
 */
export async function sendParamValue(session, spec, value) {
  const ctx = session.ctx
  const baseUrl = asString(ctx?.target?.url)
  const name = asString(spec?.name)
  if (name.length === 0 || baseUrl.length === 0) return null
  const location = spec?.location === 'body' || spec?.location === 'json' ? spec.location : 'query'

  if (location === 'query') {
    return session.probe(setQueryParam(baseUrl, name, asString(value)), { method: 'GET' })
  }

  if (location === 'json') {
    const fields = siblingFields(ctx, { name, location, sample: asString(spec?.sample ?? '1') }, 'json')
    fields[name] = value
    return session.probe(baseUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(fields),
    })
  }

  const fields = siblingFields(ctx, { name, location, sample: asString(spec?.sample ?? '1') }, 'body')
  fields[name] = value
  return session.probe(baseUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: encodeForm(fields),
  })
}

/**
 * 对同一参数发送基线请求（使用题面给的 sample，缺失时用 '1'）。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location?: string, sample?: string }} spec
 * @returns {Promise<ReturnType<typeof normalizeResponse> | null>}
 */
export function sendParamBaseline(session, spec) {
  const sample = typeof spec?.sample === 'string' && spec.sample.length > 0 ? spec.sample : '1'
  return sendParamValue(session, spec, sample)
}

/**
 * 解码常见 HTML 实体，用于 XSS 编码检测。
 * @param {string} text
 * @returns {string}
 */
export function decodeHtmlEntities(text) {
  return asString(text).replace(/&(?:#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);/g, (entity) => {
    const body = entity.slice(1, -1)
    if (body[0] === '#') {
      const hex = body[1] === 'x' || body[1] === 'X'
      const codePoint = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10)
      if (Number.isFinite(codePoint) && codePoint > 0 && codePoint <= 0x10ffff) {
        try {
          return String.fromCodePoint(codePoint)
        } catch {
          return entity
        }
      }
      return entity
    }
    const named = {
      lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ',
      colon: ':', sol: '/', lpar: '(', rpar: ')',
    }
    return Object.prototype.hasOwnProperty.call(named, body) ? named[body] : entity
  })
}

/**
 * 把文本压成只保留小写字母数字与单空格的比较串。
 * @param {unknown} value
 * @returns {string}
 */
function comparableText(value) {
  return asString(value).toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g, ' ').trim()
}

/**
 * bigram Dice 相似度，范围 0..1。
 * 只是启发式：1 表示字符二元组分布一致，不代表语义完全一致。
 * @param {unknown} left
 * @param {unknown} right
 * @returns {number}
 */
export function similarity(left, right) {
  const a = comparableText(left).slice(0, 8000)
  const b = comparableText(right).slice(0, 8000)
  if (a.length === 0 && b.length === 0) return 1
  if (a.length === 0 || b.length === 0) return 0
  if (a === b) return 1
  /** @type {Map<string, number>} */
  const grams = new Map()
  let totalA = 0
  for (let index = 0; index + 1 < a.length; index += 1) {
    const gram = a.slice(index, index + 2)
    grams.set(gram, (grams.get(gram) ?? 0) + 1)
    totalA += 1
  }
  let totalB = 0
  let overlap = 0
  for (let index = 0; index + 1 < b.length; index += 1) {
    const gram = b.slice(index, index + 2)
    totalB += 1
    const remaining = grams.get(gram) ?? 0
    if (remaining > 0) {
      overlap += 1
      grams.set(gram, remaining - 1)
    }
  }
  if (totalA + totalB === 0) return 1
  return (2 * overlap) / (totalA + totalB)
}

/**
 * 判断两个 URL 是否同源。
 * @param {string | URL} left
 * @param {string | URL} right
 * @returns {boolean}
 */
export function sameOrigin(left, right) {
  try {
    const a = new URL(asString(left))
    const b = new URL(asString(right))
    return a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port
  } catch {
    return false
  }
}

/**
 * 判断主机名是否属于回环 / 私网 / 链路本地地址（离线判断，不做 DNS 解析）。
 * @param {string} host
 * @returns {boolean}
 */
export function isInternalHost(host) {
  const value = asString(host).trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (value === '' || value === 'localhost' || value.endsWith('.localhost')) return true
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value)
  if (ipv4 !== null) {
    const octets = ipv4.slice(1).map((part) => Number.parseInt(part, 10))
    if (octets.some((octet) => octet > 255)) return false
    const [a, b] = octets
    if (a === 10 || a === 127 || a === 0) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    return false
  }
  if (value === '::1' || value === '::') return true
  if (value.startsWith('fe80:') || value.startsWith('fc') || value.startsWith('fd')) return true
  if (value.startsWith('::ffff:')) return isInternalHost(value.slice('::ffff:'.length))
  return false
}

/**
 * 安全 JSON 解析；失败返回 null，不抛错。
 * @param {unknown} text
 * @returns {unknown}
 */
export function safeJsonParse(text) {
  try {
    return JSON.parse(asString(text))
  } catch {
    return null
  }
}

/**
 * 数组去重并保持首次出现顺序。
 * @template T
 * @param {T[]} items
 * @returns {T[]}
 */
export function unique(items) {
  return Array.from(new Set(items))
}

/**
 * 从响应头 date 字段解析参考时间（毫秒）；不存在或非法时返回 null。
 * 注意：这里**不使用 Date.now**，因此同一响应得到同一参考时间，判定可复现。
 * @param {{ headers?: Record<string, string> } | null | undefined} response
 * @returns {number | null}
 */
export function referenceTimeFromHeaders(response) {
  const raw = headerValue(response, 'date')
  if (raw.length === 0) return null
  const parsed = Date.parse(raw)
  return Number.isFinite(parsed) ? parsed : null
}

/**
 * 在文本中匹配签名列表，返回全部命中（顺序按签名定义）。
 * @param {string} text
 * @param {Array<{ id: string, re: RegExp } | RegExp>} signatures
 * @returns {Array<{ id: string, match: string }>}
 */
export function matchSignatures(text, signatures) {
  const haystack = asString(text)
  /** @type {Array<{ id: string, match: string }>} */
  const hits = []
  for (const signature of signatures) {
    const re = signature instanceof RegExp ? signature : signature.re
    const id = signature instanceof RegExp ? signature.source : signature.id
    // 每次使用新的 RegExp，避免 /g 状态残留导致的非确定性。
    const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`
    const matcher = new RegExp(re.source, flags)
    const found = matcher.exec(haystack)
    if (found !== null) hits.push({ id, match: found[0] })
  }
  return hits
}

/**
 * 生成一个 Finding；evidence 强制 ≤800 字符，字段按契约裁剪。
 * @param {{
 *   module: string, checkId: string, title: string, severity: string, confidence: string,
 *   url: string | URL, param?: string, payload?: string, evidence: string,
 *   cwe?: string, remediation?: string, confirmed?: boolean
 * }} input
 * @returns {object}
 */
export function makeFinding(input) {
  /** @type {Record<string, unknown>} */
  const finding = {
    module: asString(input.module),
    checkId: asString(input.checkId),
    title: asString(input.title),
    severity: input.severity,
    confidence: input.confidence,
    url: asString(input.url),
    evidence: clipText(input.evidence, EVIDENCE_MAX),
  }
  if (input.param !== undefined && input.param !== null && asString(input.param).length > 0) {
    finding.param = asString(input.param)
  }
  if (input.payload !== undefined && input.payload !== null) {
    finding.payload = clipText(input.payload, 200)
  }
  if (input.cwe !== undefined) finding.cwe = input.cwe
  if (input.remediation !== undefined) finding.remediation = input.remediation
  if (input.confirmed === true) finding.confirmed = true
  return finding
}

/**
 * 稳定排序：keyFn 相同的结果保持原相对顺序（用原始下标兜底）。
 * 不依赖 Array.prototype.sort 的稳定性实现，保证跨运行时确定性。
 * @template T
 * @param {T[]} items
 * @param {(item: T) => unknown} [keyFn]
 * @returns {T[]}
 */
export function stableSort(items, keyFn) {
  const list = Array.isArray(items) ? items.slice() : []
  const decorate = list.map((value, index) => ({
    value,
    index,
    key: keyFn ? asString(keyFn(value)) : asString(value),
  }))
  decorate.sort((left, right) => {
    if (left.key < right.key) return -1
    if (left.key > right.key) return 1
    return left.index - right.index
  })
  return decorate.map((entry) => entry.value)
}

/**
 * 稳定排序 Finding：同一输入的输出顺序固定。
 * 排序键按 contract 里最常用于聚合的字段排列。
 * @param {Array<Record<string, unknown>>} findings
 * @returns {Array<Record<string, unknown>>}
 */
export function stableSortFindings(findings) {
  return stableSort(findings, (finding) => {
    const keys = ['module', 'checkId', 'url', 'param', 'payload', 'evidence']
    return keys.map((key) => asString(finding?.[key])).join('\u0000')
  })
}

/**
 * 统一的响应摘要（写 evidence 用）。
 * @param {{ status?: number, body?: string, elapsedMs?: number } | null | undefined} response
 * @returns {string}
 */
export function describeResponse(response) {
  if (!response) return '无响应'
  const status = Number.isFinite(response.status) ? response.status : 0
  const length = asString(response.body).length
  const elapsed = Number.isFinite(response.elapsedMs) ? response.elapsedMs : 0
  return `status=${status} len=${length}B ${Math.round(elapsed)}ms`
}

/**
 * 判断响应是否是有效 HTTP 响应（非网络失败）。
 * @param {{ status?: number } | null | undefined} response
 * @returns {boolean}
 */
export function isHttpResponse(response) {
  return Boolean(response) && Number(response.status) > 0
}

/**
 * 安全日志；ctx.log 缺失时静默。
 * @param {object} ctx
 * @param {'debug' | 'info' | 'warn'} level
 * @param {string} message
 */
export function log(ctx, level, message) {
  if (ctx && typeof ctx.log === 'function') ctx.log(level, message)
}

/**
 * 判断异常是否是宿主护栏的全局失败（预算/取消/范围）。
 * 这类异常必须冒泡给工具层，模块不得吞掉后继续扫。
 * @param {unknown} error
 * @returns {boolean}
 */
export function isGlobalEngineError(error) {
  const code = asString(error?.code)
  const name = asString(error?.name)
  return (
    code === 'BUDGET_EXCEEDED' ||
    code === 'CANCELLED' ||
    code === 'SCOPE_DENIED' ||
    code === 'INVALID_TARGET' ||
    name === 'BudgetError' ||
    name === 'CancelledError' ||
    name === 'ScopeError'
  )
}

/**
 * 模块内统一的异常处理：全局失败原样抛出，其余只记录日志后继续。
 * @param {object} ctx
 * @param {string} moduleId
 * @param {unknown} error
 */
export function handleModuleError(ctx, moduleId, error) {
  if (isGlobalEngineError(error)) throw error
  log(ctx, 'warn', `${moduleId} 探测异常（已跳过该项）: ${asString(error?.message ?? error)}`)
}

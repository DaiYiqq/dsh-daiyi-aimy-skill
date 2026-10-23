/**
 * 授权范围（scope）护栏 —— 本插件相对上游最大的安全升级。
 *
 * 上游 aimy-sikll 是"用户输入目标就直接打"的 CLI；作为常驻在 Agent 里的插件，
 * 那意味着模型可以在任意对话里对任意主机发起请求。本模块把这件事变成显式授权：
 *
 *   deny-by-default：没有任何范围登记时，所有网络工具直接拒绝；
 *   每条范围必须带 authorization（谁授权的、哪份授权函/靶场编号），审计留痕；
 *   范围支持 host / host:port / scheme / 通配子域 / 路径前缀 / 过期时间；
 *   永远拒绝 0.0.0.0/8、169.254/16、组播等异常地址；
 *   回环与内网地址额外需要 allowPrivateNetworks=true（默认关闭）。
 *
 * @module dsh-daiyi-aimy-skill/lib/scope
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { randomUUID } from 'node:crypto'

/** 范围条目最多保留条数。 */
const MAX_ENTRIES = 200
/** 审计记录最多保留条数。 */
const MAX_AUDIT = 200
/** authorization 字段最短长度，阻止"随手一填"。 */
const MIN_AUTHORIZATION_LENGTH = 8

/**
 * @typedef {object} ScopeEntry
 * @property {string} id
 * @property {string} target       登记的原始写法
 * @property {string} authorization 授权依据（授权函编号 / 靶场名 / 本人资产）
 * @property {string | null} host
 * @property {number | null} port
 * @property {'http' | 'https' | null} scheme
 * @property {string | null} pathPrefix
 * @property {boolean} wildcard    host 是否以 *. 开头
 * @property {string} createdAt    ISO 时间
 * @property {string | null} expiresAt
 */

/**
 * 范围匹配结果。
 * @typedef {{ ok: false, reason: string, code: 'NO_SCOPE' | 'NO_MATCH' | 'EXPIRED' | 'PRIVATE_BLOCKED' | 'FORBIDDEN_ADDRESS' | 'INVALID_TARGET' }} ScopeDenial
 * @typedef {{ ok: true, entry: ScopeEntry }} ScopeAllowance
 */

/**
 * 判断是否 IPv4 字面量。
 * @param {string} host
 * @returns {boolean}
 */
export function isIPv4(host) {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host)
}

/**
 * 判断 IPv6 字面量（宽松；只用于分类，不用于连接）。
 * @param {string} host
 * @returns {boolean}
 */
export function isIPv6(host) {
  return host.includes(':') && /^[0-9a-f:.]+$/i.test(host)
}

/**
 * 地址分类：返回 'loopback' | 'private' | 'link-local' | 'multicast' | 'reserved' | 'public'。
 * @param {string} host
 * @returns {'loopback' | 'private' | 'link-local' | 'multicast' | 'reserved' | 'public'}
 */
export function classifyAddress(host) {
  const normalized = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (normalized === 'localhost' || normalized === '::1') return 'loopback'
  if (isIPv4(normalized)) {
    const [a, b] = normalized.split('.').map(Number)
    if (a === 127) return 'loopback'
    if (a === 0) return 'reserved'
    if (a === 10) return 'private'
    if (a === 172 && b >= 16 && b <= 31) return 'private'
    if (a === 192 && b === 168) return 'private'
    if (a === 169 && b === 254) return 'link-local'
    if (a >= 224 && a <= 239) return 'multicast'
    if (a >= 240) return 'reserved'
    if (a === 100 && b >= 64 && b <= 127) return 'private'
    return 'public'
  }
  if (isIPv6(normalized)) {
    if (normalized.startsWith('fe80')) return 'link-local'
    if (normalized.startsWith('ff')) return 'multicast'
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return 'private'
    return 'public'
  }
  return 'public'
}

/**
 * 解析一条范围登记。接受 `example.com`、`*.example.com`、`https://example.com/app`、
 * `example.com:8443`、`127.0.0.1`、`[::1]:8080`。
 * @param {string} target
 * @returns {Pick<ScopeEntry, 'target' | 'host' | 'port' | 'scheme' | 'pathPrefix' | 'wildcard'>}
 */
export function parseScopeTarget(target) {
  const raw = String(target ?? '').trim()
  if (raw.length === 0) throw new Error('目标不能为空')
  if (/\s/.test(raw)) throw new Error('目标不能包含空白字符')

  let scheme = null
  let rest = raw
  const schemeMatch = /^(https?):\/\/(.*)$/i.exec(raw)
  if (schemeMatch) {
    scheme = /** @type {'http' | 'https'} */ (schemeMatch[1].toLowerCase())
    rest = schemeMatch[2]
  }

  let pathPrefix = null
  const slash = rest.indexOf('/')
  if (slash >= 0) {
    pathPrefix = rest.slice(slash) || '/'
    rest = rest.slice(0, slash)
  }

  // 去掉 userinfo（不接受带凭据的目标登记）
  if (rest.includes('@')) throw new Error('目标不能包含用户凭据 (user:pass@)')

  let host = rest
  let port = null
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']')
    if (close < 0) throw new Error('IPv6 目标缺少 ]')
    host = rest.slice(1, close)
    const tail = rest.slice(close + 1)
    if (tail.startsWith(':')) {
      port = Number(tail.slice(1))
    } else if (tail.length > 0) {
      throw new Error(`无法解析主机后缀 "${tail}"`)
    }
  } else {
    const colon = rest.lastIndexOf(':')
    // 排除裸 IPv6（多冒号）误判
    if (colon > 0 && rest.indexOf(':') === colon) {
      const maybePort = rest.slice(colon + 1)
      if (/^\d+$/.test(maybePort)) {
        host = rest.slice(0, colon)
        port = Number(maybePort)
      }
    }
  }

  host = host.trim().toLowerCase()
  if (host.length === 0) throw new Error('目标缺少主机名')
  if (host === '*') throw new Error('不支持全通配目标 "*"，请登记具体域名')

  let wildcard = false
  if (host.startsWith('*.')) {
    wildcard = true
    host = host.slice(2)
    if (host.length === 0 || host.includes('*')) throw new Error('通配目标格式非法')
  } else if (host.includes('*')) {
    throw new Error('通配符只支持最左一级 "*."')
  }

  if (host.includes('/')) throw new Error('主机名不能包含 /')
  if (!isIPv4(host) && !isIPv6(host) && !/^[a-z0-9.-]+$/.test(host)) {
    throw new Error(`主机名含非法字符: "${host}"`)
  }
  if (port !== null && (!Number.isInteger(port) || port <= 0 || port > 65535)) {
    throw new Error(`端口非法: ${port}`)
  }

  return { target: raw, host, port, scheme, pathPrefix, wildcard }
}

/**
 * 取出 URL 的有效端口（考虑默认端口）。
 * @param {URL} url
 * @returns {number}
 */
export function effectivePort(url) {
  if (url.port) return Number(url.port)
  return url.protocol === 'https:' ? 443 : 80
}

/**
 * 主机名是否匹配条目（不处理端口/协议/路径）。
 * @param {string} host 小写主机名
 * @param {ScopeEntry} entry
 * @returns {boolean}
 */
function hostMatches(host, entry) {
  if (entry.host === null) return false
  if (!entry.wildcard) return host === entry.host
  // 通配只匹配子域，不匹配 apex
  return host.endsWith(`.${entry.host}`) && host !== entry.host
}

/**
 * 把任意输入归一成 URL。裸主机补 http://。
 * @param {string | URL} input
 * @param {string} [fallbackScheme]
 * @returns {URL}
 */
export function toUrl(input, fallbackScheme = 'http') {
  if (input instanceof URL) return input
  const text = String(input ?? '').trim()
  if (text.length === 0) throw new Error('目标不能为空')
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return new URL(text)
  return new URL(`${fallbackScheme}://${text}`)
}

/**
 * 授权范围存储。支持内存态与 JSON 文件持久化（原子写）。
 */
export class ScopeStore {
  /**
   * @param {{ file?: string | null, persist?: boolean, allowPrivateNetworks?: boolean, now?: () => number }} [options]
   */
  constructor(options = {}) {
    this.file = options.file ?? null
    this.persist = options.persist !== false && this.file !== null
    this.allowPrivateNetworks = options.allowPrivateNetworks === true
    this.now = options.now ?? Date.now
    /** @type {ScopeEntry[]} */
    this.entries = []
    /** @type {Array<{ at: string, actor: string, action: string, target?: string, detail?: string }>} */
    this.auditLog = []
    this.loaded = false
    this.loadError = null
  }

  /**
   * 解析默认存储路径。
   * @param {string | null} configured
   * @returns {string}
   */
  static defaultFile(configured) {
    if (typeof configured === 'string' && configured.length > 0) return configured
    const home = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
    return path.join(home, 'daiyi-aimy-skill', 'scope.json')
  }

  /**
   * 创建并（可选）加载磁盘状态。
   * @param {{ file?: string | null, persist?: boolean, allowPrivateNetworks?: boolean }} [options]
   * @returns {Promise<ScopeStore>}
   */
  static async create(options = {}) {
    const store = new ScopeStore(options)
    await store.load()
    return store
  }

  /** 从磁盘载入；文件缺失视为空状态，损坏则记录 loadError 并从空状态启动。 */
  async load() {
    if (this.loaded) return
    this.loaded = true
    if (!this.persist || this.file === null) return
    try {
      const text = await fs.readFile(this.file, 'utf8')
      const parsed = JSON.parse(text)
      if (Array.isArray(parsed?.entries)) this.entries = parsed.entries.filter(isScopeEntry)
      if (Array.isArray(parsed?.auditLog)) this.auditLog = parsed.auditLog.slice(-MAX_AUDIT)
    } catch (error) {
      if (error?.code !== 'ENOENT') this.loadError = String(error?.message ?? error)
    }
  }

  /** 原子写回磁盘；失败不抛错，返回错误信息。 */
  async save() {
    if (!this.persist || this.file === null) return null
    try {
      await fs.mkdir(path.dirname(this.file), { recursive: true })
      const payload = JSON.stringify({ version: 1, entries: this.entries, auditLog: this.auditLog }, null, 2)
      const tmp = `${this.file}.tmp-${process.pid}-${randomUUID().slice(0, 8)}`
      await fs.writeFile(tmp, `${payload}\n`, 'utf8')
      await fs.rename(tmp, this.file)
      return null
    } catch (error) {
      return String(error?.message ?? error)
    }
  }

  /**
   * 记录一条审计事件（不落盘，由调用方决定 save）。
   * @param {string} action
   * @param {{ target?: string, detail?: string }} [extra]
   */
  audit(action, extra = {}) {
    this.auditLog.push({
      at: new Date(this.now()).toISOString(),
      actor: 'aimy-plugin',
      action,
      ...(extra.target === undefined ? {} : { target: extra.target }),
      ...(extra.detail === undefined ? {} : { detail: extra.detail }),
    })
    if (this.auditLog.length > MAX_AUDIT) this.auditLog = this.auditLog.slice(-MAX_AUDIT)
  }

  /**
   * 登记一条授权范围。
   * @param {{ target: string, authorization: string, expiresInHours?: number | null }} input
   * @returns {Promise<{ ok: true, entry: ScopeEntry, warning?: string } | { ok: false, error: string }>}
   */
  async add(input) {
    const authorization = String(input?.authorization ?? '').trim()
    if (authorization.length < MIN_AUTHORIZATION_LENGTH) {
      return {
        ok: false,
        error: `authorization 至少要 ${MIN_AUTHORIZATION_LENGTH} 个字符，请写清授权依据（例如「客户授权函 #A-1024」或「CTF 靶场 dvwa.local」）`,
      }
    }
    let parsed
    try {
      parsed = parseScopeTarget(input?.target)
    } catch (error) {
      return { ok: false, error: String(error?.message ?? error) }
    }
    const addressClass = classifyAddress(parsed.host)
    if (addressClass === 'link-local' || addressClass === 'multicast' || addressClass === 'reserved') {
      return { ok: false, error: `拒绝登记异常地址类别: ${addressClass}` }
    }
    if ((addressClass === 'loopback' || addressClass === 'private') && !this.allowPrivateNetworks) {
      return {
        ok: false,
        error: `目标是${addressClass === 'loopback' ? '回环' : '内网'}地址，需要在插件配置中开启 allowPrivateNetworks: true 才能登记`,
      }
    }

    const now = this.now()
    let expiresAt = null
    if (input?.expiresInHours !== undefined && input?.expiresInHours !== null) {
      const hours = Number(input.expiresInHours)
      if (!Number.isFinite(hours) || hours <= 0) return { ok: false, error: 'expiresInHours 必须是正数' }
      expiresAt = new Date(now + hours * 3600 * 1000).toISOString()
    }

    const existing = this.entries.find(
      (entry) =>
        entry.host === parsed.host &&
        entry.port === parsed.port &&
        entry.scheme === parsed.scheme &&
        entry.pathPrefix === parsed.pathPrefix &&
        entry.wildcard === parsed.wildcard,
    )
    if (existing !== undefined) {
      return { ok: true, entry: existing, warning: '该范围已存在，未重复登记' }
    }

    /** @type {ScopeEntry} */
    const entry = {
      id: `scope-${randomUUID().slice(0, 8)}`,
      ...parsed,
      authorization,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    }
    this.entries.push(entry)
    if (this.entries.length > MAX_ENTRIES) this.entries = this.entries.slice(-MAX_ENTRIES)
    this.audit('scope.add', { target: entry.target, detail: authorization })
    return { ok: true, entry }
  }

  /**
   * 按 id / target / host 删除。
   * @param {string} selector
   * @returns {{ ok: true, removed: ScopeEntry[] } | { ok: false, error: string }}
   */
  remove(selector) {
    const key = String(selector ?? '').trim().toLowerCase()
    if (key.length === 0) return { ok: false, error: 'remove 需要 target 或 entry id' }
    const before = this.entries.length
    const removed = this.entries.filter(
      (entry) => entry.id.toLowerCase() === key || entry.target.toLowerCase() === key || entry.host === key,
    )
    this.entries = this.entries.filter((entry) => !removed.includes(entry))
    if (removed.length === 0) return { ok: false, error: `未找到匹配 "${selector}" 的范围登记` }
    if (this.entries.length === 0 && before > 0) this.audit('scope.clear', { detail: 'all entries removed' })
    this.audit('scope.remove', { target: selector, detail: `${removed.length} entries` })
    return { ok: true, removed }
  }

  /** 清空全部范围。 */
  clear() {
    const count = this.entries.length
    this.entries = []
    this.audit('scope.clear', { detail: `${count} entries` })
    return count
  }

  /**
   * 列出当前范围，附带是否过期。
   * @returns {Array<ScopeEntry & { expired: boolean }>}
   */
  list() {
    const now = this.now()
    return this.entries.map((entry) => ({
      ...entry,
      expired: entry.expiresAt !== null && Date.parse(entry.expiresAt) <= now,
    }))
  }

  /**
   * 判定一个 URL / 主机是否在授权范围内。
   * @param {string | URL} input 完整 URL，或主机名（配合 options.port）
   * @param {{ port?: number, scheme?: 'http' | 'https' }} [options]
   * @returns {ScopeAllowance | ScopeDenial}
   */
  check(input, options = {}) {
    if (this.entries.length === 0) {
      return {
        ok: false,
        code: 'NO_SCOPE',
        reason: '当前没有任何授权范围。请先调用 aimy_scope(action="add", target=..., authorization=...) 登记授权目标。',
      }
    }
    let url
    try {
      url = toUrl(input, options.scheme ?? 'http')
      if (options.port !== undefined && options.port !== null) url.port = String(options.port)
    } catch (error) {
      return { ok: false, code: 'INVALID_TARGET', reason: `目标无法解析: ${String(error?.message ?? error)}` }
    }

    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
    const addressClass = classifyAddress(host)
    if (addressClass === 'link-local' || addressClass === 'multicast' || addressClass === 'reserved') {
      return { ok: false, code: 'FORBIDDEN_ADDRESS', reason: `拒绝访问异常地址类别 ${addressClass}: ${host}` }
    }
    if ((addressClass === 'loopback' || addressClass === 'private') && !this.allowPrivateNetworks) {
      return {
        ok: false,
        code: 'PRIVATE_BLOCKED',
        reason: `目标是${addressClass === 'loopback' ? '回环' : '内网'}地址 ${host}，配置未开启 allowPrivateNetworks`,
      }
    }

    const port = effectivePort(url)
    const now = this.now()
    const candidates = this.entries.filter((entry) => !(entry.expiresAt !== null && Date.parse(entry.expiresAt) <= now))
    const matched = candidates.find((entry) => {
      if (!hostMatches(host, entry)) return false
      if (entry.port !== null && entry.port !== port) return false
      if (entry.scheme !== null && entry.scheme !== url.protocol.replace(':', '')) return false
      if (entry.pathPrefix !== null && !url.pathname.startsWith(entry.pathPrefix)) return false
      return true
    })
    if (matched !== undefined) return { ok: true, entry: matched }

    const expired = this.entries.find((entry) => entry.expiresAt !== null && Date.parse(entry.expiresAt) <= now && hostMatches(host, entry))
    if (expired !== undefined) {
      return { ok: false, code: 'EXPIRED', reason: `目标 ${host} 的授权范围已于 ${expired.expiresAt} 过期，请重新登记` }
    }
    return {
      ok: false,
      code: 'NO_MATCH',
      reason: `目标 ${url.origin}${url.pathname} 不在授权范围内。已登记范围: ${this.entries.map((entry) => entry.target).join(', ')}`,
    }
  }
}

/**
 * 磁盘反序列化时的结构校验。
 * @param {unknown} value
 * @returns {boolean}
 */
function isScopeEntry(value) {
  if (value === null || typeof value !== 'object') return false
  const entry = /** @type {Record<string, unknown>} */ (value)
  return (
    typeof entry.id === 'string' &&
    typeof entry.target === 'string' &&
    typeof entry.authorization === 'string' &&
    typeof entry.host === 'string' &&
    typeof entry.createdAt === 'string'
  )
}

/**
 * 生成给人看的范围摘要。
 * @param {ReturnType<ScopeStore['list']>} entries
 * @returns {string}
 */
export function describeScope(entries) {
  if (entries.length === 0) return '（空）尚未登记任何授权范围'
  return entries
    .map((entry) => {
      const parts = [entry.target]
      if (entry.wildcard) parts.push('（含子域）')
      if (entry.expired) parts.push('（已过期）')
      return `${parts.join('')} · ${entry.authorization}`
    })
    .join('\n')
}

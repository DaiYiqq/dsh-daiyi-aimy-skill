/**
 * 受护栏约束的 HTTP 探针。
 *
 * 这是插件**唯一**允许发起 HTTP 请求的地方：所有网络访问先过 scope 校验，
 * 再受请求预算、超时、响应体上限、重定向策略约束。引擎模块只能拿到这里注入的
 * `ctx.probe` 函数，拿不到 `fetch`，因此不存在"绕过护栏"的代码路径。
 *
 * @module dsh-daiyi-aimy-skill/lib/http
 */

import { performance } from 'node:perf_hooks'

/** 目标不在授权范围内。 */
export class ScopeError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, target?: string }} [detail]
   */
  constructor(message, detail = {}) {
    super(message)
    this.name = 'ScopeError'
    this.code = detail.code ?? 'SCOPE_DENIED'
    this.target = detail.target ?? null
  }
}

/** 本次工具调用的请求预算耗尽。 */
export class BudgetError extends Error {
  /**
   * @param {number} limit
   */
  constructor(limit) {
    super(`本次调用已达到请求预算上限 ${limit}，请缩小范围后重试（或提高配置 maxRequests）`)
    this.name = 'BudgetError'
    this.code = 'BUDGET_EXCEEDED'
  }
}

/** 调用方取消。 */
export class CancelledError extends Error {
  constructor() {
    super('调用已取消')
    this.name = 'CancelledError'
    this.code = 'CANCELLED'
  }
}

/**
 * @typedef {object} ProbeResponse
 * @property {string} method
 * @property {string} url
 * @property {number} status
 * @property {Record<string, string>} headers
 * @property {string} body
 * @property {number} elapsedMs
 * @property {boolean} truncated
 * @property {string} [error]
 * @property {number} [bytes]
 */

/**
 * 带并发与预算约束的 HTTP 客户端。
 */
export class ProbeClient {
  /**
   * @param {object} options
   * @param {import('./scope.js').ScopeStore} options.scope
   * @param {object} options.config 归一化后的配置
   * @param {AbortSignal} [options.signal]
   * @param {(level: string, msg: string) => void} [options.log]
   */
  constructor(options) {
    this.scope = options.scope
    this.config = options.config
    this.signal = options.signal
    this.log = options.log ?? (() => {})
    this.requestCount = 0
    this.byteCount = 0
    /** @type {Set<string>} */
    this.visited = new Set()
  }

  /**
   * 发一个受护栏保护的请求。
   * @param {string | URL} url
   * @param {{ method?: 'GET' | 'POST' | 'HEAD' | 'PUT' | 'OPTIONS', headers?: Record<string, string>, body?: string, followRedirects?: boolean, timeoutMs?: number }} [init]
   * @returns {Promise<ProbeResponse>}
   */
  async request(url, init = {}) {
    this.throwIfAborted()
    const method = init.method ?? 'GET'
    const followRedirects = init.followRedirects ?? this.config.followRedirects
    let current
    try {
      current = url instanceof URL ? new URL(url.toString()) : new URL(String(url))
    } catch (error) {
      throw new ScopeError(`目标 URL 无法解析: ${String(error?.message ?? error)}`, { code: 'INVALID_TARGET' })
    }

    let redirects = 0
    for (;;) {
      this.throwIfAborted()
      this.assertInScope(current)
      if (this.requestCount >= this.config.maxRequests) throw new BudgetError(this.config.maxRequests)
      this.requestCount += 1

      const response = await this.send(current, method, init)
      const status = response.status
      const isRedirect = status === 301 || status === 302 || status === 303 || status === 307 || status === 308
      if (!followRedirects || !isRedirect) return response
      const location = response.headers.location
      if (location === undefined || location.length === 0) return response
      if (redirects >= this.config.maxRedirects) {
        return { ...response, error: '重定向次数超过 maxRedirects' }
      }
      redirects += 1
      let next
      try {
        next = new URL(location, current)
      } catch {
        return response
      }
      // 跨主机跳转必须重新过 scope，防止被重定向带出授权范围。
      const verdict = this.scope.check(next)
      if (!verdict.ok) {
        return { ...response, error: `重定向目标被拒绝: ${verdict.reason}` }
      }
      current = next
      if (status === 303) {
        // 303 一律降级为 GET
        init = { ...init, method: 'GET', body: undefined }
      }
    }
  }

  /**
   * @param {URL} url
   * @param {string} method
   * @param {{ headers?: Record<string, string>, body?: string, timeoutMs?: number }} init
   * @returns {Promise<ProbeResponse>}
   */
  async send(url, method, init) {
    const signal = this.composeSignal(init.timeoutMs ?? this.config.timeoutMs)
    const headers = {
      'user-agent': this.config.userAgent,
      accept: '*/*',
      'accept-encoding': 'identity',
      ...lowercaseKeys(init.headers ?? {}),
    }
    if (method === 'GET' || method === 'HEAD') delete headers['content-length']
    const started = performance.now()
    try {
      const response = await fetch(url, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : (init.body ?? ''),
        redirect: 'manual',
        signal,
      })
      const { text, truncated, bytes } = await readCapped(response, this.config.maxBodyBytes)
      this.byteCount += bytes
      return {
        method,
        url: url.toString(),
        status: response.status,
        headers: Object.fromEntries([...response.headers.entries()].map(([key, value]) => [key.toLowerCase(), value])),
        body: text,
        elapsedMs: Math.round(performance.now() - started),
        truncated,
        bytes,
      }
    } catch (error) {
      if (this.signal?.aborted === true) throw new CancelledError()
      const name = /** @type {{ name?: string }} */ (error)?.name
      if (name === 'AbortError' || name === 'TimeoutError') {
        return {
          method,
          url: url.toString(),
          status: 0,
          headers: {},
          body: '',
          elapsedMs: Math.round(performance.now() - started),
          truncated: false,
          error: `请求超时（>${init.timeoutMs ?? this.config.timeoutMs}ms）`,
        }
      }
      return {
        method,
        url: url.toString(),
        status: 0,
        headers: {},
        body: '',
        elapsedMs: Math.round(performance.now() - started),
        truncated: false,
        error: String(/** @type {{ message?: string }} */ (error)?.message ?? error),
      }
    } finally {
      signal.dispose?.()
    }
  }

  /**
   * 组合外部取消信号与单请求超时。
   * @param {number} timeoutMs
   * @returns {AbortSignal & { dispose?: () => void }}
   */
  composeSignal(timeoutMs) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), Math.max(1, timeoutMs))
    if (typeof timer.unref === 'function') timer.unref()
    const outer = this.signal
    let onOuterAbort = null
    if (outer !== undefined) {
      if (outer.aborted) controller.abort()
      else {
        onOuterAbort = () => controller.abort()
        outer.addEventListener('abort', onOuterAbort, { once: true })
      }
    }
    const signal = /** @type {AbortSignal & { dispose?: () => void }} */ (controller.signal)
    signal.dispose = () => {
      clearTimeout(timer)
      if (outer !== undefined && onOuterAbort !== null) outer.removeEventListener('abort', onOuterAbort)
    }
    return signal
  }

  /**
   * @param {URL} url
   */
  assertInScope(url) {
    const verdict = this.scope.check(url)
    if (!verdict.ok) throw new ScopeError(verdict.reason, { code: verdict.code, target: url.toString() })
  }

  /** 外部取消时抛 CancelledError。 */
  throwIfAborted() {
    if (this.signal?.aborted === true) throw new CancelledError()
  }
}

/**
 * 读取响应体但不超过上限；超限即截断并取消流。
 * @param {Response} response
 * @param {number} maxBytes
 * @returns {Promise<{ text: string, truncated: boolean, bytes: number }>}
 */
async function readCapped(response, maxBytes) {
  if (response.body === null) return { text: '', truncated: false, bytes: 0 }
  const reader = response.body.getReader()
  /** @type {Uint8Array[]} */
  const chunks = []
  let bytes = 0
  let truncated = false
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (value === undefined) continue
      const remaining = maxBytes - bytes
      if (value.byteLength >= remaining) {
        chunks.push(value.subarray(0, remaining))
        bytes += remaining
        truncated = true
        break
      }
      chunks.push(value)
      bytes += value.byteLength
    }
  } catch {
    // 读取中断（超时/取消）时保留已读内容
  } finally {
    if (truncated) {
      try {
        await reader.cancel()
      } catch {
        /* 忽略取消失败 */
      }
    }
  }
  const buffer = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), bytes)
  return { text: buffer.toString('utf8'), truncated, bytes }
}

/**
 * @param {Record<string, string>} headers
 * @returns {Record<string, string>}
 */
function lowercaseKeys(headers) {
  /** @type {Record<string, string>} */
  const out = {}
  for (const [key, value] of Object.entries(headers)) out[key.toLowerCase()] = value
  return out
}

/**
 * 受控并发执行。任何一项抛错都会中止后续调度（用于预算/取消这类全局失败）。
 * @template T, R
 * @param {T[]} items
 * @param {number} limit
 * @param {(item: T, index: number) => Promise<R>} worker
 * @param {AbortSignal} [signal]
 * @returns {Promise<R[]>}
 */
export async function mapLimit(items, limit, worker, signal) {
  /** @type {R[]} */
  const results = new Array(items.length)
  let cursor = 0
  let failure = null
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length || 1)) }, async () => {
    for (;;) {
      if (failure !== null) return
      if (signal?.aborted === true) return
      const index = cursor
      cursor += 1
      if (index >= items.length) return
      try {
        results[index] = await worker(items[index], index)
      } catch (error) {
        failure = error
        return
      }
    }
  })
  await Promise.all(workers)
  if (failure !== null) throw failure
  return results.slice(0, cursor)
}

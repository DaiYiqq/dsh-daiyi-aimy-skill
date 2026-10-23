/**
 * 工具层公共脚手架：目标解析、护栏探针、运行记录、结果渲染。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/shared
 */

import { ProbeClient, ScopeError } from '../http.js'
import { toUrl } from '../scope.js'
import { engineLimits } from '../config.js'

/**
 * 构造目标描述（引擎模块共用）。
 * @param {URL} url
 * @returns {{ url: URL, origin: string, host: string }}
 */
export function describeTarget(url) {
  return { url, origin: url.origin, host: url.hostname.replace(/^\[|\]$/g, '') }
}

/**
 * 解析并校验目标 URL；不在授权范围时抛 ScopeError。
 * @param {import('../scope.js').ScopeStore} scope
 * @param {string} input
 * @param {{ defaultScheme?: string }} [options]
 * @returns {URL}
 */
export function requireScope(scope, input, options = {}) {
  let url
  try {
    url = toUrl(input, options.defaultScheme ?? 'http')
  } catch (error) {
    throw new ScopeError(`目标无法解析为 URL: ${String(error?.message ?? error)}`, { code: 'INVALID_TARGET' })
  }
  const verdict = scope.check(url)
  if (!verdict.ok) throw new ScopeError(verdict.reason, { code: verdict.code, target: url.toString() })
  return url
}

/**
 * 校验主机（端口扫描这类没有 URL 的场景）；port 参与匹配。
 * @param {import('../scope.js').ScopeStore} scope
 * @param {string} host
 * @param {number} port
 * @param {'http' | 'https'} [scheme]
 */
export function requireScopeHost(scope, host, port, scheme = 'http') {
  const verdict = scope.check(host, { port, scheme })
  if (!verdict.ok) throw new ScopeError(verdict.reason, { code: verdict.code, target: `${host}:${port}` })
  return verdict.entry
}

/**
 * 创建受护栏探针。
 * @param {{ scope: import('../scope.js').ScopeStore, config: object, signal: AbortSignal, log: Function }} options
 * @returns {ProbeClient}
 */
export function createProbeClient(options) {
  return new ProbeClient({
    scope: options.scope,
    config: options.config,
    signal: options.signal,
    log: options.log,
  })
}

/**
 * 组装引擎模块需要的 ProbeContext。
 * @param {object} options
 * @param {URL} options.url
 * @param {ProbeClient} options.client
 * @param {Array<object>} [options.params]
 * @param {object} options.config
 * @param {AbortSignal} options.signal
 * @param {(level: string, msg: string) => void} options.log
 * @returns {object}
 */
export function buildEngineContext(options) {
  return {
    target: describeTarget(options.url),
    probe: (url, init) => options.client.request(url, init),
    params: options.params ?? [],
    mode: options.config.mode,
    authorized: true,
    signal: options.signal,
    log: options.log,
    limits: engineLimits(options.config),
  }
}

/**
 * 开始一次运行记录；返回 finish 供工具在结束时结算。
 * @param {{ store: import('../store.js').FindingsStore, log: Function }} deps
 * @param {string} tool
 * @param {string} target
 * @returns {{ finish: (info: { requests: number, findings: number, note?: string }) => object }}
 */
export function startRun(deps, tool, target) {
  const startedAt = Date.now()
  return {
    finish(info) {
      const record = deps.store.recordRun({
        tool,
        target,
        startedAt,
        requests: info.requests,
        findings: info.findings,
        ...(info.note === undefined ? {} : { note: info.note }),
      })
      deps.log('debug', `${tool} 完成：${info.requests} 次请求，${info.findings} 条新发现`)
      return record
    },
  }
}

/**
 * 把工具输出压成一行供卡片展示。
 * @param {string} summary
 * @param {Record<string, unknown>} [extra]
 * @returns {Array<{ type: 'text', text: string }>}
 */
export function renderText(summary, extra = {}) {
  const details = Object.entries(extra)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`)
  return [{ type: 'text', text: details.length === 0 ? summary : `${summary}\n${details.join('\n')}` }]
}

/**
 * 工具层统一错误消息：把 ScopeError 的原因原样抛出，让人知道下一步怎么做。
 * @param {unknown} error
 * @returns {Error}
 */
export function asToolError(error) {
  if (error instanceof Error) return error
  return new Error(String(error))
}

/**
 * 常用输出 schema 片段（避免每个工具重复写长 schema）。
 */
export const SCHEMA = {
  /** 任意 JSON 值（数组/对象结构由运行时校验跳过，适合 findings、列表等）。 */
  json: { type: 'json' },
  string: { type: 'string' },
  nullableString: { type: 'string' },
  integer: { type: 'integer' },
  boolean: { type: 'boolean' },
}

/**
 * 会话级 Finding 存储与运行记录。
 *
 * 设计要点：
 * - 只放内存 + 有上限，不写数据库；插件重启即清空（scope 才需要持久化）。
 * - Finding 去重靠稳定 key：同模块、同检查点、同 URL、同参数、同 payload 只保留一条。
 * - 每次工具调用记一条 run，报告里可以还原"测了什么、花了多少请求、得出什么"。
 *
 * @module dsh-daiyi-aimy-skill/lib/store
 */

import { randomUUID } from 'node:crypto'

/** 严重度排序权重（越大越严重）。 */
export const SEVERITY_WEIGHT = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** 合法严重度集合。 */
export const SEVERITIES = /** @type {const} */ (['info', 'low', 'medium', 'high', 'critical'])

/**
 * @typedef {object} Finding
 * @property {string} module
 * @property {string} checkId
 * @property {string} title
 * @property {'info' | 'low' | 'medium' | 'high' | 'critical'} severity
 * @property {'low' | 'medium' | 'high'} confidence
 * @property {string} url
 * @property {string} [param]
 * @property {string} [payload]
 * @property {string} evidence
 * @property {string} [cwe]
 * @property {string} [remediation]
 * @property {boolean} [confirmed]
 */

/**
 * 归一到合法 Finding；非法输入返回 null（由调用方决定跳过还是报错）。
 * @param {unknown} raw
 * @returns {Finding | null}
 */
export function normalizeFinding(raw) {
  if (raw === null || typeof raw !== 'object') return null
  const value = /** @type {Record<string, unknown>} */ (raw)
  if (typeof value.title !== 'string' || value.title.trim().length === 0) return null
  if (typeof value.url !== 'string' || value.url.length === 0) return null
  const severity = SEVERITIES.includes(/** @type {any} */ (value.severity)) ? value.severity : 'medium'
  const confidence = value.confidence === 'low' || value.confidence === 'high' ? value.confidence : 'medium'
  const evidence = typeof value.evidence === 'string' ? value.evidence.slice(0, 800) : ''
  return {
    module: typeof value.module === 'string' ? value.module : 'unknown',
    checkId: typeof value.checkId === 'string' ? value.checkId : 'unknown',
    title: value.title.trim(),
    severity: /** @type {Finding['severity']} */ (severity),
    confidence: /** @type {Finding['confidence']} */ (confidence),
    url: value.url,
    ...(typeof value.param === 'string' && value.param.length > 0 ? { param: value.param } : {}),
    ...(typeof value.payload === 'string' && value.payload.length > 0 ? { payload: value.payload.slice(0, 300) } : {}),
    evidence,
    ...(typeof value.cwe === 'string' && value.cwe.length > 0 ? { cwe: value.cwe } : {}),
    ...(typeof value.remediation === 'string' && value.remediation.length > 0 ? { remediation: value.remediation } : {}),
    ...(value.confirmed === true ? { confirmed: true } : {}),
  }
}

/**
 * 生成稳定去重 key。
 * @param {Finding} finding
 * @returns {string}
 */
export function findingKey(finding) {
  return [finding.module, finding.checkId, finding.url, finding.param ?? '', finding.payload ?? ''].join('|')
}

/**
 * @typedef {object} RunRecord
 * @property {string} id
 * @property {string} tool
 * @property {string} target
 * @property {string} startedAt
 * @property {number} durationMs
 * @property {number} requests
 * @property {number} findings
 * @property {string} [note]
 */

/** 会话级存储。 */
export class FindingsStore {
  /**
   * @param {{ maxFindings?: number, maxRuns?: number, now?: () => number }} [options]
   */
  constructor(options = {}) {
    this.maxFindings = options.maxFindings ?? 800
    this.maxRuns = options.maxRuns ?? 60
    this.now = options.now ?? Date.now
    /** @type {Map<string, Finding & { firstSeenAt: string, lastSeenAt: string, seen: number }>} */
    this.findings = new Map()
    /** @type {RunRecord[]} */
    this.runs = []
    this.totalRequests = 0
    this.dropped = 0
  }

  /**
   * 写入一批 finding，返回真正新增的条数。
   * @param {unknown[]} rawFindings
   * @returns {{ added: number, updated: number, accepted: Finding[] }}
   */
  add(rawFindings) {
    let added = 0
    let updated = 0
    /** @type {Finding[]} */
    const accepted = []
    for (const raw of rawFindings ?? []) {
      const finding = normalizeFinding(raw)
      if (finding === null) continue
      const key = findingKey(finding)
      const at = new Date(this.now()).toISOString()
      const existing = this.findings.get(key)
      if (existing !== undefined) {
        existing.seen += 1
        existing.lastSeenAt = at
        // 证据随重复观测更新（保留更长的一条）
        if (finding.evidence.length > existing.evidence.length) existing.evidence = finding.evidence
        if (finding.confirmed === true) existing.confirmed = true
        if (SEVERITY_WEIGHT[finding.severity] > SEVERITY_WEIGHT[existing.severity]) existing.severity = finding.severity
        updated += 1
        continue
      }
      this.findings.set(key, { ...finding, firstSeenAt: at, lastSeenAt: at, seen: 1 })
      accepted.push(finding)
      added += 1
    }
    this.enforceLimit()
    return { added, updated, accepted }
  }

  /** 超出上限时丢弃最轻、最近的条目。 */
  enforceLimit() {
    while (this.findings.size > this.maxFindings) {
      const sorted = this.sorted()
      const victim = sorted[sorted.length - 1]
      if (victim === undefined) return
      this.findings.delete(findingKey(victim))
      this.dropped += 1
    }
  }

  /**
   * 按严重度 → 置信度 → 首次发现时间排序。
   * @returns {Array<Finding & { firstSeenAt: string, lastSeenAt: string, seen: number }>}
   */
  sorted() {
    return [...this.findings.values()].sort((a, b) => {
      const severity = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]
      if (severity !== 0) return severity
      const confidence = confidenceWeight(b.confidence) - confidenceWeight(a.confidence)
      if (confidence !== 0) return confidence
      return a.firstSeenAt.localeCompare(b.firstSeenAt)
    })
  }

  /**
   * 按过滤条件列出。
   * @param {{ severity?: string[], module?: string[], urlContains?: string }} [filter]
   * @returns {Array<Finding & { firstSeenAt: string, lastSeenAt: string, seen: number }>}
   */
  list(filter = {}) {
    let rows = this.sorted()
    if (Array.isArray(filter.severity) && filter.severity.length > 0) {
      const allowed = new Set(filter.severity)
      rows = rows.filter((row) => allowed.has(row.severity))
    }
    if (Array.isArray(filter.module) && filter.module.length > 0) {
      const allowed = new Set(filter.module)
      rows = rows.filter((row) => allowed.has(row.module))
    }
    if (typeof filter.urlContains === 'string' && filter.urlContains.length > 0) {
      rows = rows.filter((row) => row.url.includes(filter.urlContains))
    }
    return rows
  }

  /** 各严重度计数。 */
  counts() {
    /** @type {Record<string, number>} */
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const finding of this.findings.values()) counts[finding.severity] += 1
    counts.total = this.findings.size
    return counts
  }

  /**
   * 记录一次工具运行。
   * @param {{ tool: string, target: string, startedAt: number, requests: number, findings: number, note?: string }} run
   * @returns {RunRecord}
   */
  recordRun(run) {
    const record = {
      id: `run-${randomUUID().slice(0, 8)}`,
      tool: run.tool,
      target: run.target,
      startedAt: new Date(run.startedAt).toISOString(),
      durationMs: Math.max(0, this.now() - run.startedAt),
      requests: run.requests,
      findings: run.findings,
      ...(run.note === undefined ? {} : { note: run.note }),
    }
    this.totalRequests += run.requests
    this.runs.push(record)
    if (this.runs.length > this.maxRuns) this.runs = this.runs.slice(-this.maxRuns)
    return record
  }

  /** 清空全部数据。 */
  clear() {
    this.findings.clear()
    this.runs = []
    this.totalRequests = 0
    this.dropped = 0
  }

  /**
   * 生成报告快照。
   * @param {{ scopeEntries?: Array<Record<string, unknown>>, plugin?: Record<string, unknown> }} [meta]
   * @returns {object}
   */
  snapshot(meta = {}) {
    const counts = this.counts()
    return {
      generatedAt: new Date(this.now()).toISOString(),
      plugin: meta.plugin ?? {},
      scope: meta.scopeEntries ?? [],
      stats: {
        runs: this.runs.length,
        requests: this.totalRequests,
        findings: counts,
        dropped: this.dropped,
      },
      runs: this.runs,
      findings: this.sorted(),
    }
  }
}

/**
 * @param {'low' | 'medium' | 'high'} confidence
 * @returns {number}
 */
function confidenceWeight(confidence) {
  return confidence === 'high' ? 3 : confidence === 'medium' ? 2 : 1
}

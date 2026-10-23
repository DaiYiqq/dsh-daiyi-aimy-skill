/**
 * 报告渲染：Markdown / JSON / SARIF 2.1.0。
 *
 * 报告只消费 lib/store.js 的 snapshot，不重新探测，因此可以随时重复导出。
 *
 * @module dsh-daiyi-aimy-skill/lib/report
 */

import { SEVERITIES, SEVERITY_WEIGHT } from './store.js'

/** 严重度中文标签。 */
export const SEVERITY_LABEL = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

/** 模块 id → 人类可读名称。 */
export const MODULE_LABEL = {
  sqli: 'SQL 注入',
  xss: '跨站脚本',
  cmdi: '命令注入',
  ssti: '模板注入',
  ssrf: '服务端请求伪造',
  nosqli: 'NoSQL 注入',
  lfi: '本地文件包含/路径遍历',
  cors: '跨域配置',
  jwt: 'JWT 会话',
  graphql: 'GraphQL',
  'proto-pollution': '原型污染',
  'dir-brute': '目录枚举',
  ports: '端口暴露',
  crawler: '爬虫',
  'param-miner': '参数挖掘',
  'tech-fingerprint': '技术指纹',
  headers: '安全响应头',
}

const SEVERITY_ORDER = [...SEVERITIES].reverse()

/**
 * 对疑似凭据做脱敏，避免报告把令牌带出。
 * @param {string} text
 * @returns {string}
 */
export function redact(text) {
  return String(text ?? '')
    .replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, 'eyJ***.***.***(已脱敏)')
    .replace(/(bearer\s+)[A-Za-z0-9._~+/-]{12,}/gi, '$1***')
    // 值里出现 `*` 说明已被前面的规则脱敏过，这里跳过，避免二次覆盖掉「已脱敏」标记
    .replace(/((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*)([^\s&"',;*]{6,})/gi, '$1***')
}

/**
 * 渲染 Markdown 报告。
 * @param {object} report lib/store.js snapshot 形状
 * @param {{ redactSecrets?: boolean }} [options]
 * @returns {string}
 */
export function renderMarkdown(report, options = {}) {
  const hide = options.redactSecrets !== false
  const clean = (text) => (hide ? redact(text) : String(text ?? ''))
  const counts = report?.stats?.findings ?? {}
  const lines = []

  lines.push('# 授权安全检测报告')
  lines.push('')
  lines.push(`- 生成时间：${report?.generatedAt ?? '-'}`)
  if (report?.plugin?.name !== undefined) {
    lines.push(`- 生成工具：${report.plugin.name} v${report.plugin.version ?? '-'}（模式：${report.plugin.mode ?? '-'}）`)
  }
  lines.push(`- 运行次数：${report?.stats?.runs ?? 0}　累计请求：${report?.stats?.requests ?? 0}`)
  lines.push('')

  lines.push('## 授权范围')
  lines.push('')
  const scope = Array.isArray(report?.scope) ? report.scope : []
  if (scope.length === 0) {
    lines.push('> 未登记授权范围。')
  } else {
    lines.push('| 目标 | 授权依据 | 有效期 |')
    lines.push('| --- | --- | --- |')
    for (const entry of scope) {
      lines.push(`| ${escapeCell(String(entry.target ?? ''))} | ${escapeCell(String(entry.authorization ?? ''))} | ${entry.expiresAt ?? '长期'} |`)
    }
  }
  lines.push('')

  lines.push('## 风险概览')
  lines.push('')
  lines.push('| 级别 | 数量 |')
  lines.push('| --- | --- |')
  for (const severity of SEVERITY_ORDER) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${counts[severity] ?? 0} |`)
  }
  lines.push(`| **合计** | **${counts.total ?? 0}** |`)
  lines.push('')

  const findings = Array.isArray(report?.findings) ? report.findings : []
  if (findings.length === 0) {
    lines.push('## 发现')
    lines.push('')
    lines.push('本次会话未记录到确认的发现。注意：无发现不等于无漏洞，只代表已执行的检查没有命中。')
    lines.push('')
  } else {
    lines.push('## 发现明细')
    lines.push('')
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter((finding) => finding.severity === severity)
      if (group.length === 0) continue
      lines.push(`### ${SEVERITY_LABEL[severity]}（${group.length}）`)
      lines.push('')
      for (const finding of group) {
        lines.push(`#### ${clean(finding.title)}`)
        lines.push('')
        lines.push(`- 模块：${MODULE_LABEL[finding.module] ?? finding.module}（\`${finding.checkId}\`）`)
        lines.push(`- 位置：\`${clean(finding.url)}\`${finding.param === undefined ? '' : `　参数：\`${clean(finding.param)}\``}`)
        if (finding.payload !== undefined) lines.push(`- 载荷：\`${clean(finding.payload)}\``)
        lines.push(`- 置信度：${finding.confidence}${finding.confirmed === true ? '（已复现确认）' : ''}`)
        if (finding.cwe !== undefined) lines.push(`- CWE：${finding.cwe}`)
        lines.push(`- 首次发现：${finding.firstSeenAt ?? '-'}　观测次数：${finding.seen ?? 1}`)
        if (finding.remediation !== undefined) lines.push(`- 修复建议：${clean(finding.remediation)}`)
        lines.push('')
        lines.push('```text')
        lines.push(clean(finding.evidence ?? ''))
        lines.push('```')
        lines.push('')
      }
    }
  }

  const runs = Array.isArray(report?.runs) ? report.runs : []
  if (runs.length > 0) {
    lines.push('## 运行记录')
    lines.push('')
    lines.push('| 时间 | 工具 | 目标 | 请求数 | 新增发现 | 耗时 |')
    lines.push('| --- | --- | --- | --- | --- | --- |')
    for (const run of runs) {
      lines.push(
        `| ${run.startedAt ?? '-'} | ${run.tool ?? '-'} | ${escapeCell(String(run.target ?? ''))} | ${run.requests ?? 0} | ${run.findings ?? 0} | ${run.durationMs ?? 0}ms |`,
      )
    }
    lines.push('')
  }

  lines.push('---')
  lines.push('')
  lines.push('> 本报告由 AI 辅助生成，仅用于**已获授权**的安全测试。结论需要人工复核；')
  lines.push('> 未命中不代表不存在漏洞，只表示已执行的检查未发现证据。')
  return lines.join('\n')
}

/**
 * 渲染 JSON 报告。
 * @param {object} report
 * @returns {string}
 */
export function renderJson(report) {
  return JSON.stringify(report, null, 2)
}

/**
 * 渲染 SARIF 2.1.0 报告（可直接喂给 GitHub Code Scanning 一类的消费方）。
 * @param {object} report
 * @returns {string}
 */
export function renderSarif(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : []
  /** @type {Map<string, { id: string, name: string, shortDescription: { text: string }, helpUri?: string, properties?: Record<string, unknown> }>} */
  const rules = new Map()
  const results = []

  for (const finding of findings) {
    const ruleId = `${finding.module}/${finding.checkId}`
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: finding.checkId,
        shortDescription: { text: MODULE_LABEL[finding.module] ?? finding.module },
        ...(finding.cwe === undefined ? {} : { helpUri: `https://cwe.mitre.org/data/definitions/${String(finding.cwe).replace(/\D/g, '')}.html` }),
        properties: { tags: ['security'], ...(finding.cwe === undefined ? {} : { cwe: finding.cwe }) },
      })
    }
    results.push({
      ruleId,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title}${finding.param === undefined ? '' : `（参数 ${finding.param}）`}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.url },
            region: { startLine: 1, startColumn: 1 },
          },
        },
      ],
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        ...(finding.param === undefined ? {} : { param: finding.param }),
        ...(finding.evidence === undefined ? {} : { evidence: finding.evidence }),
      },
    })
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report?.plugin?.name ?? 'dsh-daiyi-aimy-skill',
            version: String(report?.plugin?.version ?? '3.0.0'),
            informationUri: 'https://github.com/DaiYiqq/dsh-daiyi-aimy-skill',
            rules: [...rules.values()],
          },
        },
        results,
        properties: {
          generatedAt: report?.generatedAt ?? null,
          authorizedScope: Array.isArray(report?.scope) ? report.scope.map((entry) => entry.target) : [],
        },
      },
    ],
  }
  return JSON.stringify(sarif, null, 2)
}

/**
 * 按 format 选择渲染器。
 * @param {'md' | 'json' | 'sarif'} format
 * @param {object} report
 * @param {{ redactSecrets?: boolean }} [options]
 * @returns {string}
 */
export function renderReport(format, report, options = {}) {
  if (format === 'json') return renderJson(report)
  if (format === 'sarif') return renderSarif(report)
  return renderMarkdown(report, options)
}

/**
 * 人类可读的一句话摘要（工具 output.render 用）。
 * @param {object} report
 * @returns {string}
 */
export function summarize(report) {
  const counts = report?.stats?.findings ?? {}
  const parts = SEVERITY_ORDER.filter((severity) => (counts[severity] ?? 0) > 0).map(
    (severity) => `${SEVERITY_LABEL[severity]} ${counts[severity]}`,
  )
  if (parts.length === 0) return '暂无发现'
  return parts.join('，')
}

/**
 * @param {string} severity
 * @returns {'error' | 'warning' | 'note'}
 */
function sarifLevel(severity) {
  if (severity === 'critical' || severity === 'high') return 'error'
  if (severity === 'medium') return 'warning'
  return 'note'
}

/**
 * @param {string} value
 * @returns {string}
 */
function escapeCell(value) {
  return value.replace(/\|/g, '\\|').replace(/\n/g, ' ')
}

/**
 * 供排序工具复用。
 * @param {string} severity
 * @returns {number}
 */
export function severityWeight(severity) {
  return SEVERITY_WEIGHT[severity] ?? 0
}

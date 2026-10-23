import test from 'node:test'
import assert from 'node:assert/strict'

import { FindingsStore, SEVERITIES, findingKey, normalizeFinding, SEVERITY_WEIGHT } from '../lib/store.js'
import { renderJson, renderMarkdown, renderReport, renderSarif, redact, summarize } from '../lib/report.js'
import { DEFAULTS, MODE_PRESETS, engineLimits, normalizeConfig } from '../lib/config.js'

const baseFinding = {
  module: 'sqli',
  checkId: 'error-based',
  title: '检测到 SQL 注入',
  severity: 'high',
  confidence: 'high',
  url: 'https://example.com/item?id=1',
  param: 'id',
  payload: "' OR '1'='1",
  evidence: '响应出现 MySQL syntax error',
}

test('normalizeFinding：补齐默认值并过滤非法输入', () => {
  const ok = normalizeFinding(baseFinding)
  assert.equal(ok.severity, 'high')
  assert.equal(ok.confidence, 'high')
  assert.equal(normalizeFinding({ ...baseFinding, severity: 'apocalyptic' }).severity, 'medium')
  assert.equal(normalizeFinding({ ...baseFinding, confidence: 'sure' }).confidence, 'medium')
  assert.equal(normalizeFinding({ ...baseFinding, evidence: 'x'.repeat(2000) }).evidence.length, 800)
  assert.equal(normalizeFinding(null), null)
  assert.equal(normalizeFinding({ ...baseFinding, title: '  ' }), null)
  assert.equal(normalizeFinding({ ...baseFinding, url: '' }), null)
})

test('findingKey 稳定且能区分参数/载荷', () => {
  const a = normalizeFinding(baseFinding)
  const b = normalizeFinding({ ...baseFinding })
  assert.equal(findingKey(a), findingKey(b))
  assert.notEqual(findingKey(a), findingKey(normalizeFinding({ ...baseFinding, param: 'name' })))
  assert.notEqual(findingKey(a), findingKey(normalizeFinding({ ...baseFinding, payload: 'other' })))
})

test('FindingsStore：去重、升级严重度、计数与排序', () => {
  const store = new FindingsStore({ now: () => Date.parse('2026-01-01T00:00:00Z') })
  const first = store.add([baseFinding, { ...baseFinding, severity: 'critical' }])
  assert.equal(first.added, 1, '同 key 只应新增一条')
  assert.equal(first.updated, 1)
  assert.equal(store.counts().critical, 1, '重复观测到更高严重度时升级')
  assert.equal(store.counts().total, 1)

  store.add([
    { ...baseFinding, checkId: 'blind', severity: 'low', url: 'https://example.com/a' },
    { ...baseFinding, checkId: 'info-leak', severity: 'info', url: 'https://example.com/b' },
  ])
  const sorted = store.sorted()
  assert.deepEqual(
    sorted.map((finding) => finding.severity),
    ['critical', 'low', 'info'],
  )
  assert.equal(store.counts().total, 3)
})

test('FindingsStore：过滤、清空、运行记录与快照', () => {
  const store = new FindingsStore({ now: () => Date.parse('2026-01-01T00:00:00Z') })
  store.add([
    baseFinding,
    { ...baseFinding, checkId: 'xss', module: 'xss', severity: 'medium', url: 'https://example.com/x' },
  ])
  assert.equal(store.list({ severity: ['high'] }).length, 1)
  assert.equal(store.list({ module: ['xss'] }).length, 1)
  assert.equal(store.list({ urlContains: '/x' }).length, 1)

  const run = store.recordRun({ tool: 'aimy_web_scan', target: 'https://example.com', startedAt: 0, requests: 12, findings: 2 })
  assert.equal(run.requests, 12)
  assert.equal(store.totalRequests, 12)

  const snapshot = store.snapshot({ plugin: { name: 'x', version: '1' }, scopeEntries: [] })
  assert.equal(snapshot.stats.runs, 1)
  assert.equal(snapshot.stats.requests, 12)
  assert.equal(snapshot.findings.length, 2)
  assert.equal(snapshot.plugin.name, 'x')

  store.clear()
  assert.equal(store.counts().total, 0)
  assert.equal(store.runs.length, 0)
})

test('FindingsStore：超过上限时丢弃最轻条目', () => {
  const store = new FindingsStore({ maxFindings: 2, now: () => 0 })
  store.add([
    { ...baseFinding, checkId: 'a', severity: 'high', url: 'https://e.test/1' },
    { ...baseFinding, checkId: 'b', severity: 'critical', url: 'https://e.test/2' },
    { ...baseFinding, checkId: 'c', severity: 'info', url: 'https://e.test/3' },
  ])
  assert.ok(store.findings.size <= 2)
  assert.equal(store.counts().info, 0, '最轻的 info 应被丢弃')
  assert.ok(store.dropped >= 1)
})

test('SEVERITY_WEIGHT / SEVERITIES 覆盖完整', () => {
  assert.equal(SEVERITIES.length, 5)
  for (const severity of SEVERITIES) assert.equal(typeof SEVERITY_WEIGHT[severity], 'number')
  assert.ok(SEVERITY_WEIGHT.critical > SEVERITY_WEIGHT.high)
  assert.ok(SEVERITY_WEIGHT.high > SEVERITY_WEIGHT.medium)
})

test('redact：JWT / Bearer / password 被脱敏', () => {
  const text = 'Authorization: Bearer abcdefghijklmnop1234 password=hunter2hunter2 token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg'
  const masked = redact(text)
  assert.doesNotMatch(masked, /hunter2hunter2/)
  assert.doesNotMatch(masked, /abcdefghijklmnop1234/)
  assert.match(masked, /已脱敏/)
})

test('renderMarkdown：包含范围、概览、发现与免责声明', () => {
  const store = new FindingsStore({ now: () => Date.parse('2026-01-01T00:00:00Z') })
  store.add([baseFinding])
  const report = store.snapshot({
    plugin: { name: 'dsh-daiyi-aimy-skill', version: '3.0.0', mode: 'rookie' },
    scopeEntries: [{ target: 'example.com', authorization: '客户授权函 #A-1024', expiresAt: null }],
  })
  const markdown = renderMarkdown(report)
  assert.match(markdown, /# 授权安全检测报告/)
  assert.match(markdown, /## 授权范围/)
  assert.match(markdown, /客户授权函 #A-1024/)
  assert.match(markdown, /## 风险概览/)
  assert.match(markdown, /高危（1）/)
  assert.match(markdown, /检测到 SQL 注入/)
  assert.match(markdown, /授权/)
  assert.doesNotMatch(markdown, /undefined/)
  assert.equal(summarize(report), '高危 1')
})

test('renderJson / renderSarif 结构合法', () => {
  const store = new FindingsStore({ now: () => 0 })
  store.add([baseFinding])
  const report = store.snapshot({ plugin: { name: 'p', version: '1' }, scopeEntries: [] })

  const json = JSON.parse(renderJson(report))
  assert.equal(json.findings.length, 1)

  const sarif = JSON.parse(renderSarif(report))
  assert.equal(sarif.version, '2.1.0')
  assert.equal(sarif.runs.length, 1)
  assert.equal(sarif.runs[0].results.length, 1)
  assert.equal(sarif.runs[0].results[0].level, 'error')
  assert.equal(sarif.runs[0].tool.driver.rules.length, 1)
  assert.match(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, /example\.com/)
})

test('renderReport 按 format 分派', () => {
  const store = new FindingsStore({ now: () => 0 })
  const report = store.snapshot({ plugin: { name: 'p', version: '1' }, scopeEntries: [] })
  assert.match(renderReport('md', report), /授权安全检测报告/)
  assert.equal(JSON.parse(renderReport('json', report)).findings.length, 0)
  assert.equal(JSON.parse(renderReport('sarif', report)).version, '2.1.0')
})

test('normalizeConfig：默认值、模式预设与非法配置回退', () => {
  const { config, warnings } = normalizeConfig(undefined)
  assert.equal(config.mode, 'rookie')
  assert.equal(config.timeoutMs, MODE_PRESETS.rookie.timeoutMs)
  assert.equal(config.maxRequests, MODE_PRESETS.rookie.maxRequests)
  assert.deepEqual(warnings, [])
  assert.equal(engineLimits(config).maxBodyBytes, DEFAULTS.maxBodyBytes)

  const veteran = normalizeConfig({ mode: 'veteran' }).config
  assert.equal(veteran.mode, 'veteran')
  assert.equal(veteran.concurrency, MODE_PRESETS.veteran.concurrency)
  assert.equal(veteran.allowTimeBased, true)

  const odd = normalizeConfig({
    mode: 'nightmare',
    timeoutMs: -5,
    concurrency: 'x',
    unknownKey: 1,
    allowPrivateNetworks: 'yes',
    maxRequests: 99999,
  })
  assert.equal(odd.config.mode, 'rookie')
  assert.equal(odd.config.timeoutMs, MODE_PRESETS.rookie.timeoutMs)
  assert.equal(odd.config.concurrency, MODE_PRESETS.rookie.concurrency)
  assert.equal(odd.config.allowPrivateNetworks, false)
  assert.equal(odd.config.maxRequests, 400)
  assert.ok(odd.warnings.some((warning) => warning.includes('mode')))
  assert.ok(odd.warnings.some((warning) => warning.includes('unknownKey')))
  assert.ok(odd.warnings.some((warning) => warning.includes('maxRequests')))
})

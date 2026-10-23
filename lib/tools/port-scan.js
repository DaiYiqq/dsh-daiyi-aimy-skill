/**
 * 工具 aimy_port_scan：TCP connect 端口探测。
 *
 * 只在授权范围内工作，且不发送任何应用层 payload —— 只是完成 TCP 三次握手，
 * 用来确认攻击面里"有哪些服务在听"。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/port-scan
 */

import net from 'node:net'
import { defineTool } from './define.js'
import { renderText, requireScopeHost, startRun } from './shared.js'
import { classifyAddress, parseScopeTarget } from '../scope.js'

/** 预设端口集合（按用途分组，便于选择而不是盲目全扫）。 */
export const PORT_PRESETS = {
  top20: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200],
  common: [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631, 993, 995, 1080, 1433, 1521, 1723,
    2049, 2082, 2083, 2181, 2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 6379, 7001, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 11211, 27017,
  ],
  web: [80, 81, 443, 3000, 4443, 5000, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 10000],
  db: [1433, 1521, 3306, 5432, 6379, 9042, 9200, 11211, 27017],
}

/** 端口 → 常见服务名。 */
const SERVICE_NAMES = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  110: 'pop3',
  111: 'rpcbind',
  135: 'msrpc',
  139: 'netbios',
  143: 'imap',
  443: 'https',
  445: 'smb',
  465: 'smtps',
  587: 'smtp-submission',
  631: 'ipp',
  993: 'imaps',
  995: 'pop3s',
  1080: 'socks',
  1433: 'mssql',
  1521: 'oracle',
  1723: 'pptp',
  2049: 'nfs',
  2082: 'cpanel',
  2083: 'cpanel-ssl',
  2181: 'zookeeper',
  2375: 'docker',
  2376: 'docker-tls',
  3000: 'http-alt',
  3306: 'mysql',
  3389: 'rdp',
  4444: 'unknown',
  5000: 'http-alt',
  5432: 'postgresql',
  5601: 'kibana',
  5672: 'rabbitmq',
  5900: 'vnc',
  6379: 'redis',
  7001: 'weblogic',
  8000: 'http-alt',
  8008: 'http-alt',
  8080: 'http-proxy',
  8081: 'http-alt',
  8443: 'https-alt',
  8888: 'http-alt',
  9000: 'http-alt',
  9090: 'http-alt',
  9200: 'elasticsearch',
  10000: 'webmin',
  11211: 'memcached',
  27017: 'mongodb',
}

/**
 * 单端口连通性探测（只做 connect，不发数据）。
 * @param {string} host
 * @param {number} port
 * @param {number} timeoutMs
 * @returns {Promise<{ port: number, state: 'open' | 'closed' | 'filtered', elapsedMs: number }>}
 */
export function probePort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false
    const started = Date.now()
    const done = (state) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve({ port, state, elapsedMs: Date.now() - started })
    }
    socket.setTimeout(Math.max(1, timeoutMs))
    socket.once('connect', () => done('open'))
    socket.once('timeout', () => done('filtered'))
    socket.once('error', (error) => done(error?.code === 'ECONNREFUSED' ? 'closed' : 'filtered'))
    try {
      socket.connect({ host, port })
    } catch {
      done('filtered')
    }
  })
}

/**
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createPortScanTool(deps) {
  return defineTool({
    name: 'aimy_port_scan',
    description:
      '对**已授权**主机的常见 TCP 端口做连通性探测（仅完成 TCP 握手，不发送应用层数据）。' +
      '返回开放端口与服务推断，并把数据库/管理端口暴露写成 finding。目标必须先用 aimy_scope 登记。',
    parameters: {
      target: { type: 'string', required: true, description: '主机名或 IP，例如 example.com 或 127.0.0.1' },
      preset: {
        type: 'string',
        enum: ['top20', 'common', 'web', 'db'],
        description: '端口预设：top20（默认，最常用 20 个）、common（约 50 个）、web、db',
      },
      ports: {
        type: 'array',
        description: '自定义端口列表（1-65535），给了就覆盖 preset；请不要一次传几千个端口',
        items: { type: 'integer' },
      },
      timeoutMs: { type: 'integer', description: '单端口超时（毫秒），默认 2000' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          target: { type: 'string', required: true },
          ports: { type: 'json', required: true },
          open: { type: 'json', required: true },
          findings: { type: 'json', required: true },
          requests: { type: 'integer', required: true },
          notes: { type: 'json' },
        },
      },
      render: (_args, value) => {
        const open = Array.isArray(value.open) ? value.open : []
        const list = open.map((entry) => `${entry.port}/${entry.service ?? '?'}`).join(', ')
        return renderText(`端口探测完成：${open.length} 个开放端口`, { 开放: list || '无' })
      },
    },
    presentCall: (args) => ({ card: 'generic', title: '端口探测', kind: 'other', rawInput: args.target }),
    async execute(args, exec) {
      const rawTarget = String(args.target ?? '').trim()
      // 目标可能是 "https://example.com" —— 取出主机部分再校验
      const parsed = parseScopeTarget(rawTarget)
      const host = parsed.host
      const ports = resolvePorts(args)
      if (ports.length === 0) throw new Error('端口列表为空：请提供 preset 或 ports')
      if (ports.length > 1024) throw new Error('单次最多探测 1024 个端口，请拆分为多次调用')

      // 逐端口过 scope（不同端口可能是不同范围条目）
      for (const port of ports) requireScopeHost(deps.scope, host, port, parsed.scheme ?? 'http')

      const timeoutMs = Math.max(200, Math.min(10000, args.timeoutMs ?? 2000))
      const concurrency = Math.max(1, Math.min(16, deps.config.concurrency))
      const addressClass = classifyAddress(host)
      const run = startRun(deps, 'aimy_port_scan', host)
      deps.log('info', `aimy_port_scan ${host}：${ports.length} 个端口，并发 ${concurrency}`)

      /** @type {Array<{port:number,state:string,elapsedMs:number}>} */
      const results = []
      let cursor = 0
      const workers = Array.from({ length: Math.min(concurrency, ports.length) }, async () => {
        for (;;) {
          if (exec.signal?.aborted === true) return
          const index = cursor
          cursor += 1
          if (index >= ports.length) return
          results.push(await probePort(host, ports[index], timeoutMs))
        }
      })
      await Promise.all(workers)

      const open = results
        .filter((entry) => entry.state === 'open')
        .sort((a, b) => a.port - b.port)
        .map((entry) => ({ port: entry.port, service: SERVICE_NAMES[entry.port] ?? 'unknown', elapsedMs: entry.elapsedMs }))

      /** @type {unknown[]} */
      const findings = []
      const risky = new Set([1433, 1521, 2375, 3306, 5432, 5601, 6379, 7001, 9200, 11211, 27017, 5900, 3389, 4444])
      for (const entry of open) {
        if (!risky.has(entry.port)) continue
        findings.push({
          module: 'ports',
          checkId: `exposed-${entry.port}`,
          title: `高危端口对公网开放：${entry.port}/${entry.service}`,
          severity: entry.port === 6379 || entry.port === 2375 || entry.port === 11211 ? 'critical' : 'high',
          confidence: 'high',
          url: `${parsed.scheme ?? 'tcp'}://${host}:${entry.port}`,
          evidence: `TCP 握手成功（${entry.elapsedMs}ms）。该端口通常承载数据库/管理/缓存服务，直接暴露时常见未授权访问风险。`,
          cwe: 'CWE-284',
          remediation: '在边界防火墙限制来源 IP，或只监听内网/回环地址，并启用认证。',
        })
      }
      if (addressClass === 'public' && open.some((entry) => entry.port === 22 || entry.port === 3389)) {
        findings.push({
          module: 'ports',
          checkId: 'admin-remote-access',
          title: '远程管理端口对外可达',
          severity: 'medium',
          confidence: 'high',
          url: `${parsed.scheme ?? 'tcp'}://${host}:${open.find((entry) => entry.port === 22 || entry.port === 3389)?.port}`,
          evidence: 'SSH/RDP 对公网可达；若未启用强口令与双因素，容易被撞库或爆破。',
          cwe: 'CWE-284',
          remediation: '限制来源 IP、启用密钥登录/双因素、部署登录失败封禁。',
        })
      }

      const accepted = deps.store.add(findings)
      const record = run.finish({ requests: results.length, findings: accepted.added })
      return {
        target: host,
        ports,
        open,
        findings: accepted.accepted,
        requests: results.length,
        notes: [`runId=${record.id}`, `超时=${timeoutMs}ms`, `地址类别=${addressClass}`],
      }
    },
  })
}

/**
 * @param {{ preset?: string, ports?: number[] }} args
 * @returns {number[]}
 */
function resolvePorts(args) {
  if (Array.isArray(args.ports) && args.ports.length > 0) {
    const cleaned = [...new Set(args.ports.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))]
    return cleaned.sort((a, b) => a - b)
  }
  const preset = PORT_PRESETS[args.preset ?? 'top20'] ?? PORT_PRESETS.top20
  return [...preset].sort((a, b) => a - b)
}

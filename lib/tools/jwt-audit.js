/**
 * 工具 aimy_jwt_audit：JWT 本地审计（不发起网络请求，因此不需要 scope）。
 *
 * 只做**分析**：解码、声明检查、算法缺陷、弱 HMAC 密钥字典验证。
 * 不生成伪造令牌、不尝试密钥注入攻击链 —— 发现问题由人工在授权窗口内复核。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/jwt-audit
 */

import { createHmac } from 'node:crypto'
import { defineTool } from './define.js'
import { renderText } from './shared.js'

/** 常见弱 HMAC 密钥字典（JWT 工具链默认值 + 常见口令）。 */
export const WEAK_SECRETS = [
  'secret', 'secretkey', 'secret_key', 'password', 'passw0rd', '123456', '12345678', '1234567890',
  'changeme', 'change-me', 'default', 'jwt', 'jwtsecret', 'jwt_secret', 'jwt-secret', 'mysecret',
  'your-256-bit-secret', 'your_jwt_secret', 'supersecret', 'super-secret', 's3cr3t', 'keyboard cat',
  'hunter2', 'qwerty', 'admin', 'root', 'test', 'development', 'dev-secret', 'prod', 'production',
  'example', 'examplekey', 'hmac', 'hmacsecret', 'token', 'tokenkey', 'auth', 'authkey', 'api',
  'apikey', 'api_key', 'express', 'node', 'nodejs', 'laravel', 'django', 'spring', 'flask',
]

/** HS 算法 → node:crypto 摘要名。 */
const HMAC_DIGEST = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

/**
 * @param {{ store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 */
export function createJwtAuditTool(deps) {
  return defineTool({
    name: 'aimy_jwt_audit',
    description:
      '离线审计一个 JWT：解码 header/payload、检查 alg=none、弱 HMAC 密钥（内置字典 + 自定义候选）、jku/x5u 外部密钥、' +
      'kid 注入面、过期时间与敏感声明。纯本地计算，不发网络请求，但仍建议只在授权测试中使用。',
    parameters: {
      token: { type: 'string', required: true, description: '完整 JWT 字符串（三段 base64url，或五段 JWE）' },
      secretCandidates: {
        type: 'array',
        description: '额外的候选密钥（会用 HS* 算法逐一双向验证签名）',
        items: { type: 'string' },
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          header: { type: 'json', required: true },
          payload: { type: 'json', required: true },
          issues: { type: 'json', required: true },
          crackedSecret: { type: 'json' },
          summary: { type: 'string', required: true },
          recommendations: { type: 'json', required: true },
        },
      },
      render: (_args, value) => renderText(value.summary ?? 'JWT 审计完成', {
        问题: Array.isArray(value.issues) ? value.issues.length : 0,
        弱密钥: value.crackedSecret ?? undefined,
      }),
    },
    presentCall: (args) => ({
      card: 'generic',
      title: 'JWT 审计',
      kind: 'other',
      rawInput: typeof args.token === 'string' ? `${args.token.slice(0, 24)}…` : args.token,
    }),
    async execute(args) {
      const token = String(args.token ?? '').trim().replace(/^bearer\s+/i, '')
      if (token.length === 0) throw new Error('token 不能为空')
      const parts = token.split('.')
      if (parts[2] === undefined) {
        throw new Error('不是合法 JWT：期望 header.payload.signature 三段（当前段数不足）')
      }

      /** @type {Record<string, unknown>} */
      let header = {}
      /** @type {Record<string, unknown>} */
      let payload = {}
      /** @type {string[]} */
      const parseNotes = []
      try {
        header = decodeSegment(parts[0])
      } catch {
        parseNotes.push('header 不是合法 base64url JSON')
      }
      try {
        payload = decodeSegment(parts[1])
      } catch {
        parseNotes.push('payload 不是合法 base64url JSON')
      }

      /** @type {unknown[]} */
      const issues = []
      const push = (spec) => {
        issues.push({
          module: 'jwt',
          checkId: spec.checkId,
          title: spec.title,
          severity: spec.severity,
          confidence: spec.confidence ?? 'high',
          url: 'jwt://local-audit',
          evidence: spec.evidence,
          cwe: spec.cwe,
          remediation: spec.remediation,
        })
      }

      const alg = typeof header.alg === 'string' ? header.alg.toUpperCase() : undefined
      if (alg === undefined) {
        push({ checkId: 'jwt-missing-alg', title: 'JWT header 缺少 alg', severity: 'medium', evidence: JSON.stringify(header).slice(0, 300), cwe: 'CWE-347', remediation: '服务端必须固定允许的算法，不接受缺失 alg 的令牌。' })
      } else if (alg === 'NONE') {
        push({
          checkId: 'jwt-alg-none',
          title: 'JWT 使用 alg=none（未签名）',
          severity: 'critical',
          evidence: `header.alg = "none"，签名段长度 ${parts[2].length}`,
          cwe: 'CWE-347',
          remediation: '服务端显式校验算法白名单，拒绝 none/空算法。',
        })
      }

      if (typeof header.jku === 'string' || typeof header.x5u === 'string') {
        push({
          checkId: 'jwt-external-key',
          title: 'JWT header 携带外部密钥源（jku/x5u）',
          severity: 'high',
          evidence: `jku=${String(header.jku ?? '-')} x5u=${String(header.x5u ?? '-')}；若服务端不校验来源，可被指向攻击者密钥。`,
          cwe: 'CWE-347',
          remediation: '固定可信密钥源，忽略或严格白名单 jku/x5u。',
        })
      }
      if (typeof header.kid === 'string' && /[\\/]|\.\.|;|\||`|\$\(/.test(header.kid)) {
        push({
          checkId: 'jwt-kid-injection-surface',
          title: 'JWT header 的 kid 含路径/命令字符',
          severity: 'medium',
          confidence: 'low',
          evidence: `kid = ${String(header.kid).slice(0, 120)}；kid 若被拼进文件路径或查询语句存在注入面，需人工确认实现。`,
          cwe: 'CWE-78',
          remediation: 'kid 只允许映射到本地固定密钥表，禁止拼接路径或语句。',
        })
      }

      // 弱 HMAC 密钥验证
      /** @type {string | undefined} */
      let crackedSecret
      const digest = alg === undefined ? undefined : HMAC_DIGEST[alg]
      if (digest !== undefined) {
        const signingInput = `${parts[0]}.${parts[1]}`
        const candidates = [...WEAK_SECRETS, ...(Array.isArray(args.secretCandidates) ? args.secretCandidates.filter((item) => typeof item === 'string') : [])]
        for (const candidate of candidates) {
          const expected = createHmac(digest, candidate).update(signingInput).digest('base64url')
          if (timingSafeEqual(expected, parts[2])) {
            crackedSecret = candidate
            break
          }
        }
        if (crackedSecret !== undefined) {
          push({
            checkId: 'jwt-weak-hmac-secret',
            title: `JWT 使用可猜测的 HMAC 密钥（${alg}）`,
            severity: 'critical',
            evidence: `用字典候选 "${crackedSecret}" 复算签名与令牌一致，说明密钥强度不足。`,
            cwe: 'CWE-521',
            remediation: '换成 ≥32 字节的高熵随机密钥并轮换；不要复用示例密钥。',
          })
        }
      }

      // 声明检查
      const now = Math.floor(Date.now() / 1000)
      if (typeof payload.exp === 'number') {
        if (payload.exp <= now) {
          push({ checkId: 'jwt-expired', title: 'JWT 已过期（若服务端仍接受则异常）', severity: 'info', confidence: 'high', evidence: `exp=${payload.exp}（${new Date(payload.exp * 1000).toISOString()}），当前 ${new Date(now * 1000).toISOString()}`, cwe: 'CWE-613', remediation: '确认服务端校验 exp。' })
        } else if (payload.exp - now > 60 * 60 * 24 * 30) {
          push({ checkId: 'jwt-long-lived', title: 'JWT 有效期超过 30 天', severity: 'low', evidence: `exp-now = ${Math.round((payload.exp - now) / 86400)} 天`, cwe: 'CWE-613', remediation: '缩短访问令牌有效期，改用刷新令牌机制。' })
        }
      } else {
        push({ checkId: 'jwt-no-exp', title: 'JWT 没有 exp 声明', severity: 'medium', evidence: 'payload 中不存在 exp，令牌可能长期有效。', cwe: 'CWE-613', remediation: '签发时写入 exp，并在服务端强制校验。' })
      }
      if (payload.iss === undefined) {
        push({ checkId: 'jwt-no-iss', title: 'JWT 没有 iss 声明', severity: 'low', evidence: '缺少 iss，不利于校验签发方。', cwe: 'CWE-345', remediation: '签发 iss 并校验。' })
      }
      if (payload.aud === undefined) {
        push({ checkId: 'jwt-no-aud', title: 'JWT 没有 aud 声明', severity: 'low', evidence: '缺少 aud，令牌可能被跨服务重放。', cwe: 'CWE-345', remediation: '签发 aud 并在各服务校验。' })
      }

      const sensitiveKeys = Object.keys(payload).filter((key) => /^(role|roles|admin|is_?admin|scope|scopes|perm|permissions|group|groups)$/i.test(key))
      if (sensitiveKeys.length > 0) {
        push({
          checkId: 'jwt-client-readable-authorization',
          title: 'JWT 载荷包含权限声明（客户端可读）',
          severity: 'info',
          confidence: 'high',
          evidence: `包含字段：${sensitiveKeys.join(', ')}。JWT 载荷仅 base64url 编码，任何人都能读取；权限判断必须在服务端基于签名后的声明做。`,
          cwe: 'CWE-522',
          remediation: '不要放敏感数据；权限判断在服务端完成，且不要仅信任前端展示。',
        })
      }

      if (parseNotes.length > 0) {
        push({ checkId: 'jwt-malformed', title: 'JWT 结构不完整', severity: 'low', confidence: 'low', evidence: parseNotes.join('；'), cwe: 'CWE-345', remediation: '确认令牌是否被截断或使用了非 JWT 格式。' })
      }

      const accepted = deps.store.add(issues)
      const severities = summarizeSeverities(accepted.accepted)
      return {
        header,
        payload,
        issues: accepted.accepted,
        ...(crackedSecret === undefined ? {} : { crackedSecret }),
        summary: accepted.accepted.length === 0 ? '未发现明显的 JWT 配置缺陷（仍需人工确认服务端校验逻辑）' : `发现 ${accepted.accepted.length} 个问题：${severities}`,
        recommendations: buildRecommendations(accepted.accepted),
      }
    },
  })
}

/**
 * @param {string} segment
 * @returns {Record<string, unknown>}
 */
function decodeSegment(segment) {
  const json = Buffer.from(segment, 'base64url').toString('utf8')
  const value = JSON.parse(json)
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object')
  return value
}

/**
 * 定长时间比较，避免把密钥验证本身变成时序侧信道。
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index)
  return diff === 0
}

/**
 * @param {unknown[]} findings
 * @returns {string}
 */
function summarizeSeverities(findings) {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  const labels = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
  const counts = new Map()
  for (const finding of findings) {
    const severity = /** @type {{ severity?: string }} */ (finding).severity ?? 'info'
    counts.set(severity, (counts.get(severity) ?? 0) + 1)
  }
  return order
    .filter((severity) => (counts.get(severity) ?? 0) > 0)
    .map((severity) => `${labels[severity]} ${counts.get(severity)}`)
    .join('，')
}

/**
 * @param {unknown[]} findings
 * @returns {string[]}
 */
function buildRecommendations(findings) {
  const checks = new Set(findings.map((finding) => /** @type {{ checkId?: string }} */ (finding).checkId))
  /** @type {string[]} */
  const out = []
  if (checks.has('jwt-weak-hmac-secret') || checks.has('jwt-alg-none')) out.push('更换高熵密钥，并在服务端固定算法白名单（拒绝 none）。')
  if (checks.has('jwt-no-exp')) out.push('签发时写入 exp，服务端强制校验过期时间。')
  if (checks.has('jwt-external-key')) out.push('忽略外部 jku/x5u，或对密钥来源做严格白名单。')
  if (checks.has('jwt-no-aud') || checks.has('jwt-no-iss')) out.push('补齐 iss/aud 声明并在各服务校验，防止跨服务重放。')
  if (out.length === 0) out.push('继续保持：密钥轮换、算法白名单、短有效期、服务端鉴权。')
  return out
}

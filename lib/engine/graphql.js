/**
 * GraphQL 检测（introspection 可用性 / GET 批量查询）。
 *
 * 检测原理：
 * 1. 从目标 URL 推测常见 GraphQL 端点（/graphql、/api/graphql、/graphiql 等）；
 * 2. POST 一个**只读** introspection 查询，若返回 `data.__schema.types`
 *    且类型数量 > 0，判定 introspection 开启（暴露 schema）；
 * 3. 用 GET + `?query={__typename}` 检查端点是否接受 GET 查询
 *    （可能被用于跨站发起查询，配合 CSRF 风险）；
 * 4. 只发送查询，**绝不发送 mutation**，避免创建/修改业务数据。
 *
 * 局限：
 * - introspection 被禁用时无法枚举 schema，但端点仍可能存在（漏报）；
 * - 端点猜测是启发式，自定义路径（如 /api/v3/gql）可能漏报；
 * - GET 查询可被接受不等同于存在可利用漏洞，因此只给 low/info。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/graphql
 */

import {
  createSession, isHttpResponse, makeFinding, stableSortFindings, handleModuleError,
  safeJsonParse, oneLine, readyForMode, describeResponse,
} from './util.js'
import { GRAPHQL_INTROSPECTION_QUERY, GRAPHQL_TYPENAME_QUERY } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'graphql',
  title: 'GraphQL 端点检测',
  kinds: ['graphql', 'api'],
  cwe: 'CWE-200',
  defaultSeverity: 'medium',
  minMode: 'rookie',
}

/**
 * 从目标 URL 推测 GraphQL 端点候选（去重、最多 4 个）。
 * @param {string} targetUrl
 * @returns {string[]}
 */
function endpointCandidates(targetUrl) {
  /** @type {string[]} */
  const candidates = []
  let base
  try {
    base = new URL(targetUrl)
  } catch {
    return candidates
  }
  const push = (value) => {
    if (!candidates.includes(value)) candidates.push(value)
  }
  if (/graphql|graphiql/i.test(base.pathname)) push(base.toString())
  const paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphiql', '/query']
  for (const path of paths) {
    const candidate = new URL(base.toString())
    candidate.pathname = path
    candidate.search = ''
    candidate.hash = ''
    push(candidate.toString())
  }
  return candidates.slice(0, 4)
}

/**
 * 判断响应是否是合法的 GraphQL JSON 结果。
 * @param {object} response
 * @returns {object | null}
 */
function parseGraphqlBody(response) {
  const json = safeJsonParse(response.body)
  if (json === null || typeof json !== 'object' || Array.isArray(json)) {
    const text = String(response.body ?? '')
    if (/GraphQL|__schema|__typename/i.test(text)) return { text: true }
    return null
  }
  return json
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  const session = createSession(ctx)
  const targetUrl = String(ctx?.target?.url ?? '')
  if (targetUrl.length === 0) return []
  /** @type {object[]} */
  const findings = []
  /** @type {Set<string>} */
  const reportedEndpoints = new Set()

  try {
    for (const endpoint of endpointCandidates(targetUrl)) {
      if (session.aborted || session.remaining <= 0) break

      // 1) introspection（只读查询）
      const introspection = await session.probe(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ query: GRAPHQL_INTROSPECTION_QUERY }),
      })
      if (!introspection) break
      if (isHttpResponse(introspection)) {
        const json = parseGraphqlBody(introspection)
        const types = json && typeof json === 'object' && !Array.isArray(json)
          ? json?.data?.__schema?.types
          : undefined
        if (Array.isArray(types) && types.length > 0) {
          findings.push(makeFinding({
            module: meta.id,
            checkId: 'graphql-introspection',
            title: 'GraphQL introspection 未禁用',
            severity: 'medium',
            confidence: 'high',
            url: endpoint,
            evidence: `端点 ${endpoint} 接受 introspection 查询，返回 ${types.length} 个 schema 类型；响应 ${describeResponse(introspection)}。`,
            cwe: meta.cwe,
            remediation: '生产环境禁用 introspection（或仅对内部/鉴权用户开放），并限制查询复杂度。',
          }))
          reportedEndpoints.add(endpoint)
          continue
        }
        const errors = json && typeof json === 'object' && !Array.isArray(json) ? json?.errors : undefined
        if (Array.isArray(errors)) {
          const text = oneLine(errors.map((error) => error?.message ?? '').join('; '), 160)
          if (/graphql|schema|query/i.test(text)) reportedEndpoints.add(endpoint)
        }
      }

      // 2) GET 方式查询（CSRF 风险面）
      if (session.aborted || session.remaining <= 0) break
      const getUrl = new URL(endpoint)
      getUrl.searchParams.set('query', GRAPHQL_TYPENAME_QUERY)
      const getResponse = await session.probe(getUrl.toString(), { method: 'GET' })
      if (!getResponse) break
      if (!isHttpResponse(getResponse) || getResponse.status !== 200) continue
      const getJson = parseGraphqlBody(getResponse)
      if (getJson === null) continue
      const data = getJson && typeof getJson === 'object' && !Array.isArray(getJson) ? getJson.data : undefined
      const acceptedGet = data !== null && typeof data === 'object' && (typeof data.__typename === 'string' || '__typename' in data)
      if (!acceptedGet) continue
      findings.push(makeFinding({
        module: meta.id,
        checkId: 'graphql-get-query',
        title: 'GraphQL 端点接受 GET 查询',
        severity: 'low',
        confidence: 'medium',
        url: endpoint,
        payload: GRAPHQL_TYPENAME_QUERY,
        evidence: `端点 ${endpoint} 对 GET ?query={__typename} 返回 200 且响应含 data.__typename，可能被跨站 GET 请求触发查询。`,
        cwe: meta.cwe,
        remediation: '只允许 POST 执行 GraphQL 查询，并校验 Content-Type 与 CSRF token。',
      }))
      reportedEndpoints.add(endpoint)
    }
  } catch (error) {
    handleModuleError(ctx, meta.id, error)
  }
  return stableSortFindings(findings)
}

/**
 * 本地文件包含 / 路径遍历检测。
 *
 * 检测原理：
 * 1. 取基线，记录基线响应体；
 * 2. 注入 `../etc/passwd`、`..\\windows\\win.ini` 等遍历串，
 *    只有响应里出现**基线没有的**文件内容特征（如 `root:...:0:0:`）才判定；
 * 3. veteran 模式追加 URL 编码/双编码变体，以及 PHP filter 包装器读取；
 *    包装器只做 base64 读取并**本地解码校验**（含 `<?php` 等特征）才计为命中。
 *
 * 局限：
 * - 只读取系统特征文件，不写文件、不写日志、不投毒；
 * - 不执行命令、不使用 expect:// 等 RCE 包装器；
 * - 应用把路径限制在固定目录或重写 URL 时会漏报（保守策略）。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/lfi
 */

import {
  createSession, pickParams, sendParamBaseline, sendParamValue, isHttpResponse,
  matchSignatures, makeFinding, stableSortFindings, handleModuleError,
  describeResponse, oneLine, readyForMode,
} from './util.js'
import { forMode, LFI_TRAVERSAL_PAYLOADS, LFI_WRAPPER_PAYLOADS, LFI_SIGNATURES } from './payloads.js'

/** @type {{ id: string, title: string, kinds: string[], cwe: string, defaultSeverity: string, minMode: 'rookie' }} */
export const meta = {
  id: 'lfi',
  title: '本地文件包含 / 路径遍历检测',
  kinds: ['lfi', 'path-traversal', 'file-inclusion'],
  cwe: 'CWE-98',
  defaultSeverity: 'high',
  minMode: 'rookie',
}

/** 每个参数最多测试的遍历 payload 数（控制请求预算）。 */
const TRAVERSAL_LIMIT = { rookie: 5, veteran: 8 }

/**
 * 在响应中查找基线不存在的文件内容特征。
 * @param {string} body
 * @param {string} baselineBody
 * @returns {Array<{ id: string, file: string, match: string }>}
 */
function findFileSignatures(body, baselineBody) {
  const baselineIds = new Set(matchSignatures(baselineBody, LFI_SIGNATURES).map((hit) => hit.id))
  return matchSignatures(body, LFI_SIGNATURES)
    .filter((hit) => !baselineIds.has(hit.id))
    .map((hit) => {
      const sig = LFI_SIGNATURES.find((candidate) => candidate.id === hit.id)
      return { id: hit.id, file: sig?.file ?? '', match: hit.match }
    })
}

/**
 * 尝试从响应中提取 PHP filter 的 base64 内容并本地解码校验。
 * @param {string} body
 * @returns {{ decoded: string, chunkLength: number } | null}
 */
function decodeFilteredBase64(body) {
  const matcher = /[A-Za-z0-9+/]{80,}={0,2}/g
  const found = matcher.exec(body)
  if (found === null) return null
  const chunk = found[0]
  let decoded = ''
  try {
    decoded = Buffer.from(chunk, 'base64').toString('utf8')
  } catch {
    return null
  }
  if (decoded.length === 0) return null
  const printable = decoded.replace(/[^\x20-\x7e\r\n\t]/g, '')
  const ratio = printable.length / decoded.length
  if (ratio < 0.8) return null
  if (!/\<\?php|\<\?=|root:[^:\r\n]*:0:0:|\[fonts\]/i.test(decoded)) return null
  return { decoded, chunkLength: chunk.length }
}

/**
 * 检测单个参数。
 * @param {ReturnType<typeof createSession>} session
 * @param {{ name: string, location: string, sample: string }} spec
 * @returns {Promise<object[]>}
 */
async function checkParam(session, spec) {
  /** @type {object[]} */
  const findings = []
  const baseline = await sendParamBaseline(session, spec)
  if (!baseline || !isHttpResponse(baseline)) return findings

  const traversalPayloads = forMode(LFI_TRAVERSAL_PAYLOADS, session.ctx.mode)
    .slice(0, TRAVERSAL_LIMIT[session.ctx.mode === 'veteran' ? 'veteran' : 'rookie'])

  for (const payload of traversalPayloads) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, payload)
    if (!response) break
    if (!isHttpResponse(response)) continue
    const hits = findFileSignatures(response.body, baseline.body)
    if (hits.length === 0) continue
    const hit = hits[0]
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'lfi-traversal',
      title: '本地文件包含 / 路径遍历',
      severity: 'high',
      confidence: hit.id === 'hostname' ? 'medium' : 'high',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload,
      evidence:
        `参数 ${spec.name} 注入路径遍历串「${payload}」后读取到特征文件 ${hit.file}：` +
        `${hit.id}="${oneLine(hit.match, 80)}"；基线 ${describeResponse(baseline)}，命中响应 ${describeResponse(response)}。`,
      cwe: meta.cwe,
      remediation: '使用文件名白名单/固定映射，规范化路径并拒绝 .. 序列；以最小权限运行应用。',
    }))
    return findings
  }

  // PHP 包装器（仅 veteran）：base64 读取后本地解码校验，证据更硬。
  for (const wrapper of forMode(LFI_WRAPPER_PAYLOADS, session.ctx.mode)) {
    if (session.aborted || session.remaining <= 0) break
    const response = await sendParamValue(session, spec, wrapper.value)
    if (!response) break
    if (!isHttpResponse(response)) continue
    const decoded = decodeFilteredBase64(response.body)
    if (decoded === null) continue
    const hint = oneLine(decoded.decoded, 120)
    findings.push(makeFinding({
      module: meta.id,
      checkId: 'lfi-php-filter',
      title: 'PHP filter 包装器文件读取',
      severity: 'high',
      confidence: 'high',
      url: String(session.ctx?.target?.url ?? ''),
      param: spec.name,
      payload: wrapper.value,
      evidence:
        `参数 ${spec.name} 使用「${wrapper.value}」返回 base64 数据（${decoded.chunkLength} 字符），` +
        `本地解码后含文件内容特征。解码片段：${hint}`,
      cwe: meta.cwe,
      remediation: '禁用不必要的 PHP 包装器（allow_url_include=Off 并限制 filter 协议），校验包含路径。',
    }))
    return findings
  }
  return findings
}

/**
 * @param {object} ctx ProbeContext
 * @returns {Promise<object[]>}
 */
export async function run(ctx) {
  if (!readyForMode(ctx, meta.minMode)) return []
  const session = createSession(ctx)
  /** @type {object[]} */
  const findings = []
  for (const spec of pickParams(ctx, 2)) {
    if (session.aborted) break
    try {
      findings.push(...(await checkParam(session, spec)))
    } catch (error) {
      handleModuleError(ctx, meta.id, error)
    }
  }
  return stableSortFindings(findings)
}

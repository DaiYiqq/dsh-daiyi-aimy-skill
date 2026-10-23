/**
 * 工具注册表：插件向宿主暴露的全部模型可调用工具。
 *
 * 约定：每个 create*Tool 返回 `defineTool(...)` 的结果（已通过宿主 schema 校验）。
 * 工具名统一 `aimy_` 前缀，snake_case，避免与宿主内置工具或其他插件冲突。
 *
 * @module dsh-daiyi-aimy-skill/lib/tools/index
 */

import { createScopeTool } from './scope.js'
import { createReconTool } from './recon.js'
import { createPortScanTool } from './port-scan.js'
import { createDirFuzzTool } from './dir-fuzz.js'
import { createCrawlTool } from './crawl.js'
import { createWebScanTool } from './web-scan.js'
import { createJwtAuditTool } from './jwt-audit.js'
import { createReportTool } from './report.js'

/** 工具名清单（不含宿主提供的其他工具）。 */
export const TOOL_NAMES = /** @type {const} */ ([
  'aimy_scope',
  'aimy_recon',
  'aimy_port_scan',
  'aimy_dir_fuzz',
  'aimy_crawl',
  'aimy_web_scan',
  'aimy_jwt_audit',
  'aimy_report',
])

/**
 * 按依赖构造全部工具定义（不注册，注册由插件入口完成）。
 * @param {{ scope: import('../scope.js').ScopeStore, store: import('../store.js').FindingsStore, config: object, log: Function }} deps
 * @returns {object[]} defineTool 结果数组
 */
export function createTools(deps) {
  return [
    createScopeTool(deps),
    createReconTool(deps),
    createPortScanTool(deps),
    createDirFuzzTool(deps),
    createCrawlTool(deps),
    createWebScanTool(deps),
    createJwtAuditTool(deps),
    createReportTool(deps),
  ]
}

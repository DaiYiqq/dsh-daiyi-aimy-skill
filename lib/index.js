/**
 * dsh-daiyi-aimy-skill · DeepSeek Harness 插件入口
 *
 * 由 zxz0119/aimy-sikll（Python CLI 渗透测试辅助工具）再开发而来：
 * 把命令行脚本升级为宿主内的原生 Cordis 插件 —— 模型可直接调用 8 个工具，
 * 8 个中文 playbook 技能随插槽加载，所有网络访问强制经过授权范围护栏。
 *
 * 加载契约（见 docs/CONTRACT.md）：
 *   export const name   插件 id
 *   export const inject 需要的宿主服务
 *   export function apply(ctx, config) 注册工具与技能
 *
 * `apply` 必须永不抛错：任何单个注册失败只记录 warning，保证插件不会拖垮宿主启动。
 *
 * @module dsh-daiyi-aimy-skill
 */

import { MODE_PRESETS, PLUGIN_ID, PLUGIN_VERSION, normalizeConfig } from './config.js'
import { ScopeStore } from './scope.js'
import { FindingsStore } from './store.js'
import { createTools } from './tools/index.js'
import { loadSkillPack } from './skills/index.js'

/** 插件 id（Cordis row 里也用这个名字）。 */
export const name = 'daiyi-aimy-skill'

/** 依赖的宿主服务：工具注册表与技能注册表。 */
export const inject = ['tools', 'skills']

/**
 * 挂载插件。
 * @param {object} ctx Cordis 上下文
 * @param {Record<string, unknown>} [rawConfig] cordis.patch.yml 中该行的 config
 * @returns {Promise<void>}
 */
export async function apply(ctx, rawConfig) {
  const log = createLogger(ctx)
  const { config, warnings } = normalizeConfig(rawConfig)
  for (const warning of warnings) log('warn', warning)

  // ── 授权范围：加载失败也要继续启动（deny-by-default 的语义天然安全）──
  const scopeFile = config.persistScope ? ScopeStore.defaultFile(config.scopeFile) : null
  const scope = new ScopeStore({ file: scopeFile, persist: config.persistScope, allowPrivateNetworks: config.allowPrivateNetworks })
  try {
    await scope.load()
    if (scope.loadError !== null) log('warn', `授权范围文件读取失败（按空范围启动）：${scope.loadError}`)
  } catch (error) {
    log('warn', `授权范围初始化异常（按空范围启动）：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
  }

  const store = new FindingsStore({ maxFindings: config.maxFindings, maxRuns: config.maxRuns })

  // ── 工具注册 ──
  let registeredTools = 0
  if (ctx?.tools === undefined || typeof ctx.tools.register !== 'function') {
    log('warn', '宿主未提供 tools 服务，跳过工具注册（技能仍会注册）')
  } else {
    let tools = []
    try {
      tools = createTools({ scope, store, config, log })
    } catch (error) {
      log('warn', `构造工具定义失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
      tools = []
    }
    for (const tool of tools) {
      try {
        ctx.tools.register(tool)
        registeredTools += 1
      } catch (error) {
        // 单个工具 schema 不合法（或与既有工具重名）时不让整插件失败
        log('warn', `注册工具 ${String(tool?.name ?? '?')} 失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
      }
    }
  }

  // ── 技能注册 ──
  let registeredSkills = 0
  if (ctx?.skills === undefined || typeof ctx.skills.register !== 'function') {
    log('warn', '宿主未提供 skills 服务，跳过技能注册')
  } else {
    try {
      const { skills, warnings: skillWarnings } = await loadSkillPack()
      for (const warning of skillWarnings ?? []) {
        log('warn', `技能包：${warning.file} — ${warning.message}`)
      }
      for (const skill of skills ?? []) {
        try {
          ctx.skills.register({
            name: skill.name,
            description: skill.description,
            ...(skill.whenToUse === undefined ? {} : { whenToUse: skill.whenToUse }),
            content: skill.content,
            invocation: { modelInvocable: true, userInvocable: true },
          })
          registeredSkills += 1
        } catch (error) {
          log('warn', `注册技能 ${skill?.name ?? '?'} 失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
        }
      }
    } catch (error) {
      log('warn', `技能包加载失败：${String(/** @type {{ message?: string }} */ (error)?.message ?? error)}`)
    }
  }

  log(
    'info',
    `${PLUGIN_ID} v${PLUGIN_VERSION} 已加载：模式=${MODE_PRESETS[config.mode].label}，工具 ${registeredTools} 个，技能 ${registeredSkills} 个，` +
      `授权范围 ${scope.list().length} 条${config.persistScope ? `（${scopeFile}）` : '（仅内存）'}`,
  )
  if (scope.list().length === 0) {
    log('info', '提示：尚未登记授权范围，所有网络工具都会拒绝执行；请先调用 aimy_scope(action="add", ...)')
  }
}

/**
 * 构造带前缀的日志函数；宿主 logger 不可用时回退 console。
 * @param {object} ctx
 * @returns {(level: 'debug' | 'info' | 'warn', message: string) => void}
 */
function createLogger(ctx) {
  let logger
  try {
    logger = typeof ctx?.logger === 'function' ? ctx.logger(PLUGIN_ID) : undefined
  } catch {
    logger = undefined
  }
  return (level, message) => {
    const line = `[${PLUGIN_ID}] ${message}`
    const sink = logger?.[level]
    if (typeof sink === 'function') {
      try {
        sink.call(logger, message)
        return
      } catch {
        /* 落到 console */
      }
    }
    // 宿主没有 logger 时不要在正常路径刷屏，warning 以上才输出
    if (level === 'warn') console.warn(line)
    else if (level === 'info') console.info(line)
  }
}

export default apply

/**
 * 配置与运行模式。
 *
 * 设计要点：
 * - 不引入 schemastery，配置就是普通对象合并，宿主传什么就用什么，非法值回退默认并记录 warning。
 * - 运行模式（rookie / veteran）只影响**默认预算**与**payload 激进度**，不改变安全边界。
 *
 * @module dsh-daiyi-aimy-skill/lib/config
 */

/** 插件标识（日志、存储目录、User-Agent 共用）。 */
export const PLUGIN_ID = 'daiyi-aimy-skill'

/** 插件版本，与 package.json 保持同步。 */
export const PLUGIN_VERSION = '3.0.0'

/** 运行模式预设。引擎与工具从这里取预算。 */
export const MODE_PRESETS = {
  /**
   * 菜鸟模式：只读、低并发、保守 payload，适合演练与学习。
   */
  rookie: {
    label: '菜鸟模式',
    concurrency: 4,
    maxRequests: 24,
    timeoutMs: 8000,
    allowTimeBased: false,
    allowAggressivePayloads: false,
    verbose: true,
  },
  /**
   * 老鸟模式：更高并发、允许时间盲注与激进 payload，但**仍然只做检测**。
   */
  veteran: {
    label: '老鸟模式',
    concurrency: 8,
    maxRequests: 60,
    timeoutMs: 12000,
    allowTimeBased: true,
    allowAggressivePayloads: true,
    verbose: false,
  },
}

/** 默认配置。 */
export const DEFAULTS = {
  /** 'rookie' | 'veteran' */
  mode: 'rookie',
  /** 是否把授权范围写入磁盘（false = 进程内内存态，重启即失效）。 */
  persistScope: true,
  /** 授权范围文件路径；null = <DSH_HOME>/daiyi-aimy-skill/scope.json */
  scopeFile: null,
  /** 单个 HTTP 请求超时（毫秒）。 */
  timeoutMs: MODE_PRESETS.rookie.timeoutMs,
  /** 单次工具调用的请求预算。 */
  maxRequests: MODE_PRESETS.rookie.maxRequests,
  /** 并发上限。 */
  concurrency: MODE_PRESETS.rookie.concurrency,
  /** 响应体最大读取字节数。 */
  maxBodyBytes: 262144,
  /** 默认是否跟随重定向（安全默认：不跟随，直接暴露 3xx）。 */
  followRedirects: false,
  /** 重定向最大跳数（仅在跟随开启时生效）。 */
  maxRedirects: 3,
  /** 默认 User-Agent。 */
  userAgent: `dsh-daiyi-aimy-skill/${PLUGIN_VERSION} (authorized-security-testing; +https://github.com/DaiYiqq/dsh-daiyi-aimy-skill)`,
  /** 是否允许访问回环/内网地址（仍必须显式登记在授权范围内）。 */
  allowPrivateNetworks: false,
  /** 报告里是否对疑似凭据做脱敏。 */
  redactSecrets: true,
  /** 内存中保留的最大 finding 条数。 */
  maxFindings: 800,
  /** 内存中保留的最大运行记录条数。 */
  maxRuns: 60,
}

const DURATION_KEYS = ['timeoutMs']
const COUNT_KEYS = ['maxRequests', 'concurrency', 'maxBodyBytes', 'maxRedirects', 'maxFindings', 'maxRuns']
const BOOL_KEYS = ['persistScope', 'followRedirects', 'allowPrivateNetworks', 'redactSecrets']

/**
 * 合并宿主配置与默认值。非法值回退默认，并把原因写进 warnings，绝不抛错。
 * @param {Record<string, unknown>} [raw] 宿主配置（cordis.patch.yml 的 config）。
 * @returns {{ config: typeof DEFAULTS & { preset: typeof MODE_PRESETS.rookie, warnings: string[] } }}
 */
export function normalizeConfig(raw) {
  const warnings = []
  const input = raw !== null && typeof raw === 'object' ? raw : {}
  const mode = input.mode === 'veteran' ? 'veteran' : 'rookie'
  if (input.mode !== undefined && input.mode !== 'rookie' && input.mode !== 'veteran') {
    warnings.push(`未知 mode "${String(input.mode)}"，已回退 rookie`)
  }
  const preset = MODE_PRESETS[mode]
  const config = { ...DEFAULTS, ...preset, mode, preset }

  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || value === null) continue
    if (key === 'mode') continue
    if (key === 'scopeFile') {
      if (typeof value === 'string' && value.trim().length > 0) config.scopeFile = value.trim()
      else warnings.push('scopeFile 必须是非空字符串，已忽略')
      continue
    }
    if (key === 'userAgent') {
      if (typeof value === 'string' && value.trim().length > 0) config.userAgent = value.trim()
      else warnings.push('userAgent 必须是非空字符串，已忽略')
      continue
    }
    if (BOOL_KEYS.includes(key)) {
      if (typeof value === 'boolean') config[key] = value
      else warnings.push(`${key} 必须是布尔值，已忽略`)
      continue
    }
    if (DURATION_KEYS.includes(key) || COUNT_KEYS.includes(key)) {
      const parsed = typeof value === 'number' ? value : Number(value)
      if (!Number.isFinite(parsed) || parsed <= 0) {
        warnings.push(`${key} 必须是正数，已忽略`)
        continue
      }
      config[key] = Math.floor(parsed)
      continue
    }
    warnings.push(`未知配置项 "${key}"，已忽略`)
  }

  // 模式预算只能被显式配置放宽，不能被静默放大到不合理的量级。
  if (config.maxRequests > 400) {
    warnings.push(`maxRequests=${config.maxRequests} 过大，已钳制到 400`)
    config.maxRequests = 400
  }
  if (config.concurrency > 32) {
    warnings.push(`concurrency=${config.concurrency} 过大，已钳制到 32`)
    config.concurrency = 32
  }
  if (config.timeoutMs > 60000) {
    warnings.push(`timeoutMs=${config.timeoutMs} 过大，已钳制到 60000`)
    config.timeoutMs = 60000
  }
  if (config.maxBodyBytes > 4 * 1024 * 1024) {
    warnings.push('maxBodyBytes 过大，已钳制到 4MiB')
    config.maxBodyBytes = 4 * 1024 * 1024
  }

  return { config, warnings }
}

/**
 * 生成传给引擎模块的预算对象。
 * @param {ReturnType<typeof normalizeConfig>['config']} config
 * @returns {{ timeoutMs: number, maxRequests: number, maxBodyBytes: number, concurrency: number }}
 */
export function engineLimits(config) {
  return {
    timeoutMs: config.timeoutMs,
    maxRequests: config.maxRequests,
    maxBodyBytes: config.maxBodyBytes,
    concurrency: config.concurrency,
  }
}

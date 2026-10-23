/**
 * 假的 Cordis 上下文（仅用于契约测试）。
 *
 * 目标：在没有 DSH 运行时的机器上，也能调用 `lib/index.js` 的 `apply(ctx, config)`，
 * 并检查它到底注册了什么。假 ctx 只模拟插件用到的宿主面，且**刻意模仿真实实现的
 * 关键失败语义**：
 *
 *   - `tools.register()`：与 @deepseek-ai/dsh-tools 的 ToolRuntime 一致——定义必须是
 *     对象、`output.render` 必须是函数、**同层重名会抛错**。这样「apply 永不抛错」
 *     的契约（单个注册失败要自行 catch + warn）才真的被验证到。
 *   - `skills.register()`：与 @deepseek-ai/dsh-skill 一致——缺 name/description 抛错；
 *     重名时 warn 并返回 no-op disposer（first-wins）。
 *   - `ctx.logger(scope)`：真实 Cordis 的 `ctx.logger` 是**函数**，返回带
 *     debug/info/warn/error 的 logger 对象。这里同时把 logger 方法挂在函数自身上，
 *     兼容 `ctx.logger.warn(...)` 的老写法；两种写法都会被记入 `logs`。
 *   - `ctx.effect()` / `ctx.on()`：记录 disposer，便于断言可清理副作用。
 *
 * 不模拟的部分（不参与本插件契约）：scope 分层、服务注入/依赖图、事件总线语义。
 *
 * @module test/helpers/fake-ctx
 */

/** 日志级别（与 Cordis logger 一致的常用四级）。 */
const LOG_LEVELS = ['debug', 'info', 'warn', 'error']

/** 把任意参数压成一行可读文本。 */
function renderLogArgs(args) {
  return args
    .map((value) => {
      if (typeof value === 'string') return value
      try {
        return JSON.stringify(value)
      } catch {
        return String(value)
      }
    })
    .join(' ')
}

/**
 * 创建一个假的 Cordis ctx。
 *
 * @param {object} [options]
 * @param {string} [options.label] logger 的默认 scope 名
 * @param {boolean} [options.mirrorToConsole] 是否同时把 warn/error 打到 console（默认 false）
 * @returns {{
 *   ctx: object,
 *   tools: object[],
 *   skills: object[],
 *   logs: Array<{level: string, scope: string, message: string}>,
 *   disposers: Function[],
 *   clearLogs: () => void,
 * }}
 */
export function createFakeCtx(options = {}) {
  const label = typeof options.label === 'string' && options.label.length > 0 ? options.label : 'fake-ctx'
  /** @type {object[]} 已注册工具定义（defineTool 结果原样保存） */
  const tools = []
  /** @type {object[]} 已注册技能定义 */
  const skills = []
  /** @type {Array<{level: string, scope: string, message: string}>} */
  const logs = []
  /** @type {Function[]} 注册 disposer / effect 清理函数 */
  const disposers = []
  /** @type {Set<string>} 工具名集合（用于重名检测） */
  const toolNames = new Set()
  /** @type {Map<string, Function[]>} 事件监听器 */
  const listeners = new Map()

  /** 记录一条日志。 */
  function record(level, scope, args) {
    const message = renderLogArgs(args)
    logs.push({ level, scope, message })
    if (options.mirrorToConsole === true && (level === 'warn' || level === 'error')) {
      // eslint-disable-next-line no-console
      console[level](`[${scope}] ${message}`)
    }
  }

  /** 创建一个 logger 对象（带 child 与四个级别方法）。 */
  function makeLogger(scope) {
    /** @type {Record<string, unknown>} */
    const logger = { name: scope }
    for (const level of LOG_LEVELS) {
      logger[level] = (...args) => record(level, scope, args)
    }
    logger.child = (name) => makeLogger(String(name))
    return logger
  }

  // 真实 Cordis：ctx.logger 是函数 `ctx.logger(name?) -> Logger`。
  const logger = (scope) => makeLogger(scope === undefined ? label : String(scope))
  // 兼容旧式 `ctx.logger.warn(...)` / `ctx.log.warn(...)`。
  for (const level of LOG_LEVELS) {
    logger[level] = (...args) => record(level, label, args)
  }
  logger.child = (name) => makeLogger(String(name))

  const ctx = {
    logger,
    log: logger,

    tools: {
      /** 与 ToolRuntime.register 的关键前置校验保持一致。 */
      register(definition) {
        if (definition === null || typeof definition !== 'object') {
          throw new TypeError('tools.register(definition) 需要一个对象')
        }
        const name = definition.name
        if (typeof name !== 'string' || name.length === 0) {
          throw new TypeError('工具定义缺少字符串 name')
        }
        const output = definition.output
        if (output === null || typeof output !== 'object' || typeof output.render !== 'function') {
          throw new TypeError(`tool "${name}" must declare output { schema, render }`)
        }
        if (toolNames.has(name)) {
          throw new Error(`tool "${name}" is already registered in this scope`)
        }
        toolNames.add(name)
        tools.push(definition)
        const dispose = () => {
          if (!toolNames.delete(name)) return
          const index = tools.indexOf(definition)
          if (index >= 0) tools.splice(index, 1)
        }
        disposers.push(dispose)
        return dispose
      },
      /** 已注册工具定义快照。 */
      list: () => tools.slice(),
      get: (name) => tools.find((tool) => tool.name === name),
      has: (name) => toolNames.has(name),
    },

    skills: {
      /** 与 SkillsService.register 一致：重名 warn + first-wins + no-op disposer。 */
      register(skill) {
        if (skill === null || typeof skill !== 'object') {
          throw new TypeError('skills.register(skill) 需要一个对象')
        }
        if (typeof skill.name !== 'string' || skill.name.length === 0) {
          throw new TypeError('技能定义缺少字符串 name')
        }
        if (typeof skill.description !== 'string' || skill.description.length === 0) {
          throw new TypeError(`技能 "${skill.name}" 缺少字符串 description`)
        }
        if (skills.some((registered) => registered.name === skill.name)) {
          record('warn', label, [`runtime skill "${skill.name}" ignored because it is already registered`])
          return () => {}
        }
        const stored = { ...skill }
        skills.push(stored)
        const dispose = () => {
          const index = skills.indexOf(stored)
          if (index >= 0) skills.splice(index, 1)
        }
        disposers.push(dispose)
        return dispose
      },
      list: () => skills.slice(),
      get: (name) => skills.find((skill) => skill.name === name),
    },

    /**
     * 简化版 Cordis effect：执行回调并记录其返回的 disposer。
     * @param {Function} callback
     */
    effect(callback) {
      if (typeof callback !== 'function') return () => {}
      const result = callback({})
      const dispose = typeof result === 'function' ? result : () => {}
      disposers.push(dispose)
      return dispose
    },

    /** 事件监听（记录并返回 disposer）。 */
    on(event, listener) {
      if (typeof listener !== 'function') return () => {}
      const list = listeners.get(String(event)) ?? []
      list.push(listener)
      listeners.set(String(event), list)
      return () => {
        const current = listeners.get(String(event))
        if (!current) return
        const index = current.indexOf(listener)
        if (index >= 0) current.splice(index, 1)
      }
    },
    off(event, listener) {
      const current = listeners.get(String(event))
      if (!current) return
      const index = current.indexOf(listener)
      if (index >= 0) current.splice(index, 1)
    },
    emit(event, ...args) {
      for (const listener of listeners.get(String(event)) ?? []) listener(...args)
    },

    /** 服务查询：假 ctx 只认识 tools / skills 两个服务。 */
    get(key) {
      if (key === 'tools') return ctx.tools
      if (key === 'skills') return ctx.skills
      return undefined
    },
    /** 服务注册：假 ctx 不维护服务依赖图，只记录。 */
    set() {},
    provide() {},

    /** 清理：按注册逆序执行 disposer。 */
    async dispose() {
      for (const dispose of [...disposers].reverse()) {
        try {
          await dispose()
        } catch {
          /* 假 ctx 不因清理失败打断测试 */
        }
      }
      disposers.length = 0
      listeners.clear()
    },
  }

  return {
    ctx,
    tools,
    skills,
    logs,
    disposers,
    /** 清空日志（保留注册结果）。 */
    clearLogs() {
      logs.length = 0
    },
  }
}

/**
 * 过滤日志。
 * @param {Array<{level: string}>} logs
 * @param {'debug'|'info'|'warn'|'error'} level
 * @returns {Array<{level: string, scope: string, message: string}>}
 */
export function logsAtLevel(logs, level) {
  return logs.filter((entry) => entry.level === level)
}

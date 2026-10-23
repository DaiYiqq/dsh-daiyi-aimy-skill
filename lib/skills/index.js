/**
 * 技能包加载器（skills-author 范围）。
 *
 * 契约见 docs/CONTRACT.md 第 3 节：
 * - 每个技能目录 `skills/<kebab-name>/SKILL.md`，frontmatter 只有 `key: value` 标量；
 * - 零第三方依赖，只用 `node:fs/promises` 与 `node:url`；
 * - 按目录名排序保证确定性，解析失败跳过并写入 warnings，绝不抛错。
 *
 * @module dsh-daiyi-aimy-skill/lib/skills
 */

import { readdir, readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

/** 技能文件名（固定）。 */
const SKILL_FILE = 'SKILL.md'

/** 技能名必须是 kebab-case（CONTRACT §3）。 */
const NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

/** 包根目录（本文件位于 <root>/lib/skills/index.js）。 */
const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/** 默认技能目录：<root>/skills。 */
const DEFAULT_SKILLS_DIR = fileURLToPath(new URL('../../skills/', import.meta.url))

/** 去掉目录尾部的一个或多个分隔符（兼容 Windows 反斜杠）。 */
function stripTrailingSep(value) {
  return value.replace(/[\\/]+$/, '')
}

/** 用字符串拼接路径，避免为两个 join 引入 node:path。 */
function joinPath(base, child) {
  return `${stripTrailingSep(base)}/${child}`
}

/** 判断是否为绝对路径（Windows 盘符 / UNC / POSIX）。 */
function isAbsolutePath(value) {
  return /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\')
}

/** 把 options.dirs 里的目录解析成绝对路径：URL 原样转换，相对路径相对包根。 */
function resolveDir(dir) {
  if (dir instanceof URL) return fileURLToPath(dir)
  const value = String(dir)
  return isAbsolutePath(value) ? value : joinPath(PACKAGE_ROOT, value)
}

/** 稳定排序比较函数：不依赖 locale，保证跨机器一致。 */
function compareName(a, b) {
  if (a < b) return -1
  if (a > b) return 1
  return 0
}

/** 去掉值首尾成对的单引号或双引号。 */
function unquote(value) {
  if (value.length >= 2) {
    const first = value[0]
    const last = value[value.length - 1]
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return value.slice(1, -1)
    }
  }
  return value
}

/**
 * 最小 YAML frontmatter 解析器。
 *
 * 只支持 `key: value` 标量：
 * - 空行与 `#` 注释行忽略；
 * - 值首尾成对引号会被去掉；
 * - 不支持嵌套、列表、多行块标量（`>-` / `|`），这类行会被忽略而不是猜测。
 *
 * @param {string} text 完整文件文本
 * @returns {{ data: Record<string, string>, body: string }} 数据与去掉 frontmatter 的正文
 */
export function parseFrontmatter(text) {
  const source = String(text ?? '').replace(/^\uFEFF/, '')
  const lines = source.split(/\r?\n/)

  // 允许文件开头有若干空行，但 frontmatter 必须从第一条非空行开始。
  let start = 0
  while (start < lines.length && lines[start].trim() === '') start += 1
  if (start >= lines.length || lines[start].trim() !== '---') {
    return { data: {}, body: source }
  }

  let end = -1
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i].trim()
    if (line === '---' || line === '...') {
      end = i
      break
    }
  }
  if (end === -1) {
    // 没有闭合分隔符：视为没有 frontmatter，整份文本都是正文。
    return { data: {}, body: source }
  }

  /** @type {Record<string, string>} */
  const data = {}
  for (let i = start + 1; i < end; i += 1) {
    const rawLine = lines[i]
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    // 缩进行属于不支持的嵌套结构或多行块标量续行，直接忽略。
    if (/^\s/.test(rawLine)) continue
    const colon = line.indexOf(':')
    if (colon <= 0) continue // 不是 key: value 的行直接忽略
    const key = line.slice(0, colon).trim()
    if (!key) continue
    const value = line.slice(colon + 1).trim()
    // `>-`、`|` 这类块标量标记无法用标量表达，忽略该 key 而不是存成字面量。
    if (/^[>|][+-]?$/.test(value)) continue
    data[key] = unquote(value)
  }

  return { data, body: lines.slice(end + 1).join('\n') }
}

/**
 * 解析单个 SKILL.md。
 *
 * 缺 name、缺 description、name 非 kebab-case、正文为空都会抛错；
 * `loadSkillPack()` 会捕获这些错误并转成 warnings。
 *
 * @param {string} text 文件文本
 * @param {string} [filename] 仅用于错误信息
 * @returns {{ name: string, description: string, whenToUse: string|undefined, content: string }}
 */
export function parseSkillMarkdown(text, filename = SKILL_FILE) {
  const { data, body } = parseFrontmatter(text)

  const name = (data.name ?? '').trim()
  const description = (data.description ?? '').trim()
  const whenToUse = (data.whenToUse ?? data.when_to_use ?? '').trim() || undefined

  if (!name) throw new Error(`${filename}: frontmatter 缺少 name`)
  if (!NAME_PATTERN.test(name)) {
    throw new Error(`${filename}: name "${name}" 不是 kebab-case（应为 a-z0-9 加单个连字符）`)
  }
  if (!description) throw new Error(`${filename}: frontmatter 缺少 description`)

  const content = body.trim()
  if (!content) throw new Error(`${filename}: 正文为空`)

  return { name, description, whenToUse, content }
}

/**
 * 扫描包根 `skills/*\/SKILL.md`，按目录名排序返回全部有效技能。
 *
 * 单个目录或文件解析失败不会中断整体加载：错误进入 `warnings`（`{ file, message }`）。
 *
 * @param {{ dirs?: Array<string|URL> }} [options] 覆盖扫描目录（缺省为包根 skills/）
 * @returns {Promise<{
 *   skills: Array<{ name: string, description: string, whenToUse: string|undefined, content: string }>,
 *   warnings: Array<{ file: string, message: string }>
 * }>}
 */
export async function loadSkillPack(options = {}) {
  const opts = options && typeof options === 'object' ? options : {}
  const dirs = Array.isArray(opts.dirs) && opts.dirs.length > 0 ? opts.dirs : [DEFAULT_SKILLS_DIR]

  /** @type {Array<{ name: string, description: string, whenToUse: string|undefined, content: string }>} */
  const skills = []
  /** @type {Array<{ file: string, message: string }>} */
  const warnings = []
  const seenNames = new Set()

  for (const configuredDir of dirs) {
    const dir = resolveDir(configuredDir)

    /** @type {import('node:fs').Dirent[]} */
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch (error) {
      warnings.push({ file: dir, message: `无法读取技能目录：${error.message}` })
      continue
    }

    const dirNames = entries
      .filter((entry) => entry.isDirectory() || entry.isSymbolicLink())
      .map((entry) => entry.name)
      .sort(compareName)

    for (const dirName of dirNames) {
      const file = joinPath(joinPath(dir, dirName), SKILL_FILE)

      let text
      try {
        text = await readFile(file, 'utf8')
      } catch (error) {
        warnings.push({ file, message: `无法读取 ${SKILL_FILE}：${error.message}` })
        continue
      }

      let skill
      try {
        skill = parseSkillMarkdown(text, file)
      } catch (error) {
        warnings.push({ file, message: error.message })
        continue
      }

      if (skill.name !== dirName) {
        warnings.push({ file, message: `name "${skill.name}" 与目录名 "${dirName}" 不一致` })
      }
      if (seenNames.has(skill.name)) {
        warnings.push({ file, message: `技能名重复，已跳过：${skill.name}` })
        continue
      }

      seenNames.add(skill.name)
      skills.push(skill)
    }
  }

  // 目录名已排序，再按技能名稳定排序，保证多目录输入也确定。
  skills.sort((a, b) => compareName(a.name, b.name))

  return { skills, warnings }
}

export default { loadSkillPack, parseSkillMarkdown, parseFrontmatter }

#!/usr/bin/env node
/**
 * dsh-daiyi-aimy-skill 插件契约校验器。
 *
 * 纯 Node 内置模块实现，无第三方依赖、无网络访问、不执行插件代码：
 *
 * ```bash
 * node scripts/validate-plugin.mjs              # 人读清单 + 统计，失败 exit 1
 * node scripts/validate-plugin.mjs --json       # 机器可读 JSON（给 CI / 测试用）
 * node scripts/validate-plugin.mjs --root DIR   # 校验指定目录（测试夹具用）
 * node scripts/validate-plugin.mjs --help
 * ```
 *
 * 校验项来自 docs/CONTRACT.md 与 package.json 的 DSH 插件清单约定：
 *   - package.json 存在、JSON 合法、name/version/author/license 齐全，author 精确匹配
 *   - dsh.manifestVersion === 1，dsh.bundle.patch 指向的文件存在
 *   - exports['.'] / exports['./cordis.patch.yml'] 指向文件存在，main 与 exports['.'] 一致
 *   - cordis.patch.yml 可解析（内置最小 YAML 子集解析器），insert 项 name 与包名一致
 *   - lib/index.js 含 `export const name` / `export const inject` / `export function apply`
 *   - 契约声明的 lib 模块与 skills/**\/SKILL.md 存在；SKILL.md frontmatter 合法
 *
 * 输出约定：每条检查一行 `✓` / `✗`，末尾打印统计；存在任意 `✗` 时退出码为 1，
 * 全部通过为 0（命令行用法错误为 2）。
 *
 * @module scripts/validate-plugin
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

/** 作者字段必须精确等于该字符串（契约硬性要求）。 */
export const EXPECTED_AUTHOR = '戴亿 <1703205607@qq.com>'

/** 契约（docs/CONTRACT.md）声明由 lead 提供的 lib 模块。 */
export const CONTRACT_LIB_MODULES = Object.freeze([
  'lib/index.js',
  'lib/config.js',
  'lib/scope.js',
  'lib/http.js',
  'lib/store.js',
  'lib/report.js',
  'lib/tools/index.js',
  'lib/engine/index.js',
  'lib/skills/index.js',
])

/** 技能名 kebab-case 规则（CONTRACT.md §3）。 */
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
/** 技能描述长度上限（CONTRACT.md §3）。 */
const SKILL_DESCRIPTION_MAX = 160

/** 校验报告的收集器。 */
function createReport(rootDir) {
  /** @type {Array<{ok: boolean, label: string, detail?: string}>} */
  const checks = []
  return {
    root: rootDir,
    checks,
    /**
     * 记录一条检查。
     * @param {boolean} ok
     * @param {string} label
     * @param {string} [detail]
     */
    add(ok, label, detail) {
      checks.push(detail === undefined ? { ok: Boolean(ok), label } : { ok: Boolean(ok), label, detail })
      return ok
    },
  }
}

/** 小工具：判断路径存在且是普通文件。 */
function isFile(filePath) {
  try {
    return statSync(filePath).isFile()
  } catch {
    return false
  }
}

/** 小工具：判断路径存在且是目录。 */
function isDirectory(dirPath) {
  try {
    return statSync(dirPath).isDirectory()
  } catch {
    return false
  }
}

/** 读取 UTF-8 文本，失败返回 null。 */
function readText(filePath) {
  try {
    return readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '')
  } catch {
    return null
  }
}

/**
 * 递归列出目录下所有匹配扩展名的文件（相对 rootDir 的 POSIX 风格路径，排序稳定）。
 * @param {string} rootDir
 * @param {string} relativeDir
 * @param {(name: string) => boolean} matcher
 * @returns {string[]}
 */
function walkFiles(rootDir, relativeDir, matcher) {
  const out = []
  const absolute = path.join(rootDir, relativeDir)
  if (!isDirectory(absolute)) return out
  let entries
  try {
    entries = readdirSync(absolute, { withFileTypes: true })
  } catch {
    return out
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  for (const entry of entries) {
    const relativePath = path.posix.join(relativeDir.split(path.sep).join('/'), entry.name)
    if (entry.isDirectory()) out.push(...walkFiles(rootDir, relativePath, matcher))
    else if (entry.isFile() && matcher(entry.name)) out.push(relativePath)
  }
  return out.sort()
}

/**
 * 在字符串中寻找 YAML 映射键值分隔冒号：冒号后必须是空白或行尾（避免误伤 `http://`）。
 * @param {string} text
 * @returns {number} 冒号下标；找不到返回 -1
 */
function findMappingColon(text) {
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] !== ':') continue
    const next = text[index + 1]
    if (next === undefined || next === ' ' || next === '\t') return index
  }
  return -1
}

/** 构造带行号的 YAML 解析错误。 */
function yamlError(lineNumber, message) {
  return new Error(`YAML 第 ${lineNumber} 行：${message}`)
}

/**
 * 最小 YAML 子集解析器：缩进块 + 块序列 + 映射 + 标量。
 *
 * 足够解析 Cordis patch 文件（`- insert:` / `- id: ...` / 嵌套 `config:`），
 * 刻意不支持锚点、多文档、流式映射、多行标量等高级语法——遇到就抛错，
 * 而不是静默给出错误结构。
 *
 * @param {string} text
 * @returns {unknown}
 */
export function parseYamlSubset(text) {
  const rawLines = String(text).replace(/\r\n?/g, '\n').split('\n')
  /** @type {Array<{indent: number, content: string, line: number}>} */
  const lines = []
  for (let index = 0; index < rawLines.length; index += 1) {
    const raw = rawLines[index]
    if (/^[ \t]*$/.test(raw)) continue
    if (/^[ \t]*#/.test(raw)) continue
    if (/^---[ \t]*$/.test(raw)) continue
    if (/^\.\.\.[ \t]*$/.test(raw)) break
    if (raw.includes('\t')) throw yamlError(index + 1, '不支持 tab 缩进，请使用空格')
    const indent = /^ */.exec(raw)[0].length
    const content = raw.slice(indent).replace(/[ \t]+$/, '')
    lines.push({ indent, content, line: index + 1 })
  }

  let position = 0

  /** 解析标量（带引号字符串、布尔、数字、null、行内序列）。 */
  function parseScalar(textValue, lineNumber) {
    const trimmed = textValue.trim()
    if (trimmed === '') return null
    if (/^"(?:[^"\\]|\\.)*"$/.test(trimmed)) {
      return trimmed.slice(1, -1).replace(/\\(["\\/bfnrt])/g, (_, escape) => ({
        '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t',
      })[escape])
    }
    if (/^'(?:[^']|'')*'$/.test(trimmed)) return trimmed.slice(1, -1).replace(/''/g, "'")
    if (/^(true|false)$/i.test(trimmed)) return trimmed.toLowerCase() === 'true'
    if (/^(null|~)$/i.test(trimmed)) return null
    if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed)
    if (/^\[.*\]$/.test(trimmed)) {
      const inner = trimmed.slice(1, -1).trim()
      if (inner === '') return []
      return inner.split(',').map((part) => parseScalar(part, lineNumber))
    }
    if (trimmed.startsWith('{')) throw yamlError(lineNumber, '不支持流式映射 `{...}`，请使用块状写法')
    if (trimmed.startsWith('&') || trimmed.startsWith('*')) throw yamlError(lineNumber, '不支持 YAML 锚点/别名')
    if (trimmed === '|' || trimmed === '>') throw yamlError(lineNumber, '不支持多行标量')
    return trimmed
  }

  function isSequenceLine(line) {
    return line.content === '-' || line.content.startsWith('- ')
  }

  /** 解析任意块，依据首行决定序列还是映射。 */
  function parseBlock(indent) {
    const first = lines[position]
    if (first === undefined) return null
    if (first.indent !== indent) {
      throw yamlError(first.line, `缩进不一致：期望 ${indent} 个空格，实际 ${first.indent} 个`)
    }
    return isSequenceLine(first) ? parseSequence(indent) : parseMapping(indent)
  }

  /** 解析映射块。 */
  function parseMapping(indent) {
    /** @type {Record<string, unknown>} */
    const object = {}
    while (position < lines.length) {
      const line = lines[position]
      if (line.indent !== indent) break
      if (isSequenceLine(line)) break
      const colon = findMappingColon(line.content)
      if (colon < 0) throw yamlError(line.line, `映射项缺少 "key:"：${JSON.stringify(line.content)}`)
      const key = line.content.slice(0, colon).trim()
      if (key === '') throw yamlError(line.line, '映射键不能为空')
      if (Object.hasOwn(object, key)) throw yamlError(line.line, `重复的映射键 "${key}"`)
      position += 1
      const rest = line.content.slice(colon + 1).trim()
      if (rest !== '') {
        object[key] = parseScalar(rest, line.line)
        continue
      }
      const next = lines[position]
      object[key] = next !== undefined && next.indent > indent ? parseBlock(next.indent) : null
    }
    return object
  }

  /** 解析序列块。 */
  function parseSequence(indent) {
    const array = []
    while (position < lines.length) {
      const line = lines[position]
      if (line.indent !== indent || !isSequenceLine(line)) break
      const rest = line.content === '-' ? '' : line.content.slice(2).trim()
      position += 1
      if (rest === '') {
        const next = lines[position]
        array.push(next !== undefined && next.indent > indent ? parseBlock(next.indent) : null)
        continue
      }
      const colon = findMappingColon(rest)
      if (colon < 0) {
        array.push(parseScalar(rest, line.line))
        continue
      }
      // 序列项以映射开头（如 `- id: foo`）：后续键与首键对齐到 indent + 2。
      const itemIndent = indent + 2
      /** @type {Record<string, unknown>} */
      const object = {}
      const key = rest.slice(0, colon).trim()
      if (key === '') throw yamlError(line.line, '映射键不能为空')
      const tail = rest.slice(colon + 1).trim()
      if (tail !== '') {
        object[key] = parseScalar(tail, line.line)
      } else {
        const next = lines[position]
        object[key] = next !== undefined && next.indent > indent ? parseBlock(next.indent) : null
      }
      while (position < lines.length) {
        const nextLine = lines[position]
        if (nextLine.indent !== itemIndent || isSequenceLine(nextLine)) break
        const nextColon = findMappingColon(nextLine.content)
        if (nextColon < 0) break
        const nextKey = nextLine.content.slice(0, nextColon).trim()
        if (nextKey === '') throw yamlError(nextLine.line, '映射键不能为空')
        if (Object.hasOwn(object, nextKey)) throw yamlError(nextLine.line, `重复的映射键 "${nextKey}"`)
        position += 1
        const nextTail = nextLine.content.slice(nextColon + 1).trim()
        if (nextTail !== '') object[nextKey] = parseScalar(nextTail, nextLine.line)
        else {
          const nested = lines[position]
          object[nextKey] = nested !== undefined && nested.indent > itemIndent ? parseBlock(nested.indent) : null
        }
      }
      array.push(object)
    }
    return array
  }

  if (lines.length === 0) return null
  const value = parseBlock(lines[0].indent)
  if (position < lines.length) {
    const leftover = lines[position]
    throw yamlError(leftover.line, `无法解析的剩余内容：${JSON.stringify(leftover.content)}`)
  }
  return value
}

/**
 * 解析 Markdown frontmatter（只支持 `key: value` 标量，符合 CONTRACT.md §3）。
 * @param {string} text
 * @returns {{data: Record<string, unknown>, body: string}}
 */
export function parseFrontmatter(text) {
  const normalized = String(text).replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n')
  const lines = normalized.split('\n')
  if (lines[0]?.trim() !== '---') throw new Error('缺少 frontmatter 起始标记 "---"')
  let closing = -1
  for (let index = 1; index < lines.length; index += 1) {
    if (lines[index].trim() === '---') {
      closing = index
      break
    }
  }
  if (closing < 0) throw new Error('缺少 frontmatter 结束标记 "---"')
  const frontmatterText = lines.slice(1, closing).join('\n')
  const parsed = parseYamlSubset(frontmatterText)
  if (parsed === null) return { data: {}, body: lines.slice(closing + 1).join('\n').replace(/^\n/, '') }
  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('frontmatter 必须是 `key: value` 映射')
  }
  return { data: parsed, body: lines.slice(closing + 1).join('\n').replace(/^\n/, '') }
}

/**
 * 执行全部契约校验。
 * @param {string} [rootDir] 插件根目录，默认当前工作目录
 * @returns {{root: string, ok: boolean, stats: {total: number, passed: number, failed: number}, checks: Array<{ok: boolean, label: string, detail?: string}>}}
 */
export function validatePlugin(rootDir = process.cwd()) {
  const root = path.resolve(rootDir)
  const report = createReport(root)
  /** @type {any} 解析后的 package.json，供后续检查使用 */
  let packageJson = null

  // ---- package.json ------------------------------------------------------
  const packagePath = path.join(root, 'package.json')
  const packageText = readText(packagePath)
  report.add(packageText !== null, 'package.json 存在', packageText === null ? `未找到 ${packagePath}` : undefined)
  if (packageText !== null) {
    let parseError = null
    try {
      packageJson = JSON.parse(packageText)
    } catch (error) {
      parseError = error instanceof Error ? error.message : String(error)
    }
    report.add(parseError === null, 'package.json 是合法 JSON', parseError ?? undefined)
    if (packageJson !== null && typeof packageJson !== 'object') {
      report.add(false, 'package.json 顶层是对象', `实际类型：${Array.isArray(packageJson) ? 'array' : typeof packageJson}`)
      packageJson = null
    }
  }

  if (packageJson) {
    const requiredFields = ['name', 'version', 'author', 'license']
    const missing = requiredFields.filter((field) => typeof packageJson[field] !== 'string' || packageJson[field].trim() === '')
    report.add(missing.length === 0, 'name/version/author/license 齐全', missing.length ? `缺少或为空：${missing.join(', ')}` : undefined)
    report.add(
      packageJson.author === EXPECTED_AUTHOR,
      `author 精确等于 "${EXPECTED_AUTHOR}"`,
      packageJson.author === EXPECTED_AUTHOR ? undefined : `实际：${JSON.stringify(packageJson.author)}`,
    )

    const dsh = packageJson.dsh
    report.add(dsh !== null && typeof dsh === 'object', 'dsh 字段存在且是对象')
    if (dsh && typeof dsh === 'object') {
      report.add(dsh.manifestVersion === 1, 'dsh.manifestVersion === 1', dsh.manifestVersion === 1 ? undefined : `实际：${JSON.stringify(dsh.manifestVersion)}`)

      const bundlePatch = dsh.bundle && typeof dsh.bundle === 'object' ? dsh.bundle.patch : undefined
      report.add(typeof bundlePatch === 'string' && bundlePatch.length > 0, 'dsh.bundle.patch 是非空字符串')
      if (typeof bundlePatch === 'string' && bundlePatch.length > 0) {
        const patchPath = path.resolve(root, bundlePatch)
        report.add(isFile(patchPath), `dsh.bundle.patch 指向的文件存在（${bundlePatch}）`, isFile(patchPath) ? undefined : `未找到 ${patchPath}`)
      }
    }

    const exportsField = packageJson.exports
    const exportsRoot = exportsField && typeof exportsField === 'object' ? exportsField['.'] : undefined
    report.add(typeof exportsRoot === 'string' && exportsRoot.length > 0, "exports['.'] 指向一个字符串路径")
    if (typeof exportsRoot === 'string' && exportsRoot.length > 0) {
      const absolute = path.resolve(root, exportsRoot)
      report.add(isFile(absolute), `exports['.'] 指向的文件存在（${exportsRoot}）`, isFile(absolute) ? undefined : `未找到 ${absolute}`)
    }
    const exportsPatch = exportsField && typeof exportsField === 'object' ? exportsField['./cordis.patch.yml'] : undefined
    report.add(typeof exportsPatch === 'string' && exportsPatch.length > 0, "exports['./cordis.patch.yml'] 指向一个字符串路径")
    if (typeof exportsPatch === 'string' && exportsPatch.length > 0) {
      const absolute = path.resolve(root, exportsPatch)
      report.add(isFile(absolute), `exports['./cordis.patch.yml'] 指向的文件存在（${exportsPatch}）`, isFile(absolute) ? undefined : `未找到 ${absolute}`)
    }
    const normalizePackagePath = (value) => (typeof value === 'string' ? value.replace(/^\.\/+/, '').replace(/\/+/g, '/') : value)
    const mainMatchesExports = typeof packageJson.main === 'string'
      && typeof exportsRoot === 'string'
      && normalizePackagePath(packageJson.main) === normalizePackagePath(exportsRoot)
    report.add(
      mainMatchesExports,
      'main 与 exports[\'.\'] 指向同一文件',
      mainMatchesExports ? undefined : `main=${JSON.stringify(packageJson.main)}，exports['.']=${JSON.stringify(exportsRoot)}`,
    )
  }

  // ---- cordis.patch.yml --------------------------------------------------
  const patchRelative = packageJson && packageJson.dsh && packageJson.dsh.bundle && typeof packageJson.dsh.bundle.patch === 'string'
    ? packageJson.dsh.bundle.patch
    : 'cordis.patch.yml'
  const patchPath = path.resolve(root, patchRelative)
  const patchText = readText(patchPath)
  report.add(patchText !== null, `cordis patch 文件存在（${patchRelative}）`)
  let patchDocument = null
  if (patchText !== null) {
    let patchError = null
    try {
      patchDocument = parseYamlSubset(patchText)
    } catch (error) {
      patchError = error instanceof Error ? error.message : String(error)
    }
    report.add(patchError === null, `cordis.patch.yml 可被解析（${patchRelative}）`, patchError ?? undefined)
  }
  if (patchDocument !== null && patchDocument !== undefined) {
    const insertNames = []
    if (Array.isArray(patchDocument)) {
      for (const entry of patchDocument) {
        if (!entry || typeof entry !== 'object' || !Array.isArray(entry.insert)) continue
        for (const item of entry.insert) {
          if (item && typeof item === 'object' && typeof item.name === 'string') insertNames.push(item.name)
        }
      }
    }
    report.add(insertNames.length > 0, 'cordis patch 存在 insert 项且带 name', insertNames.length ? undefined : '未找到任意 `- insert:` 项或其中的 name')
    if (insertNames.length > 0) {
      const expectedName = packageJson && typeof packageJson.name === 'string' ? packageJson.name : null
      const mismatched = insertNames.filter((name) => name !== expectedName)
      report.add(
        expectedName !== null && mismatched.length === 0,
        'insert 项 name 与 package.json name 一致',
        mismatched.length ? `package name=${JSON.stringify(expectedName)}，不一致的 insert name=${JSON.stringify(mismatched)}` : undefined,
      )
    }
    const hasConfigInsert = Array.isArray(patchDocument)
    report.add(hasConfigInsert, 'cordis patch 顶层是数组（Cordis patch 形状）', hasConfigInsert ? undefined : `实际类型：${typeof patchDocument}`)
  }

  // ---- lib/index.js 导出契约 --------------------------------------------
  const indexPath = path.join(root, 'lib', 'index.js')
  const indexText = readText(indexPath)
  report.add(indexText !== null, 'lib/index.js 存在', indexText === null ? `未找到 ${indexPath}` : undefined)
  if (indexText !== null) {
    report.add(/export\s+const\s+name\s*=/.test(indexText), 'lib/index.js 含 `export const name = ...`')
    report.add(/export\s+const\s+inject\s*=/.test(indexText), 'lib/index.js 含 `export const inject = ...`')
    report.add(/export\s+(?:async\s+)?function\s+apply\s*\(/.test(indexText), 'lib/index.js 含 `export function apply(...)`（允许 async）')
  }

  // ---- 契约声明的 lib 模块 ----------------------------------------------
  for (const relative of CONTRACT_LIB_MODULES) {
    const absolute = path.join(root, relative)
    report.add(isFile(absolute), `契约模块存在：${relative}`, isFile(absolute) ? undefined : `未找到 ${absolute}`)
  }
  const libJsFiles = walkFiles(root, 'lib', (name) => name.endsWith('.js'))
  report.add(libJsFiles.length > 0, 'lib/ 下至少存在一个 .js 文件', libJsFiles.length ? undefined : 'lib/ 目录为空或不存在')

  // ---- skills/**/SKILL.md ------------------------------------------------
  const skillFiles = walkFiles(root, 'skills', (name) => name === 'SKILL.md')
  report.add(skillFiles.length > 0, 'skills/ 下至少存在一个 SKILL.md', skillFiles.length ? undefined : '未找到任意 skills/*/SKILL.md')
  for (const relative of skillFiles) {
    const absolute = path.join(root, relative)
    const dirName = path.basename(path.dirname(relative))
    const text = readText(absolute)
    if (text === null) {
      report.add(false, `${relative}：可读取`)
      continue
    }
    let frontmatter = null
    let frontmatterError = null
    try {
      frontmatter = parseFrontmatter(text)
    } catch (error) {
      frontmatterError = error instanceof Error ? error.message : String(error)
    }
    if (!report.add(frontmatterError === null, `${relative}：frontmatter 可解析`, frontmatterError ?? undefined)) continue
    const data = frontmatter.data
    const name = typeof data.name === 'string' ? data.name : ''
    const description = typeof data.description === 'string' ? data.description : ''
    report.add(name.length > 0, `${relative}：frontmatter 含 name`)
    report.add(description.length > 0, `${relative}：frontmatter 含 description`)
    report.add(KEBAB_CASE.test(name), `${relative}：name 是 kebab-case`, KEBAB_CASE.test(name) ? undefined : `实际：${JSON.stringify(name)}`)
    report.add(name.startsWith('aimy-'), `${relative}：name 以 aimy- 开头`, name.startsWith('aimy-') ? undefined : `实际：${JSON.stringify(name)}`)
    report.add(name === dirName, `${relative}：name 与目录名一致`, name === dirName ? undefined : `name=${JSON.stringify(name)}，目录名=${JSON.stringify(dirName)}`)
    report.add(
      description.length > 0 && description.length <= SKILL_DESCRIPTION_MAX,
      `${relative}：description 长度 1..${SKILL_DESCRIPTION_MAX}`,
      description.length > SKILL_DESCRIPTION_MAX ? `实际长度：${description.length}` : undefined,
    )
  }

  // ---- 统计 --------------------------------------------------------------
  const passed = report.checks.filter((check) => check.ok).length
  const failed = report.checks.length - passed
  return {
    root,
    ok: failed === 0,
    stats: { total: report.checks.length, passed, failed, libJsFiles: libJsFiles.length, skillFiles: skillFiles.length },
    checks: report.checks,
  }
}

/**
 * 打印人读清单并返回退出码。
 * @param {ReturnType<typeof validatePlugin>} result
 * @param {{json?: boolean}} [options]
 * @returns {number} 0 通过，1 存在失败
 */
export function printReport(result, options = {}) {
  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
    return result.ok ? 0 : 1
  }
  const lines = []
  lines.push(`dsh-daiyi-aimy-skill 插件契约校验`)
  lines.push(`根目录: ${result.root}`)
  lines.push('')
  for (const check of result.checks) {
    lines.push(`  ${check.ok ? '✓' : '✗'} ${check.label}`)
    if (!check.ok && check.detail) lines.push(`      ↳ ${check.detail}`)
  }
  lines.push('')
  lines.push(
    `统计: ${result.stats.passed} ✓ / ${result.stats.failed} ✗ (共 ${result.stats.total} 项)` +
      ` · lib/**/*.js ${result.stats.libJsFiles} 个 · SKILL.md ${result.stats.skillFiles} 个`,
  )
  lines.push(result.ok ? '结果: PASS（全部契约检查通过）' : '结果: FAIL（存在 ✗ 项，见上）')
  process.stdout.write(`${lines.join('\n')}\n`)
  return result.ok ? 0 : 1
}

const USAGE = `用法: node scripts/validate-plugin.mjs [--root <目录>] [--json]

  --root <目录>  校验指定插件根目录（默认：当前工作目录）
  --json         输出机器可读 JSON（仍以退出码表示结果）
  --help         显示本帮助

退出码: 0 全部通过 / 1 存在 ✗ 项 / 2 命令行用法错误`

/**
 * CLI 入口。
 * @param {string[]} argv
 * @returns {number} 退出码
 */
export function main(argv) {
  let root = process.cwd()
  let json = false
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--json') {
      json = true
    } else if (argument === '--root') {
      const value = argv[index + 1]
      if (value === undefined) {
        process.stderr.write(`${USAGE}\n\n错误: --root 需要一个目录参数\n`)
        return 2
      }
      root = path.resolve(value)
      index += 1
    } else if (argument === '--help' || argument === '-h') {
      process.stdout.write(`${USAGE}\n`)
      return 0
    } else if (argument.startsWith('--root=')) {
      root = path.resolve(argument.slice('--root='.length))
    } else {
      process.stderr.write(`${USAGE}\n\n错误: 未知参数 ${JSON.stringify(argument)}\n`)
      return 2
    }
  }
  if (!isDirectory(root)) {
    process.stderr.write(`错误: 根目录不存在或不是目录：${root}\n`)
    return 1
  }
  const result = validatePlugin(root)
  return printReport(result, { json })
}

const isDirectRun = process.argv[1] !== undefined
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url

if (isDirectRun) {
  process.exitCode = main(process.argv.slice(2))
}

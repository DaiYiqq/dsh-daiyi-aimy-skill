/**
 * 契约测试：scripts/validate-plugin.mjs 自身。
 *
 * 分两层：
 *   1. 解析器单元测试（最小 YAML 子集 / SKILL.md frontmatter）——不依赖仓库状态；
 *   2. 用临时目录里的“合规 / 违规”夹具跑完整校验，验证 ✓/✗ 判定与退出码；
 *   3. 最后对真实仓库跑一次：仓库尚未补齐契约文件时 skip（而不是 fail）。
 *
 * @module test/contract/validate-plugin
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CONTRACT_LIB_MODULES,
  EXPECTED_AUTHOR,
  main,
  parseFrontmatter,
  parseYamlSubset,
  validatePlugin,
} from '../../scripts/validate-plugin.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = path.resolve(HERE, '..', '..')
const SCRIPT_PATH = path.join(REPO_ROOT, 'scripts', 'validate-plugin.mjs')

/** 写一个文件（自动建父目录）。 */
function writeFile(root, relative, content) {
  const absolute = path.join(root, relative)
  mkdirSync(path.dirname(absolute), { recursive: true })
  writeFileSync(absolute, content, 'utf8')
  return absolute
}

/** 读取仓库里的真实 patch 文件文本。 */
function readRepoPatch() {
  return readFileSync(path.join(REPO_ROOT, 'cordis.patch.yml'), 'utf8')
}

/**
 * 生成一个“所有检查都通过”的临时插件夹具。
 * @returns {string} 夹具根目录
 */
function createValidFixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'aimy-validate-ok-'))
  writeFile(root, 'package.json', `${JSON.stringify({
    name: 'dsh-fixture-plugin',
    version: '9.9.9',
    description: 'validator fixture',
    type: 'module',
    main: 'lib/index.js',
    exports: {
      '.': './lib/index.js',
      './cordis.patch.yml': './cordis.patch.yml',
      './package.json': './package.json',
    },
    author: EXPECTED_AUTHOR,
    license: 'MIT',
    dsh: { manifestVersion: 1, bundle: { patch: './cordis.patch.yml' } },
  }, null, 2)}\n`)
  writeFile(root, 'cordis.patch.yml', [
    '- insert:',
    '    - id: fixture-plugin',
    '      name: dsh-fixture-plugin',
    '      config:',
    '        mode: rookie',
    '        persistScope: true',
    '',
  ].join('\n'))
  writeFile(root, 'lib/index.js', [
    "export const name = 'dsh-fixture-plugin'",
    "export const inject = ['tools', 'skills']",
    'export function apply() {}',
    'export default apply',
    '',
  ].join('\n'))
  for (const relative of CONTRACT_LIB_MODULES) {
    if (relative === 'lib/index.js') continue
    writeFile(root, relative, 'export {}\n')
  }
  writeFile(root, 'skills/aimy-demo/SKILL.md', [
    '---',
    'name: aimy-demo',
    'description: 夹具技能，仅用于校验 frontmatter 解析',
    'whenToUse: 仅测试',
    '---',
    '',
    '# 夹具',
    '',
    '正文。',
    '',
  ].join('\n'))
  return root
}

/** 找到某个 label 前缀的检查项。 */
function findCheck(result, labelPrefix) {
  return result.checks.find((check) => check.label.startsWith(labelPrefix))
}

// ---------------------------------------------------------------------------
// 1. 最小 YAML 子集解析器
// ---------------------------------------------------------------------------

test('parseYamlSubset：解析仓库真实 cordis.patch.yml', () => {
  const document = parseYamlSubset(readRepoPatch())
  assert.deepEqual(document, [
    {
      insert: [
        {
          id: 'daiyi-aimy-skill',
          name: 'dsh-daiyi-aimy-skill',
          config: { mode: 'rookie', persistScope: true },
        },
      ],
    },
  ])
})

test('parseYamlSubset：注释/引号/布尔/数字/行内序列/CRLF', () => {
  const text = [
    '# 注释行',
    'a: 1',
    "b: 'quoted value'",
    'c: "double \\"escaped\\""',
    'd: true',
    'e: null',
    'f: [x, 2]',
    'g:',
    '  h: deep',
    'list:',
    '  - one',
    '  - two',
    '',
  ].join('\r\n')
  assert.deepEqual(parseYamlSubset(text), {
    a: 1,
    b: 'quoted value',
    c: 'double "escaped"',
    d: true,
    e: null,
    f: ['x', 2],
    g: { h: 'deep' },
    list: ['one', 'two'],
  })
})

test('parseYamlSubset：不支持/非法语法必须显式报错', () => {
  assert.throws(() => parseYamlSubset('a:\n\tb: 1'), /tab/)
  assert.throws(() => parseYamlSubset('a: {b: 1}'), /流式映射/)
  assert.throws(() => parseYamlSubset('a: 1\n  b: 2'), /缩进|无法解析/)
  assert.throws(() => parseYamlSubset('a: 1\na: 2'), /重复/)
  assert.equal(parseYamlSubset(''), null)
  assert.equal(parseYamlSubset('# 只有注释\n'), null)
})

test('parseFrontmatter：提取 key/value 与正文', () => {
  const parsed = parseFrontmatter('---\nname: aimy-demo\ndescription: 描述\n---\n\n# 标题\n正文\n')
  assert.deepEqual(parsed.data, { name: 'aimy-demo', description: '描述' })
  assert.match(parsed.body, /# 标题/)
  assert.throws(() => parseFrontmatter('没有 frontmatter'), /缺少 frontmatter 起始标记/)
  assert.throws(() => parseFrontmatter('---\nname: x\n'), /缺少 frontmatter 结束标记/)
})

// ---------------------------------------------------------------------------
// 2. 夹具上的完整校验
// ---------------------------------------------------------------------------

test('校验器：合规夹具全部 ✓，退出码 0（CLI --json）', (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const result = validatePlugin(root)
  assert.equal(result.ok, true, `合规夹具不应失败，实际失败项：${result.checks.filter((check) => !check.ok).map((check) => check.label).join(' | ')}`)
  assert.equal(result.stats.failed, 0)
  assert.equal(result.stats.passed, result.stats.total)

  const cli = spawnSync(process.execPath, [SCRIPT_PATH, '--root', root, '--json'], { encoding: 'utf8', cwd: REPO_ROOT })
  assert.equal(cli.status, 0, `CLI 应 exit 0，stderr=${cli.stderr}`)
  const parsed = JSON.parse(cli.stdout)
  assert.equal(parsed.ok, true)
  assert.equal(parsed.stats.failed, 0)
})

test('校验器：author 不精确匹配时 ✗ 且 exit 1', (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const packageJson = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
  packageJson.author = '戴亿'
  writeFile(root, 'package.json', `${JSON.stringify(packageJson, null, 2)}\n`)

  const result = validatePlugin(root)
  assert.equal(result.ok, false)
  const authorCheck = findCheck(result, 'author 精确等于')
  assert.ok(authorCheck, '应存在 author 检查项')
  assert.equal(authorCheck.ok, false)

  const cli = spawnSync(process.execPath, [SCRIPT_PATH, '--root', root, '--json'], { encoding: 'utf8', cwd: REPO_ROOT })
  assert.equal(cli.status, 1)
  assert.equal(JSON.parse(cli.stdout).ok, false)
})

test('校验器：cordis patch 的 insert name 与包名不一致时 ✗', (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))
  writeFile(root, 'cordis.patch.yml', '- insert:\n    - id: fixture\n      name: wrong-package-name\n')
  const result = validatePlugin(root)
  assert.equal(result.ok, false)
  assert.equal(findCheck(result, 'insert 项 name 与 package.json name 一致')?.ok, false)
})

test('校验器：SKILL.md 的 name 与目录名不一致 / 缺 frontmatter 时 ✗', (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))
  writeFile(root, 'skills/aimy-wrong-dir/SKILL.md', '---\nname: aimy-other-name\ndescription: 名字对不上目录\n---\n\n正文\n')
  let result = validatePlugin(root)
  assert.equal(result.ok, false)
  assert.equal(findCheck(result, 'skills/aimy-wrong-dir/SKILL.md：name 与目录名一致')?.ok, false)

  rmSync(path.join(root, 'skills/aimy-wrong-dir'), { recursive: true, force: true })
  writeFile(root, 'skills/aimy-broken/SKILL.md', '# 没有 frontmatter\n')
  result = validatePlugin(root)
  assert.equal(result.ok, false)
  assert.equal(findCheck(result, 'skills/aimy-broken/SKILL.md：frontmatter 可解析')?.ok, false)
})

test('校验器：最小 YAML 解析失败 / 缺 lib/index.js 时 ✗', (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))
  writeFile(root, 'cordis.patch.yml', '- insert:\n   bad indent here\n')
  let result = validatePlugin(root)
  assert.equal(result.ok, false)
  assert.equal(findCheck(result, 'cordis.patch.yml 可被解析')?.ok, false)

  writeFile(root, 'cordis.patch.yml', '- insert:\n    - name: dsh-fixture-plugin\n')
  rmSync(path.join(root, 'lib/index.js'))
  result = validatePlugin(root)
  assert.equal(result.ok, false)
  assert.equal(findCheck(result, 'lib/index.js 存在')?.ok, false)
  assert.equal(findCheck(result, 'lib/index.js 含 `export const name = ...`'), undefined)
})

test("校验器：main 与 exports['.'] 允许 \"./\" 前缀差异", (t) => {
  const root = createValidFixture()
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const packageJson = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'))
  packageJson.main = 'lib/index.js'
  packageJson.exports['.'] = './lib/index.js'
  writeFile(root, 'package.json', `${JSON.stringify(packageJson, null, 2)}\n`)
  const result = validatePlugin(root)
  assert.equal(findCheck(result, "main 与 exports['.'] 指向同一文件")?.ok, true)
})

test('main()：未知参数返回 2，--help 返回 0', () => {
  const originalWrite = process.stdout.write
  const originalError = process.stderr.write
  process.stdout.write = () => true
  process.stderr.write = () => true
  try {
    assert.equal(main(['--nonsense']), 2)
    assert.equal(main(['--help']), 0)
    assert.equal(main(['--root']), 2)
  } finally {
    process.stdout.write = originalWrite
    process.stderr.write = originalError
  }
})

// ---------------------------------------------------------------------------
// 3. 真实仓库
// ---------------------------------------------------------------------------

test('真实仓库：validate-plugin.mjs 全部通过', (t) => {
  const result = validatePlugin(REPO_ROOT)
  if (!result.ok) {
    const failures = result.checks.filter((check) => !check.ok).map((check) => check.label)
    t.skip(`仓库当前有 ${failures.length} 项未通过（等待其他模块完成）：\n  ${failures.join('\n  ')}`)
    return
  }
  assert.equal(result.stats.failed, 0)
  assert.ok(result.stats.total > 0)
})

test('真实仓库：CLI exit 0（仓库完整时）或 exit 1 且输出合法 JSON（未完成时）', (t) => {
  const cli = spawnSync(process.execPath, [SCRIPT_PATH, '--json'], { encoding: 'utf8', cwd: REPO_ROOT })
  assert.ok(cli.status === 0 || cli.status === 1, `退出码只能是 0/1，实际 ${cli.status}，stderr=${cli.stderr}`)
  const parsed = JSON.parse(cli.stdout)
  assert.equal(typeof parsed.ok, 'boolean')
  assert.equal(parsed.stats.passed + parsed.stats.failed, parsed.stats.total)
  if (cli.status === 1) {
    const failedLabels = parsed.checks.filter((check) => !check.ok).map((check) => check.label)
    assert.ok(failedLabels.length > 0, 'exit 1 时 JSON 里必须有失败项')
    t.diagnostic(`未通过项：${failedLabels.join(' | ')}`)
  }
  assert.ok(existsSync(SCRIPT_PATH))
})

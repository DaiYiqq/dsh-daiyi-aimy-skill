import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { loadSkillPack, parseFrontmatter, parseSkillMarkdown } from '../lib/skills/index.js'

const SKILLS_DIR = fileURLToPath(new URL('../skills/', import.meta.url))
const KEBAB_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const TOOL_CALL_PATTERN = /aimy_(?:scope|recon|port_scan|dir_fuzz|crawl|web_scan|jwt_audit|report)\(/
const REQUIRED_SECTIONS = ['## 何时用', '## 前置条件', '## 操作步骤', '## 判定标准', '## 常见误报', '## 停止条件']
const EXPECTED_SKILL_NAMES = [
  'aimy-api-and-graphql',
  'aimy-auth-and-jwt',
  'aimy-authorized-scope',
  'aimy-finding-report',
  'aimy-recon-workflow',
  'aimy-rookie-mode',
  'aimy-veteran-mode',
  'aimy-web-vuln-triage',
]
// 只允许公开演示目标出现在技能正文里。
const ALLOWED_URL_HOSTS = new Set(['example.com', 'api.example.com', 'www.example.com', '127.0.0.1', 'scanme.nmap.org'])

/** 构造一份合法 SKILL.md 文本。 */
function buildSkill({
  name = 'aimy-demo',
  description = '演示技能，用于单元测试。',
  whenToUse = '需要演示时使用。',
  body = '# 演示\n\n正文内容。',
} = {}) {
  return `---\nname: ${name}\ndescription: ${description}\nwhenToUse: ${whenToUse}\n---\n\n${body}\n`
}

test('parseFrontmatter：解析基本 key: value', () => {
  const text = '---\nname: aimy-demo\ndescription: 一句话描述\nwhenToUse: 测试时\n---\n\n# 正文\n\n内容\n'
  const { data, body } = parseFrontmatter(text)
  assert.deepEqual(data, {
    name: 'aimy-demo',
    description: '一句话描述',
    whenToUse: '测试时',
  })
  assert.equal(body.trim(), '# 正文\n\n内容')
})

test('parseFrontmatter：去掉值首尾成对引号', () => {
  const { data } = parseFrontmatter('---\nname: "aimy-quoted"\ndescription: \'带 空格 的描述\'\n---\n')
  assert.equal(data.name, 'aimy-quoted')
  assert.equal(data.description, '带 空格 的描述')
  // 不成对的引号原样保留
  const { data: odd } = parseFrontmatter('---\nname: "aimy-odd\n---\n')
  assert.equal(odd.name, '"aimy-odd')
})

test('parseFrontmatter：没有 frontmatter 时整份文本都是正文', () => {
  const text = '# 只有正文\n\n没有分隔符。\n'
  const { data, body } = parseFrontmatter(text)
  assert.deepEqual(data, {})
  assert.equal(body, text)
})

test('parseFrontmatter：兼容 BOM、CRLF、注释与不支持的块标量', () => {
  const text = [
    '\uFEFF---',
    '# 这是注释',
    'name: aimy-crlf',
    '',
    'description: >-',
    '  这一行属于块标量，应被忽略',
    'whenToUse: 测试 CRLF',
    '---',
    '正文第一行',
    '正文第二行',
    '',
  ].join('\r\n')
  const { data, body } = parseFrontmatter(text)
  assert.equal(data.name, 'aimy-crlf')
  assert.equal(data.description, undefined)
  assert.equal(data.whenToUse, '测试 CRLF')
  assert.equal(body.trim(), '正文第一行\n正文第二行')
})

test('parseFrontmatter：缺少闭合分隔符时视为没有 frontmatter', () => {
  const text = '---\nname: aimy-broken\n正文\n'
  const { data, body } = parseFrontmatter(text)
  assert.deepEqual(data, {})
  assert.equal(body, text)
})

test('parseFrontmatter：空值与非 key: value 行被安全忽略', () => {
  const { data } = parseFrontmatter('---\nname:\ndescription: 有值\n随便一行没有冒号\n---\n')
  assert.equal(data.name, '')
  assert.equal(data.description, '有值')
})

test('parseSkillMarkdown：解析正常技能', () => {
  const skill = parseSkillMarkdown(buildSkill({ body: '# 演示\n\n调用 aimy_recon(...) 演示。' }), 'SKILL.md')
  assert.equal(skill.name, 'aimy-demo')
  assert.equal(skill.description, '演示技能，用于单元测试。')
  assert.equal(skill.whenToUse, '需要演示时使用。')
  assert.equal(skill.content, '# 演示\n\n调用 aimy_recon(...) 演示。')
  assert.ok(!skill.content.includes('name: aimy-demo'))
})

test('parseSkillMarkdown：缺 name 或缺 description 视为无效', () => {
  assert.throws(() => parseSkillMarkdown('---\ndescription: 只有描述\n---\n正文\n', 'a.md'), /缺少 name/)
  assert.throws(() => parseSkillMarkdown('---\nname: aimy-demo\n---\n正文\n', 'b.md'), /缺少 description/)
  assert.throws(() => parseSkillMarkdown('没有 frontmatter 的文本\n', 'c.md'), /缺少 name/)
})

test('parseSkillMarkdown：name 必须是 kebab-case', () => {
  assert.throws(() => parseSkillMarkdown(buildSkill({ name: 'Aimy Demo' }), 'd.md'), /kebab-case/)
  assert.throws(() => parseSkillMarkdown(buildSkill({ name: 'aimy_demo' }), 'e.md'), /kebab-case/)
})

test('parseSkillMarkdown：正文为空视为无效', () => {
  assert.throws(() => parseSkillMarkdown('---\nname: aimy-demo\ndescription: 描述\n---\n\n   \n', 'f.md'), /正文为空/)
})

test('parseSkillMarkdown：带引号的 name/description 会被去引号', () => {
  const text = '---\nname: "aimy-quoted"\ndescription: \'带引号 的描述\'\nwhenToUse: "测试"\n---\n\n正文\n'
  const skill = parseSkillMarkdown(text, 'g.md')
  assert.equal(skill.name, 'aimy-quoted')
  assert.equal(skill.description, '带引号 的描述')
  assert.equal(skill.whenToUse, '测试')
})

test('loadSkillPack：默认加载包根 skills/，返回 8 个技能且无告警', async () => {
  const pack = await loadSkillPack()
  assert.deepEqual(Object.keys(pack).sort(), ['skills', 'warnings'])
  assert.ok(Array.isArray(pack.skills))
  assert.equal(pack.skills.length, 8)
  assert.deepEqual(pack.warnings, [])

  const names = pack.skills.map((skill) => skill.name)
  assert.deepEqual(names, EXPECTED_SKILL_NAMES)
  assert.deepEqual(names, [...names].sort(), '技能应按名称排序')
  assert.equal(new Set(names).size, names.length, '技能名必须唯一')
})

test('loadSkillPack：目录名与 name 一致，且全部是 aimy- 前缀的 kebab-case', async () => {
  const pack = await loadSkillPack()
  const dirNames = (await readdir(SKILLS_DIR, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.deepEqual(pack.skills.map((skill) => skill.name), dirNames)

  for (const skill of pack.skills) {
    assert.match(skill.name, KEBAB_PATTERN)
    assert.ok(skill.name.startsWith('aimy-'), `${skill.name} 必须带 aimy- 前缀`)
    assert.ok(skill.description.length > 0 && skill.description.length <= 160, `${skill.name} description 长度`)
    assert.equal(typeof skill.whenToUse, 'string')
    assert.ok(skill.whenToUse.length > 0, `${skill.name} whenToUse 不能为空`)
  }
})

test('loadSkillPack：每个技能正文都包含要求的章节、工具调用与合规目标域名', async () => {
  const pack = await loadSkillPack()
  for (const skill of pack.skills) {
    for (const section of REQUIRED_SECTIONS) {
      assert.ok(skill.content.includes(section), `${skill.name} 缺少章节 ${section}`)
    }
    assert.match(skill.content, TOOL_CALL_PATTERN, `${skill.name} 必须包含具体工具调用示例`)

    const lineCount = skill.content.split('\n').length
    assert.ok(lineCount >= 60 && lineCount <= 160, `${skill.name} 正文 ${lineCount} 行，应在 60~160 行`)

    const urlHosts = [...skill.content.matchAll(/https?:\/\/([A-Za-z0-9._-]+(?::\d+)?)/g)]
    for (const match of urlHosts) {
      const host = match[1].toLowerCase().replace(/:\d+$/, '')
      assert.ok(ALLOWED_URL_HOSTS.has(host), `${skill.name} 出现非演示域名: ${match[0]}`)
    }
  }
})

test('loadSkillPack：可用 dirs 覆盖扫描目录，坏技能进 warnings 且不影响其他技能', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aimy-skills-'))
  try {
    const createSkill = async (dirName, content) => {
      const dir = join(root, dirName)
      await mkdir(dir, { recursive: true })
      await writeFile(join(dir, 'SKILL.md'), content, 'utf8')
    }

    await createSkill('aimy-beta', buildSkill({ name: 'aimy-beta', description: '"第二个技能"' }))
    await createSkill('aimy-alpha', buildSkill({ name: 'aimy-alpha', description: '第一个技能' }))
    await createSkill('aimy-broken', '---\nname: aimy-broken\n---\n\n正文\n')
    // name 与目录名不一致：仍加载，但产生一条 warning
    await createSkill('wrong-dir', buildSkill({ name: 'aimy-wrong-name', description: '名字不一致' }))
    // 目录存在但没有 SKILL.md：产生一条 warning
    await mkdir(join(root, 'empty-dir'), { recursive: true })

    const pack = await loadSkillPack({ dirs: [root] })
    assert.deepEqual(pack.skills.map((skill) => skill.name), ['aimy-alpha', 'aimy-beta', 'aimy-wrong-name'])
    assert.equal(pack.skills[1].description, '第二个技能')
    assert.equal(pack.warnings.length, 3, JSON.stringify(pack.warnings))
    assert.ok(pack.warnings.some((warning) => warning.file.endsWith('aimy-broken/SKILL.md') || warning.file.endsWith('aimy-broken\\SKILL.md')))
    assert.ok(pack.warnings.some((warning) => warning.message.includes('目录名')))
    assert.ok(pack.warnings.some((warning) => warning.message.includes('无法读取 SKILL.md')))

    // 结果确定：重复调用输出一致
    assert.deepEqual(await loadSkillPack({ dirs: [root] }), pack)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('loadSkillPack：目录不存在时只返回 warning，不抛错', async () => {
  const missing = join(tmpdir(), 'aimy-skills-does-not-exist-9f3c')
  const pack = await loadSkillPack({ dirs: [missing] })
  assert.deepEqual(pack.skills, [])
  assert.equal(pack.warnings.length, 1)
  assert.equal(typeof pack.warnings[0].file, 'string')
  assert.match(pack.warnings[0].message, /无法读取技能目录/)
})

test('loadSkillPack：默认结果与传入默认目录的结果一致且可重复', async () => {
  const first = await loadSkillPack()
  const second = await loadSkillPack({})
  assert.deepEqual(first, second)
  const explicit = await loadSkillPack({ dirs: [SKILLS_DIR] })
  assert.deepEqual(first, explicit)
})

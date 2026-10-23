/**
 * 语法检查：对仓库内所有 ESM 源文件跑 `node --check`。
 *
 * CI 里等价于 `node --check <file>` 的批量版本；`npm run verify` 会先跑它，
 * 保证任何一个 lib/tool/engine 文件都不会带着语法错误进主干。
 *
 * 用法：node scripts/check-syntax.mjs [目录...]
 * 退出码：0 全部通过；1 有文件失败。
 *
 * @module dsh-daiyi-aimy-skill/scripts/check-syntax
 */

import { spawnSync } from 'node:child_process'
import { readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_DIRS = ['lib', 'skills', 'test', 'scripts']
const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', 'coverage'])

/**
 * 递归收集 .js 文件。
 * @param {string} dir
 * @param {string[]} out
 * @returns {string[]}
 */
function collect(dir, out = []) {
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue
      collect(path.join(dir, entry.name), out)
      continue
    }
    if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.mjs'))) {
      out.push(path.join(dir, entry.name))
    }
  }
  return out
}

const targets = process.argv.slice(2)
const roots = targets.length > 0 ? targets.map((target) => path.resolve(target)) : DEFAULT_DIRS.map((dir) => path.join(REPO_ROOT, dir))

/** @type {string[]} */
const files = []
for (const root of roots) {
  try {
    if (statSync(root).isFile()) files.push(root)
    else collect(root, files)
  } catch {
    // 目录不存在时跳过（例如只有部分子集被拉取）
  }
}

files.sort()
let failed = 0
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' })
  if (result.status === 0) continue
  failed += 1
  const relative = path.relative(REPO_ROOT, file).replaceAll('\\', '/')
  console.error(`✗ ${relative}`)
  const detail = `${result.stderr ?? ''}${result.stdout ?? ''}`.trim()
  if (detail.length > 0) console.error(detail.split('\n').slice(0, 6).map((line) => `    ${line}`).join('\n'))
}

console.log(`语法检查：${files.length - failed} ✓ / ${failed} ✗（共 ${files.length} 个文件）`)
process.exit(failed === 0 ? 0 : 1)

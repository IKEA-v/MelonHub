import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const documents = ['数据库设计', '详细设计', 'API']

function inline(text) {
  return text
    .replace(/!\[([^\]]*)\]\(([^)]+)\)/g, 'image::$2[$1]')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, target) => {
      const converted = target.startsWith('http') || target.startsWith('#') ? target : target.replace(/\.md(?=($|#))/, '.adoc')
      return `link:${converted}[${label}]`
    })
    .replace(/\*\*([^*]+)\*\*/g, '*$1*')
}

function splitRow(line) {
  const value = line.trim().replace(/^\|/, '').replace(/\|$/, '')
  const cells = []
  let current = ''
  let escaped = false
  for (const char of value) {
    if (escaped) { current += char; escaped = false; continue }
    if (char === '\\') { current += char; escaped = true; continue }
    if (char === '|') { cells.push(current.trim()); current = ''; continue }
    current += char
  }
  cells.push(current.trim())
  return cells
}

function convert(markdown) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n')
  const out = []
  let index = 0
  let firstHeading = true
  while (index < lines.length) {
    const line = lines[index]
    const fence = line.match(/^```([^`]*)$/)
    if (fence) {
      const language = fence[1].trim() || 'text'
      out.push(`[source,${language}]`, '----')
      index++
      while (index < lines.length && !lines[index].startsWith('```')) out.push(lines[index++])
      out.push('----')
      index++
      continue
    }
    const heading = line.match(/^(#{1,6})\s+(.+)$/)
    if (heading) {
      out.push(`${'='.repeat(heading[1].length)} ${inline(heading[2])}`)
      if (firstHeading) out.push('', ':toc: left', ':toclevels: 4', ':sectnums:', ':source-highlighter: highlight.js')
      firstHeading = false
      index++
      continue
    }
    if (/^\|.*\|\s*$/.test(line) && index + 1 < lines.length && /^\|?\s*:?-{3,}/.test(lines[index + 1])) {
      const rows = [splitRow(line)]
      index += 2
      while (index < lines.length && /^\|.*\|\s*$/.test(lines[index])) rows.push(splitRow(lines[index++]))
      const columns = Math.max(...rows.map(row => row.length))
      out.push(`[%header,cols="${Array(columns).fill('1').join(',')}"]`, '|===')
      for (const row of rows) {
        for (let cell = 0; cell < columns; cell++) out.push(`|${inline(row[cell] ?? '')}`)
        out.push('')
      }
      out.push('|===')
      continue
    }
    if (/^\d+\.\s+/.test(line)) {
      out.push(inline(line.replace(/^\d+\.\s+/, '. ')))
      index++
      continue
    }
    if (/^>\s?/.test(line)) {
      const quote = []
      while (index < lines.length && /^>\s?/.test(lines[index])) quote.push(inline(lines[index++].replace(/^>\s?/, '')))
      out.push('[quote]', '____', ...quote, '____')
      continue
    }
    if (/^---+$/.test(line.trim())) {
      out.push("'''")
      index++
      continue
    }
    out.push(inline(line))
    index++
  }
  return out.join('\n').replace(/\n{4,}/g, '\n\n\n').replace(/\n+$/, '') + '\n'
}

for (const name of documents) {
  const source = path.join(root, 'docs', `${name}.md`)
  const target = path.join(root, 'docs', `${name}.adoc`)
  fs.writeFileSync(target, convert(fs.readFileSync(source, 'utf8')), 'utf8')
  console.log(`Generated ${path.relative(root, target)}`)
}

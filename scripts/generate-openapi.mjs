import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const controllerDir = path.join(root, 'backend/src/main/java/com/melonhub/rbac/controller')
const controllerFiles = fs.readdirSync(controllerDir).filter(name => name.endsWith('Controller.java')).sort()
const verbs = { Get: 'get', Post: 'post', Put: 'put', Delete: 'delete', Patch: 'patch' }
const tags = {
  AuthController: ['公共与管理员认证', '健康检查、登录、会话、密码和 MFA'],
  BusinessController: ['业务软件 API', '使用 API Key 调用的角色、权限、申请和在线校验接口'],
  AdminController: ['控制台配置', '部门、用户、软件、角色、权限、分配、诊断和审计'],
  GovernanceController: ['授权治理', '审批、复核、Webhook、清单、报表、搜索和系统状态'],
  AccountController: ['管理员账号', '超级管理员维护控制台账号'],
}

function balanced(text, start, open = '(', close = ')') {
  let depth = 0
  for (let i = start; i < text.length; i++) {
    if (text[i] === open) depth++
    if (text[i] === close && --depth === 0) return i
  }
  return -1
}

function splitTopLevel(value) {
  const result = []
  let current = ''
  let depth = 0
  for (const char of value) {
    if ('<(['.includes(char)) depth++
    if ('>)]'.includes(char)) depth--
    if (char === ',' && depth === 0) { result.push(current.trim()); current = ''; continue }
    current += char
  }
  if (current.trim()) result.push(current.trim())
  return result
}

function schemaForType(type) {
  const clean = type.replace(/\?$/, '')
  const list = clean.match(/(?:List|Collection|Set)<(.+)>/)
  if (list) return { type: 'array', items: schemaForType(list[1]) }
  if (clean.startsWith('Map<') || clean === 'Object') return { type: 'object', additionalProperties: true }
  if (['long', 'Long', 'int', 'Integer'].includes(clean)) return { type: 'integer', format: clean.toLowerCase().includes('long') ? 'int64' : 'int32' }
  if (['boolean', 'Boolean'].includes(clean)) return { type: 'boolean' }
  if (clean.includes('OffsetDateTime') || clean.includes('Instant')) return { type: 'string', format: 'date-time' }
  if (clean.includes('LocalDate')) return { type: 'string', format: 'date' }
  if (clean === 'String') return { type: 'string' }
  return { $ref: `#/components/schemas/${clean.replace(/^Requests\./, '')}` }
}

function requestSchemas() {
  const source = fs.readFileSync(path.join(root, 'backend/src/main/java/com/melonhub/rbac/dto/Requests.java'), 'utf8')
  const schemas = {}
  const record = /public record\s+(\w+)\s*\(/g
  let match
  while ((match = record.exec(source))) {
    const end = balanced(source, source.indexOf('(', match.index))
    if (end < 0) throw new Error(`Unclosed record ${match[1]}`)
    const properties = {}
    const required = []
    for (const raw of splitTopLevel(source.slice(source.indexOf('(', match.index) + 1, end))) {
      const notNull = /@(NotNull|NotBlank|NotEmpty)/.test(raw)
      const clean = raw.replace(/@[\w.]+(?:\([^)]*\))?\s*/g, '').trim()
      const field = clean.match(/(.+)\s+(\w+)$/)
      if (!field) continue
      properties[field[2]] = schemaForType(field[1].trim())
      if (notNull || ['long', 'int', 'boolean'].includes(field[1].trim())) required.push(field[2])
    }
    schemas[match[1]] = { type: 'object', properties, ...(required.length ? { required } : {}) }
  }
  schemas.Error = { type: 'object', properties: { code: { type: 'string' }, message: { type: 'string' }, requestId: { type: 'string' } } }
  return schemas
}

function mappingPath(argumentsText = '') {
  return argumentsText.match(/"([^"]*)"/)?.[1] ?? ''
}

function normalizePath(value) {
  const joined = '/' + value.split('/').filter(Boolean).join('/')
  return joined || '/'
}

function parameterName(raw, annotation) {
  const explicit = raw.match(new RegExp(`@${annotation}\\(\\s*"([^"]+)"`))?.[1]
  const cleaned = raw.replace(/@[\w.]+(?:\([^)]*\))?\s*/g, '').trim()
  return explicit ?? cleaned.match(/(\w+)$/)?.[1]
}

function parameterType(raw) {
  const cleaned = raw.replace(/@[\w.]+(?:\([^)]*\))?\s*/g, '').trim()
  return cleaned.match(/^(.+)\s+\w+$/)?.[1]?.trim() ?? 'String'
}

function title(value) {
  return value.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/^./, letter => letter.toUpperCase())
}

const openapi = {
  openapi: '3.0.3',
  info: {
    title: 'MelonHub RBAC0 API',
    version: '1.0.0',
    description: '由当前 Spring Controller 和 Requests DTO 生成，用于 Apifox 等接口管理平台。业务 API 使用 X-API-Key；管理 API 使用 Bearer 会话。服务器正式 API 仅回环开放，示例地址为本机 SSH 代理。',
  },
  servers: [{ url: 'http://127.0.0.1:8080', description: '本机 SSH 代理或本机调试入口' }],
  tags: Object.values(tags).map(([name, description]) => ({ name, description })),
  paths: {},
  components: {
    securitySchemes: {
      AdminBearer: { type: 'http', scheme: 'bearer', bearerFormat: 'opaque session token' },
      ApplicationApiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      ContextToken: { type: 'apiKey', in: 'header', name: 'X-Context-Token' },
    },
    schemas: requestSchemas(),
  },
}

const operationIds = new Set()
for (const file of controllerFiles) {
  const className = file.replace('.java', '')
  const source = fs.readFileSync(path.join(controllerDir, file), 'utf8')
  const classIndex = source.indexOf(`class ${className}`)
  const base = mappingPath(source.slice(0, classIndex).match(/@RequestMapping\(([^)]*)\)/)?.[1])
  const pattern = /@(Get|Post|Put|Delete|Patch)Mapping(?:\(([^)]*)\))?/g
  let mapping
  while ((mapping = pattern.exec(source))) {
    const signatureStart = pattern.lastIndex
    const brace = source.indexOf('{', signatureStart)
    if (brace < 0) continue
    const signature = source.slice(signatureStart, brace).replace(/\s+/g, ' ').trim()
    const method = signature.match(/(?:[\w<>?,.\[\]]+\s+)+(\w+)\s*\((.*)\)$/)
    if (!method) continue
    const verb = verbs[mapping[1]]
    const endpoint = normalizePath(base + mappingPath(mapping[2]))
    const operationIdBase = className.replace('Controller', '') + '_' + method[1]
    let operationId = operationIdBase
    let suffix = 2
    while (operationIds.has(operationId)) operationId = `${operationIdBase}_${suffix++}`
    operationIds.add(operationId)
    const parameters = []
    let requestBody
    for (const raw of splitTopLevel(method[2])) {
      if (raw.includes('@PathVariable')) {
        const name = parameterName(raw, 'PathVariable')
        parameters.push({ name, in: 'path', required: true, schema: schemaForType(parameterType(raw)) })
      } else if (raw.includes('@RequestParam')) {
        const name = parameterName(raw, 'RequestParam')
        const defaultValue = raw.match(/defaultValue\s*=\s*"([^"]+)"/)?.[1]
        const required = !/required\s*=\s*false/.test(raw) && defaultValue === undefined
        const schema = schemaForType(parameterType(raw))
        if (defaultValue !== undefined) schema.default = /^\d+$/.test(defaultValue) ? Number(defaultValue) : defaultValue
        parameters.push({ name, in: 'query', required, schema })
      } else if (raw.includes('@RequestHeader')) {
        const name = parameterName(raw, 'RequestHeader')
        parameters.push({ name, in: 'header', required: true, schema: schemaForType(parameterType(raw)) })
      } else if (raw.includes('@RequestBody')) {
        const schema = schemaForType(parameterType(raw))
        requestBody = { required: true, content: { 'application/json': { schema } } }
      }
    }
    const isPublic = endpoint === '/api/health' || endpoint === '/api/auth/login'
    const security = isPublic ? [] : endpoint.startsWith('/api/v1/')
      ? [{ ApplicationApiKey: [], ...(endpoint.includes('/contexts/') && endpoint !== '/api/v1/contexts' ? { ContextToken: [] } : {}) }]
      : [{ AdminBearer: [] }]
    openapi.paths[endpoint] ??= {}
    if (openapi.paths[endpoint][verb]) throw new Error(`Duplicate ${verb.toUpperCase()} ${endpoint}`)
    openapi.paths[endpoint][verb] = {
      tags: [tags[className][0]],
      summary: `${title(method[1])} - ${verb.toUpperCase()} ${endpoint}`,
      operationId,
      security,
      ...(parameters.length ? { parameters } : {}),
      ...(requestBody ? { requestBody } : {}),
      responses: {
        '200': { description: '成功', content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
        '400': { description: '参数或路径错误', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        '401': { description: '未认证或凭据失效', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        '403': { description: '无权访问', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        '409': { description: '状态冲突或存在依赖', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
      },
    }
  }
}

const target = path.join(root, 'docs/openapi.json')
fs.writeFileSync(target, JSON.stringify(openapi, null, 2) + '\n', 'utf8')
const operationCount = Object.values(openapi.paths).reduce((sum, item) => sum + Object.keys(item).length, 0)
console.log(`Generated ${path.relative(root, target)} with ${Object.keys(openapi.paths).length} paths and ${operationCount} operations`)

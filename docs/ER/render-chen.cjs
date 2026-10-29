// 陈氏概念模型：只读取结构快照，不连接数据库、不读取运行配置。
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const dependency = createRequire(path.resolve(__dirname, '../../.local/er-tools/package.json'));
const { instance } = dependency('@viz-js/viz');
const { Resvg } = dependency('@resvg/resvg-js');
const schema = JSON.parse(fs.readFileSync(path.join(__dirname, 'schema.json'), 'utf8'));
const output = path.join(__dirname, '陈氏');
// WASM Graphviz 使用内置 Arial 度量；输出交由系统微软雅黑绘制中文。
const font = 'Arial';
const diagrams = [];

// 坐标单位为英寸；固定排版让联系、属性及基数在重建时保持可读。
function diagram(name, title) {
  const d = { name, title, nodes: [], edges: [], represented: new Set() };
  diagrams.push(d);
  return d;
}
function entity(d, table, title, x, y) {
  d.nodes.push({ id: table, table, title, x, y, type: 'entity' });
  d.represented.add(table);
  return table;
}
function attribute(d, owner, table, column, title, x, y) {
  if (!schema.columns.some(c => c.TABLE_NAME === table && c.COLUMN_NAME === column)) {
    throw Error(`属性不存在：${table}.${column}`);
  }
  const key = schema.keys.some(k => k.TABLE_NAME === table && k.COLUMN_NAME === column && k.CONSTRAINT_NAME === 'PRIMARY');
  const id = `${owner}__${column}`;
  d.nodes.push({ id, title, column, key, x, y, type: 'attribute' });
  d.edges.push({ from: owner, to: id });
}
function attributes(d, owner, table, values) {
  values.forEach(([column, title, x, y]) => attribute(d, owner, table, column, title, x, y));
}
function relation(d, id, title, left, right, leftMax, rightMax, x, y, bridge) {
  d.nodes.push({ id, title, x, y, type: 'relation' });
  d.edges.push({ from: id, to: left, max: leftMax });
  d.edges.push({ from: id, to: right, max: rightMax });
  if (bridge) {
    const parents = schema.foreignKeys.filter(k => k.TABLE_NAME === bridge).map(k => k.REFERENCED_TABLE_NAME);
    if (!parents.includes(left) || !parents.includes(right)) throw Error(`联系映射不匹配：${bridge}`);
    d.represented.add(bridge);
  } else {
    const fk = schema.foreignKeys.find(k =>
      (k.TABLE_NAME === left && k.REFERENCED_TABLE_NAME === right) ||
      (k.TABLE_NAME === right && k.REFERENCED_TABLE_NAME === left));
    if (!fk) throw Error(`联系缺少结构依据：${left} / ${right}`);
    const columns = schema.keys.filter(k => k.TABLE_NAME === fk.TABLE_NAME && k.CONSTRAINT_NAME === fk.CONSTRAINT_NAME);
    const mandatory = columns.every(k => schema.columns.find(c => c.TABLE_NAME === k.TABLE_NAME && c.COLUMN_NAME === k.COLUMN_NAME).IS_NULLABLE === 'NO');
    if (mandatory) d.edges.find(e => e.from === id && e.to === fk.TABLE_NAME).total = true;
  }
  return id;
}
function top(d, table, idTitle, x, y, extras = [['name', '名称'], ['code', '编码']]) {
  const entries = [['id', idTitle], ...extras];
  entries.forEach(([column, title], i) => attribute(d, table, table, column, title, x + (i - (entries.length - 1) / 2) * 1.95, y));
}

{
  const d = diagram('01-核心授权', '01  组织与软件授权');
  entity(d, 'departments', '部门', 0, 3);
  entity(d, 'users', '业务用户', 6, 3);
  entity(d, 'roles', '软件角色', 12, 3);
  entity(d, 'permissions', '软件权限', 18, 3);
  entity(d, 'applications', '业务软件', 15, -3);
  top(d, 'departments', '部门编号', 0, 5.4);
  top(d, 'users', '用户编号', 6, 5.4, [['name', '姓名'], ['external_id', '外部用户标识']]);
  top(d, 'roles', '角色编号', 12, 5.4);
  top(d, 'permissions', '权限编号', 18, 5.4);
  top(d, 'applications', '软件编号', 15, -5.4);
  relation(d, 'member', '加入', 'departments', 'users', 'M', 'N', 3, 3, 'memberships');
  relation(d, 'grant', '分配', 'users', 'roles', 'M', 'N', 9, 3, 'user_roles');
  attributes(d, 'grant', 'user_roles', [['grant_id', '本次授予标识', 7.6, 0.4], ['expires_at', '分配到期时间', 10, 0.4]]);
  relation(d, 'authorize', '授予', 'roles', 'permissions', 'M', 'N', 15, 3, 'role_permissions');
  relation(d, 'own_role', '拥有角色', 'applications', 'roles', '1', 'N', 12, -0.4);
  relation(d, 'own_permission', '定义权限', 'applications', 'permissions', '1', 'N', 18, -0.4);
}
{
  const d = diagram('02-权限上下文', '02  权限上下文与激活角色');
  entity(d, 'users', '业务用户', 0, 3);
  entity(d, 'permission_contexts', '权限上下文', 6, 3);
  entity(d, 'roles', '软件角色', 12, 3);
  entity(d, 'applications', '业务软件', 6, -3);
  top(d, 'users', '用户编号', 0, 5.5, [['external_id', '外部用户标识']]);
  top(d, 'permission_contexts', '上下文标识（哈希）', 6, 5.5, [['expires_at', '到期时间']]);
  top(d, 'roles', '角色编号', 12, 5.5, [['code', '角色编码']]);
  top(d, 'applications', '软件编号', 6, -5.3, [['code', '软件编码']]);
  relation(d, 'create_context', '持有', 'users', 'permission_contexts', '1', 'N', 3, 3);
  relation(d, 'activate', '激活', 'permission_contexts', 'roles', 'M', 'N', 9, 3, 'context_roles');
  relation(d, 'scope_context', '限定软件', 'applications', 'permission_contexts', '1', 'N', 6, 0);
  relation(d, 'own_role', '拥有角色', 'applications', 'roles', '1', 'N', 12, -3);
}
{
  const d = diagram('03-角色申请', '03  角色申请与审批记录');
  entity(d, 'access_requests', '角色申请', 0, 0);
  entity(d, 'users', '业务用户', -6, 0);
  entity(d, 'roles', '软件角色', 6, 0);
  entity(d, 'applications', '业务软件', 0, 5);
  entity(d, 'departments', '部门', 0, -5);
  top(d, 'applications', '软件编号', 0, 7.3, [['name', '软件名称']]);
  top(d, 'departments', '部门编号', 0, -7.3, [['name', '部门名称']]);
  attributes(d, 'users', 'users', [['id', '用户编号', -8.5, 1.4], ['name', '姓名', -8.5, -1.4]]);
  attributes(d, 'roles', 'roles', [['id', '角色编号', 8.5, 1.4], ['code', '角色编码', 8.5, -1.4]]);
  attributes(d, 'access_requests', 'access_requests', [
    ['id', '申请编号', -3, 2.3], ['status', '审批状态', 3, 2.3],
    ['duration_days', '申请天数', -3, -2.3], ['grant_expires_at', '批准后到期时间', 3, -2.3],
  ]);
  relation(d, 'requester', '提出', 'users', 'access_requests', '1', 'N', -3, 0);
  relation(d, 'requested_role', '申请目标', 'roles', 'access_requests', '1', 'N', 3, 0);
  relation(d, 'request_app', '归属', 'applications', 'access_requests', '1', 'N', 0, 2.5);
  relation(d, 'request_origin', '记录来源', 'departments', 'access_requests', '1', 'N', 0, -2.5);
}
{
  const d = diagram('04-权限复核', '04  权限复核与历史条目');
  entity(d, 'applications', '业务软件', -6, 3);
  entity(d, 'departments', '部门', -6, -3);
  entity(d, 'access_reviews', '权限复核', 0, 0);
  entity(d, 'access_review_items', '复核条目', 6, 0);
  entity(d, 'users', '业务用户', 12, 3);
  entity(d, 'roles', '软件角色', 12, -3);
  top(d, 'applications', '软件编号', -6, 5.4, [['name', '软件名称']]);
  top(d, 'departments', '部门编号', -6, -5.4, [['name', '部门名称']]);
  top(d, 'users', '用户编号', 12, 5.4, [['name', '姓名']]);
  top(d, 'roles', '角色编号', 12, -5.4, [['code', '角色编码']]);
  attributes(d, 'access_reviews', 'access_reviews', [['id', '复核编号', -1, 4], ['name', '复核名称', 1.2, 4], ['status', '复核状态', 0, -3.5]]);
  attributes(d, 'access_review_items', 'access_review_items', [['id', '条目编号', 5, 4], ['decision', '复核决定', 7.2, 4], ['grant_id', '授予标识快照', 6, -3.5]]);
  relation(d, 'review_app', '归属', 'applications', 'access_reviews', '1', 'N', -3, 3);
  relation(d, 'review_filter', '筛选范围', 'departments', 'access_reviews', '1', 'N', -3, -3);
  relation(d, 'review_items', '包含', 'access_reviews', 'access_review_items', '1', 'N', 3, 0);
  relation(d, 'review_user', '被复核用户', 'users', 'access_review_items', '1', 'N', 9, 3);
  relation(d, 'review_role', '被复核角色', 'roles', 'access_review_items', '1', 'N', 9, -3);
}
{
  const d = diagram('05-管理员密钥', '05  管理员、会话与软件密钥');
  entity(d, 'admin_accounts', '控制台管理员', 0, 3);
  entity(d, 'applications', '业务软件', 7, 3);
  entity(d, 'admin_sessions', '管理员会话', 0, -3);
  entity(d, 'application_keys', '软件 API Key', 7, -3);
  attributes(d, 'admin_accounts', 'admin_accounts', [['username', '管理员账号', -2.1, 5.5], ['display_name', '显示名称', 0, 5.5], ['role', '管理员类型', 2.1, 5.5]]);
  top(d, 'applications', '软件编号', 7, 5.5);
  attributes(d, 'admin_sessions', 'admin_sessions', [['token_hash', '会话标识（哈希）', -1.2, -5.4], ['expires_at', '到期时间', 1.2, -5.4]]);
  top(d, 'application_keys', '密钥编号', 7, -5.4, [['key_hash', '密钥哈希'], ['expires_at', '到期时间']]);
  relation(d, 'admin_scope', '管理范围', 'admin_accounts', 'applications', 'M', 'N', 3.5, 3, 'admin_account_applications');
  relation(d, 'session_owner', '建立', 'admin_accounts', 'admin_sessions', '1', 'N', 0, 0);
  relation(d, 'key_owner', '签发', 'applications', 'application_keys', '1', 'N', 7, 0);
}
{
  const d = diagram('06-通知审计', '06  通知投递与审计');
  entity(d, 'applications', '业务软件', 0, 3);
  entity(d, 'webhooks', 'Webhook 订阅', 6, 3);
  entity(d, 'webhook_deliveries', '通知投递', 12, 3);
  entity(d, 'audit_events', '审计事件', 3, -3);
  entity(d, 'audit_seal', '审计封存状态', 10, -3);
  top(d, 'applications', '软件编号', 0, 5.5, [['name', '软件名称']]);
  top(d, 'webhooks', '订阅编号', 6, 5.5, [['url', '回调地址'], ['events', '订阅事件']]);
  top(d, 'webhook_deliveries', '投递编号', 12, 5.5, [['status', '投递状态'], ['attempts', '尝试次数']]);
  top(d, 'audit_events', '事件编号', 3, -5.5, [['action', '操作'], ['chain_hash', '链哈希']]);
  top(d, 'audit_seal', '状态编号', 10, -5.5, [['last_seq', '链尾序号'], ['last_hash', '链尾哈希']]);
  relation(d, 'subscribe', '配置', 'applications', 'webhooks', '1', 'N', 3, 3);
  relation(d, 'deliver', '产生投递', 'webhooks', 'webhook_deliveries', '1', 'N', 9, 3);
}

const quote = JSON.stringify;
const escape = s => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
function dot(d) {
  const lines = ['graph Chen {',
    `graph [layout=neato, overlap=true, splines=line, outputorder=edgesfirst, bgcolor="white", pad="0.5", fontname="${font}", fontsize=22, labelloc=t, labeljust=l];`,
    `node [fontname="${font}", fontsize=15, pin=true, penwidth=1.5, color="#263e48"];`,
    `edge [fontname="${font}", fontsize=15, color="#50616a", penwidth=1.2, labeldistance=1.8, labelangle=25];`,
    'label=<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="3">' +
      [
        ['MelonHub / 陈氏 E-R 图 / ' + d.title, 22],
        ['V7 软件级 RBAC0 | 2026-10-29', 14],
        ['矩形：实体　菱形：联系　椭圆：属性　下划线：主键', 14],
        ['1 / M / N：最大基数　单线：可选参与　双线：必须参与', 14],
        ['关键属性节选；完整字段和外键见原表结构图。', 14],
      ].map(([text, size]) => `<TR><TD ALIGN="LEFT"><FONT POINT-SIZE="${size}">${escape(text)}</FONT></TD></TR>`).join('') + '</TABLE>>;'];
  for (const n of d.nodes) {
    const common = `pos="${n.x},${n.y}!"`;
    if (n.type === 'entity') {
      lines.push(`${n.id} [${common}, shape=box, style=filled, fillcolor="#e9f3f5", width=2.3, height=0.8, label=<<B>${escape(n.title)}</B><BR/><FONT POINT-SIZE="11">${n.table}</FONT>>];`);
    } else if (n.type === 'relation') {
      lines.push(`${n.id} [${common}, shape=diamond, style=filled, fillcolor="#fff3dc", width=1.8, height=1, label=${quote(n.title)}];`);
    } else {
      const text = `${escape(n.title)}<BR/><FONT POINT-SIZE="10">${n.column}</FONT>`;
      lines.push(`${n.id} [${common}, shape=ellipse, width=1.8, height=0.68, fontsize=12, label=<${n.key ? '<U>' + text + '</U>' : text}>];`);
    }
  }
  for (const e of d.edges) {
    const options = [];
    if (e.max) options.push(`headlabel="${e.max}"`);
    if (e.total) options.push('color="#50616a:#ffffff:#50616a"');
    lines.push(`${e.from} -- ${e.to} [${options.join(', ')}];`);
  }
  lines.push('}');
  return lines.join('\n') + '\n';
}

async function main() {
  const represented = new Set(diagrams.flatMap(d => [...d.represented]));
  const runtime = [...new Set(schema.columns.map(c => c.TABLE_NAME))].filter(t => !t.endsWith('_archive') && t !== 'flyway_schema_history');
  const missing = runtime.filter(t => !represented.has(t));
  if (missing.length) throw Error('运行表未映射到实体或联系：' + missing.join(', '));
  fs.mkdirSync(output, { recursive: true });
  const viz = await instance();
  for (const d of diagrams) {
    const source = dot(d);
    const result = viz.render(source, { format: 'svg', engine: 'neato' });
    if (result.status !== 'success' || result.errors.some(e => e.level === 'error')) throw Error(JSON.stringify(result.errors));
    const prefix = path.join(output, d.name);
    fs.writeFileSync(prefix + '.dot', source);
    const svg = result.output.replaceAll('font-family="Arial"', 'font-family="Microsoft YaHei"');
    fs.writeFileSync(prefix + '.svg', svg);
    const png = new Resvg(svg, {
      font: { loadSystemFonts: true, defaultFontFamily: 'Microsoft YaHei' },
      fitTo: { mode: 'zoom', value: 1.5 }, background: 'white',
    }).render();
    fs.writeFileSync(prefix + '.png', png.asPng());
    console.log(`${d.name}: ${png.width} x ${png.height}`);
  }
  console.log(`结构检查通过：${represented.size} 张运行表均已映射；属性列和联系均有快照依据。`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });

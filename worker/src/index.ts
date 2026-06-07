import { Hono } from 'hono';
import { cors } from 'hono/cors';

// ============================================================
// 类型定义
// ============================================================

interface Monitor {
  id: number;
  name: string;
  url: string;
  method: string;
  request_headers: string | null; // JSON 格式自定义请求头
  request_body: string | null;    // POST 请求体
  interval: number;
  status: 'UP' | 'DOWN' | 'RETRYING' | 'PAUSED';
  retry_count: number;
  last_check: string | null;
  keyword: string | null;
  user_agent: string | null;
  tags: string | null;            // 逗号分隔标签
  domain_expiry: string | null;
  cert_expiry: string | null;
  check_info_status: string | null;
  paused: number;
  check_ssl: number;
  check_domain: number;
  alert_silence_uptime: number;
  alert_silence_ssl: number;
  alert_silence_domain: number;
  alert_error_rate: number;       // 错误率阈值告警百分比 (0=关闭)
  last_alert_uptime: string | null;
  last_alert_ssl: string | null;
  last_alert_domain: string | null;
  sort_order: number;             // 拖拽排序顺序
  created_at: string;
}

interface Log {
  id: number;
  monitor_id: number;
  status_code: number;
  latency: number;
  is_fail: number;
  reason: string | null;
  created_at: string;
}

interface DingTalkResult {
  errcode: number;
  errmsg: string;
}

interface NotificationChannel {
  id: number;
  type: 'dingtalk' | 'wecom' | 'feishu' | 'telegram' | 'webhook' | 'email';
  name: string;
  enabled: number;
  config: string;
  created_at: string;
}

interface Incident {
  id: number;
  title: string;
  description: string | null;
  severity: 'info' | 'warning' | 'critical';
  status: 'active' | 'resolved';
  type: 'incident' | 'maintenance';
  scheduled_start: string | null;
  scheduled_end: string | null;
  affected_monitors: string | null;  // 逗号分隔的监控 ID
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

type Bindings = {
  DB: D1Database;
  DINGTALK_ACCESS_TOKEN: string;
  DINGTALK_SECRET: string;
  ADMIN_PASSWORD?: string;
  ADMIN_API_KEY?: string;    // 新增：API 密钥认证（优先级高于密码）
  ALLOWED_ORIGIN?: string;
  SESSION_TTL_HOURS?: string;
};

const textEncoder = new TextEncoder();
const MONITOR_COLUMNS = `
  id, name, url, method, request_headers, request_body, interval, status,
  retry_count, last_check, keyword, user_agent, tags, domain_expiry, cert_expiry,
  check_info_status, paused, check_ssl, check_domain, alert_silence_uptime,
  alert_silence_ssl, alert_silence_domain, alert_error_rate, last_alert_uptime,
  last_alert_ssl, last_alert_domain, sort_order, created_at
`;

function getAllowedOrigins(env: Bindings): string[] {
  return (env.ALLOWED_ORIGIN || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);
}

function isLocalOrigin(origin: string): boolean {
  return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

function getAuthSecret(env: Bindings): string | null {
  return env.ADMIN_API_KEY || env.ADMIN_PASSWORD || null;
}

function base64UrlEncode(input: string | ArrayBuffer): string {
  const bytes = typeof input === 'string' ? textEncoder.encode(input) : new Uint8Array(input);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(input: string): string {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - input.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', textEncoder.encode(value)));
}

async function safeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  let diff = ha.length ^ hb.length;
  for (let i = 0; i < Math.max(ha.length, hb.length); i++) {
    diff |= (ha[i] || 0) ^ (hb[i] || 0);
  }
  return diff === 0;
}

async function hmacSha256(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return base64UrlEncode(await crypto.subtle.sign('HMAC', key, textEncoder.encode(value)));
}

async function verifyAdminCredential(env: Bindings, credential: string): Promise<boolean> {
  const candidates = [env.ADMIN_API_KEY, env.ADMIN_PASSWORD].filter(Boolean) as string[];
  for (const candidate of candidates) {
    if (await safeEqual(credential, candidate)) return true;
  }
  return false;
}

async function createSessionToken(env: Bindings): Promise<{ token: string; expires_at: string }> {
  const secret = getAuthSecret(env);
  if (!secret) throw new Error('Admin auth is not configured');
  const configuredTtl = Number(env.SESSION_TTL_HOURS);
  const ttlHours = Number.isFinite(configuredTtl) && configuredTtl > 0
    ? Math.max(1, Math.min(configuredTtl, 168))
    : 12;
  const expiresAt = new Date(Date.now() + ttlHours * 3_600_000);
  const payload = base64UrlEncode(JSON.stringify({ exp: expiresAt.toISOString() }));
  const signature = await hmacSha256(secret, payload);
  return { token: `v1.${payload}.${signature}`, expires_at: expiresAt.toISOString() };
}

async function verifySessionToken(env: Bindings, token: string): Promise<boolean> {
  const secret = getAuthSecret(env);
  if (!secret || !token.startsWith('v1.')) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [, payload, signature] = parts;
  const expected = await hmacSha256(secret, payload);
  if (!await safeEqual(signature, expected)) return false;
  try {
    const data = JSON.parse(base64UrlDecode(payload)) as { exp?: string };
    return !!data.exp && new Date(data.exp).getTime() > Date.now();
  } catch {
    return false;
  }
}

// ============================================================
// Hono 应用初始化
// ============================================================

const app = new Hono<{ Bindings: Bindings }>();

app.use('/*', cors({
  origin: (origin, c) => {
    const allowed = getAllowedOrigins(c.env);
    if (allowed.length === 0) return origin && isLocalOrigin(origin) ? origin : '';
    if (!origin) return allowed[0];
    return allowed.includes(origin) ? origin : '';
  },
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));

// ============================================================
// 鉴权中间件
// ============================================================

const PROTECTED_ROUTES = ['/monitors', '/notification-channels', '/incidents', '/settings', '/test-alert', '/health'];

app.use('/*', async (c, next) => {
  if (c.req.method === 'OPTIONS') return await next();
  // 公开路由豁免
  if (c.req.path === '/monitors/public' || c.req.path === '/monitors/public/details') return await next();
  if (c.req.path === '/incidents' && c.req.method === 'GET') return await next();
  if (c.req.path === '/settings' && c.req.method === 'GET') return await next();

  // 检查是否需要鉴权
  const needsAuth = PROTECTED_ROUTES.some(r => c.req.path.startsWith(r));
  if (!needsAuth) return await next();

  const authHeader = c.req.header('Authorization');
  if (!authHeader) return c.json({ error: 'Unauthorized' }, 401);

  const token = authHeader.replace(/^Bearer\s+/i, '');

  if (await verifySessionToken(c.env, token)) return await next();
  if (await verifyAdminCredential(c.env, token)) return await next();
  if (!getAuthSecret(c.env)) return c.json({ error: 'Admin auth is not configured' }, 503);

  return c.json({ error: 'Unauthorized: Invalid credentials' }, 401);
});

app.post('/auth/login', async (c) => {
  try {
    const body = await c.req.json<{ password?: string }>();
    if (!body.password) return c.json({ error: 'Password is required' }, 400);
    if (!getAuthSecret(c.env)) return c.json({ error: 'Admin auth is not configured' }, 503);
    if (!await verifyAdminCredential(c.env, body.password)) return c.json({ error: 'Invalid password' }, 401);
    const session = await createSessionToken(c.env);
    return c.json(session);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ============================================================
// 监控 CRUD
// ============================================================

app.get('/monitors', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(`SELECT ${MONITOR_COLUMNS} FROM monitors ORDER BY sort_order ASC, created_at ASC`).all<Monitor>();
    return c.json(results);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.get('/monitors/public', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT id, name, url, status, last_check, cert_expiry, domain_expiry, paused, tags FROM monitors ORDER BY sort_order ASC, created_at ASC'
    ).all<Pick<Monitor, 'id' | 'name' | 'url' | 'status' | 'last_check' | 'cert_expiry' | 'domain_expiry' | 'paused' | 'tags'>>();
    return c.json(results);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ── 公开详情 API：含延迟、可用率、90天历史（无需鉴权）──
app.get('/monitors/public/details', async (c) => {
  try {
    const { results: monitors } = await c.env.DB.prepare(
      'SELECT id, name, url, status, last_check, cert_expiry, domain_expiry, paused, tags FROM monitors ORDER BY sort_order ASC, created_at ASC'
    ).all();
    if (!monitors || monitors.length === 0) return c.json({ monitors: [] });

    // 自动建表（兼容未迁移数据库）
    await c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS daily_uptime (
      monitor_id INTEGER NOT NULL, date TEXT NOT NULL,
      total_checks INTEGER DEFAULT 0, successful_checks INTEGER DEFAULT 0,
      avg_latency INTEGER DEFAULT 0, PRIMARY KEY (monitor_id, date)
    )`).run();

    // 首次运行时回填历史数据
    const cnt = await c.env.DB.prepare('SELECT COUNT(*) as c FROM daily_uptime').first<{ c: number }>();
    if (cnt && cnt.c === 0) {
      await c.env.DB.prepare(`
        INSERT OR IGNORE INTO daily_uptime (monitor_id, date, total_checks, successful_checks, avg_latency)
        SELECT monitor_id, date(created_at), COUNT(*), SUM(CASE WHEN is_fail=0 THEN 1 ELSE 0 END),
               COALESCE(CAST(AVG(CASE WHEN is_fail=0 THEN latency END) AS INTEGER), 0)
        FROM logs
        WHERE created_at >= date('now','-90 days') AND created_at < date('now')
        GROUP BY monitor_id, date(created_at)
      `).run();
    }

    // 90天每日可用率
    const { results: dailyRows } = await c.env.DB.prepare(
      "SELECT monitor_id, date, total_checks, successful_checks FROM daily_uptime WHERE date >= date('now','-90 days') ORDER BY monitor_id, date"
    ).all();

    // 实时统计（24h/7d/30d 合并查询）
    const { results: liveRows } = await c.env.DB.prepare(`
      SELECT monitor_id,
        SUM(CASE WHEN created_at >= datetime('now','-24 hours') THEN 1 ELSE 0 END) as t24,
        SUM(CASE WHEN created_at >= datetime('now','-24 hours') AND is_fail=0 THEN 1 ELSE 0 END) as s24,
        SUM(CASE WHEN created_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) as t7,
        SUM(CASE WHEN created_at >= datetime('now','-7 days') AND is_fail=0 THEN 1 ELSE 0 END) as s7,
        COUNT(*) as t30, SUM(CASE WHEN is_fail=0 THEN 1 ELSE 0 END) as s30
      FROM logs WHERE created_at >= datetime('now','-30 days') GROUP BY monitor_id
    `).all();

    // 最近延迟（折线图用）
    const { results: latRows } = await c.env.DB.prepare(
      'SELECT monitor_id, latency FROM logs WHERE is_fail=0 ORDER BY created_at DESC LIMIT 200'
    ).all();

    // 组装查找表
    type DS = { date: string; up: number; total: number };
    const dMap = new Map<number, DS[]>();
    for (const r of dailyRows || []) {
      const id = r.monitor_id as number;
      if (!dMap.has(id)) dMap.set(id, []);
      dMap.get(id)!.push({ date: r.date as string, up: r.successful_checks as number, total: r.total_checks as number });
    }
    const sMap = new Map<number, Record<string, number>>();
    for (const r of liveRows || []) sMap.set(r.monitor_id as number, r as Record<string, number>);
    const lMap = new Map<number, number[]>();
    for (const r of latRows || []) {
      const id = r.monitor_id as number;
      if (!lMap.has(id)) lMap.set(id, []);
      const a = lMap.get(id)!;
      if (a.length < 24) a.push(r.latency as number);
    }
    for (const [, a] of lMap) a.reverse();

    const pct = (t?: number, s?: number) => t && t > 0 ? Number(((s! / t) * 100).toFixed(1)) : null;
    const enriched = monitors.map(m => {
      const id = m.id as number, s = sMap.get(id), lat = lMap.get(id) || [];
      return { ...m, latency: lat.length > 0 ? lat[lat.length - 1] : null,
        uptime_24h: pct(s?.t24, s?.s24), uptime_7d: pct(s?.t7, s?.s7), uptime_30d: pct(s?.t30, s?.s30),
        daily_stats: dMap.get(id) || [], recent_latencies: lat };
    });
    return c.json({ monitors: enriched });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/monitors', async (c) => {
  try {
    const body = await c.req.json<Partial<Monitor>>();
    const { name, url, interval, keyword, user_agent, tags, request_headers, request_body } = body;

    if (!name || !url) {
      return c.json({ error: 'Missing name or url' }, 400);
    }

    const method = (body.method || 'GET').toUpperCase();

    const result = await c.env.DB.prepare(
      `INSERT INTO monitors (name, url, method, interval, keyword, user_agent, tags, request_headers, request_body)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      name, url, method,
      interval || 300,
      keyword || null,
      user_agent || null,
      tags || null,
      request_headers || null,
      request_body || null
    ).run();

    const newId = result.meta.last_row_id as number;

    c.executionCtx.waitUntil(
      (async () => {
        try {
          await c.env.DB.prepare('UPDATE monitors SET check_info_status = ? WHERE id = ?')
            .bind(new Date().toISOString(), newId).run();
          const { results } = await c.env.DB.prepare(`SELECT ${MONITOR_COLUMNS} FROM monitors WHERE id = ?`)
            .bind(newId).all<Monitor>();
          if (results[0]) await updateDomainCertInfo(c.env, results[0]);
        } catch (err) { console.error('Initial cert check failed:', err); }
      })()
    );

    return c.json({ success: true, id: newId }, 201);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.delete('/monitors/:id', async (c) => {
  const id = c.req.param('id');
  try {
    await c.env.DB.prepare('DELETE FROM logs WHERE monitor_id = ?').bind(id).run();
    await c.env.DB.prepare('DELETE FROM monitors WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.patch('/monitors/:id/config', async (c) => {
  const id = c.req.param('id');
  try {
    const body = await c.req.json<Record<string, unknown>>();

    const fields: string[] = [];
    const values: unknown[] = [];

    // 字符串字段
    const strFields: Array<[string, string]> = [
      ['name', 'name'], ['url', 'url'], ['keyword', 'keyword'],
      ['user_agent', 'user_agent'], ['tags', 'tags'],
      ['request_headers', 'request_headers'], ['request_body', 'request_body'],
    ];
    for (const [key, col] of strFields) {
      if (body[key] !== undefined) {
        if (key === 'name' || key === 'url') {
          if (typeof body[key] === 'string' && (body[key] as string).trim()) {
            fields.push(`${col} = ?`); values.push((body[key] as string).trim());
          }
        } else {
          fields.push(`${col} = ?`); values.push(body[key] || null);
        }
      }
    }

    // 数值/开关字段
    if (body.interval !== undefined) {
      const iv = Number(body.interval);
      if (!isNaN(iv) && iv >= 60) { fields.push('interval = ?'); values.push(iv); }
    }
    if (body.method !== undefined) {
      fields.push('method = ?'); values.push(String(body.method).toUpperCase());
    }

    const flagFields = ['check_ssl', 'check_domain'];
    for (const k of flagFields) {
      if (body[k] !== undefined) { fields.push(`${k} = ?`); values.push(body[k] ? 1 : 0); }
    }

    const numFields = ['alert_silence_uptime', 'alert_silence_ssl', 'alert_silence_domain', 'alert_error_rate'];
    for (const k of numFields) {
      if (body[k] !== undefined) {
        const h = Number(body[k]);
        if (!isNaN(h) && h >= 0) { fields.push(`${k} = ?`); values.push(h); }
      }
    }

    if (fields.length === 0) return c.json({ error: 'No valid fields to update' }, 400);
    values.push(id);

    await c.env.DB.prepare(`UPDATE monitors SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/monitors/:id/check', async (c) => {
  const id = c.req.param('id');
  try {
    const { results } = await c.env.DB.prepare(`SELECT ${MONITOR_COLUMNS} FROM monitors WHERE id = ?`).bind(id).all<Monitor>();
    if (!results[0]) return c.json({ error: 'Monitor not found' }, 404);

    // 强制执行证书及域名信息获取
    await updateDomainCertInfo(c.env, results[0]);
    // 更新最后一次信息获取时间，防止随后重复触发
    await c.env.DB.prepare('UPDATE monitors SET check_info_status = ? WHERE id = ?')
      .bind(new Date().toISOString(), id).run();

    await performCheck(results[0], c.env);

    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.patch('/monitors/:id/pause', async (c) => {
  const id = c.req.param('id');
  try {
    const { results } = await c.env.DB.prepare('SELECT paused, status FROM monitors WHERE id = ?')
      .bind(id).all<Pick<Monitor, 'paused' | 'status'>>();
    if (!results[0]) return c.json({ error: 'Monitor not found' }, 404);

    const newPaused = results[0].paused === 1 ? 0 : 1;
    const newStatus: Monitor['status'] = newPaused ? 'PAUSED' : 'UP';

    await c.env.DB.prepare('UPDATE monitors SET paused = ?, status = ?, retry_count = 0 WHERE id = ?')
      .bind(newPaused, newStatus, id).run();
    return c.json({ success: true, paused: newPaused === 1, status: newStatus });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.get('/monitors/:id/logs', async (c) => {
  const id = c.req.param('id');
  const limit = Math.min(Number(c.req.query('limit') || 50), 200);
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM logs WHERE monitor_id = ? ORDER BY created_at DESC LIMIT ?'
    ).bind(id, limit).all<Log>();
    return c.json(results);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// 可用率统计 API
app.get('/monitors/:id/stats', async (c) => {
  const id = c.req.param('id');
  try {
    const periods = [
      { key: 'h24', hours: 24 },
      { key: 'd7',  hours: 24 * 7 },
      { key: 'd30', hours: 24 * 30 },
    ];

    const stats: Record<string, string | null> = {};
    for (const { key, hours } of periods) {
      const since = new Date(Date.now() - hours * 3_600_000).toISOString();
      const row = await c.env.DB.prepare(
        'SELECT COUNT(*) as total, SUM(CASE WHEN is_fail = 0 THEN 1 ELSE 0 END) as success FROM logs WHERE monitor_id = ? AND created_at >= ?'
      ).bind(id, since).first<{ total: number; success: number }>();
      if (row && row.total > 0) {
        stats[key] = ((row.success / row.total) * 100).toFixed(2);
      } else {
        stats[key] = null;
      }
    }
    return c.json(stats);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// 批量操作 API
app.post('/monitors/batch', async (c) => {
  try {
    const body = await c.req.json<{ action: 'pause' | 'resume' | 'delete'; ids: number[] }>();
    const { action, ids } = body;
    if (!action || !ids || !Array.isArray(ids) || ids.length === 0) {
      return c.json({ error: 'Missing action or ids' }, 400);
    }
    const placeholders = ids.map(() => '?').join(',');
    switch (action) {
      case 'pause':
        await c.env.DB.prepare(`UPDATE monitors SET paused = 1, status = 'PAUSED', retry_count = 0 WHERE id IN (${placeholders})`)
          .bind(...ids).run();
        break;
      case 'resume':
        await c.env.DB.prepare(`UPDATE monitors SET paused = 0, status = 'UP', retry_count = 0 WHERE id IN (${placeholders})`)
          .bind(...ids).run();
        break;
      case 'delete':
        await c.env.DB.prepare(`DELETE FROM logs WHERE monitor_id IN (${placeholders})`).bind(...ids).run();
        await c.env.DB.prepare(`DELETE FROM monitors WHERE id IN (${placeholders})`).bind(...ids).run();
        break;
      default:
        return c.json({ error: 'Invalid action' }, 400);
    }
    return c.json({ success: true, affected: ids.length });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// 拖拽排序 API
app.put('/monitors/reorder', async (c) => {
  try {
    const body = await c.req.json<{ ids: number[] }>();
    if (!body.ids || !Array.isArray(body.ids) || body.ids.length === 0) {
      return c.json({ error: 'Missing ids array' }, 400);
    }
    const stmts = body.ids.map((id, idx) =>
      c.env.DB.prepare('UPDATE monitors SET sort_order = ? WHERE id = ?').bind(idx, id)
    );
    await c.env.DB.batch(stmts);
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ============================================================
// 事件公告 CRUD
// ============================================================

// 公开：仅返回 active 事件
app.get('/incidents', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM incidents WHERE status = 'active' ORDER BY created_at DESC"
    ).all<Incident>();
    return c.json(results || []);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// Admin：获取全部事件
app.get('/incidents/all', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100'
    ).all<Incident>();
    return c.json(results || []);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/incidents', async (c) => {
  try {
    const body = await c.req.json<{ title: string; description?: string; severity?: string; type?: string; scheduled_start?: string; scheduled_end?: string; affected_monitors?: string }>();
    if (!body.title) return c.json({ error: 'Missing title' }, 400);
    const severity = ['info', 'warning', 'critical'].includes(body.severity || '') ? body.severity : 'info';
    const type = body.type === 'maintenance' ? 'maintenance' : 'incident';
    const now = new Date().toISOString();
    const result = await c.env.DB.prepare(
      'INSERT INTO incidents (title, description, severity, status, type, scheduled_start, scheduled_end, affected_monitors, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(body.title, body.description || null, severity, 'active', type, body.scheduled_start || null, body.scheduled_end || null, body.affected_monitors || null, now, now).run();
    return c.json({ success: true, id: result.meta.last_row_id }, 201);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.patch('/incidents/:id', async (c) => {
  const id = c.req.param('id');
  try {
    const body = await c.req.json<{ title?: string; description?: string; severity?: string; status?: string }>();
    const fields: string[] = [];
    const values: unknown[] = [];
    const now = new Date().toISOString();

    if (body.title) { fields.push('title = ?'); values.push(body.title); }
    if (body.description !== undefined) { fields.push('description = ?'); values.push(body.description || null); }
    if (body.severity && ['info', 'warning', 'critical'].includes(body.severity)) {
      fields.push('severity = ?'); values.push(body.severity);
    }
    if (body.status === 'resolved') {
      fields.push("status = 'resolved'");
      fields.push('resolved_at = ?'); values.push(now);
    } else if (body.status === 'active') {
      fields.push("status = 'active'");
      fields.push('resolved_at = NULL');
    }
    fields.push('updated_at = ?'); values.push(now);

    if (fields.length <= 1) return c.json({ error: 'No valid fields' }, 400);
    values.push(id);

    await c.env.DB.prepare(`UPDATE incidents SET ${fields.join(', ')} WHERE id = ?`)
      .bind(...values).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.delete('/incidents/:id', async (c) => {
  const id = c.req.param('id');
  try {
    await c.env.DB.prepare('DELETE FROM incidents WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ============================================================
// 系统设置
// ============================================================

app.get('/settings', async (c) => {
  try {
    const { results } = await c.env.DB.prepare('SELECT key, value FROM settings').all<{ key: string; value: string }>();
    const obj: Record<string, string> = {};
    (results || []).forEach(r => { obj[r.key] = r.value; });
    return c.json(obj);
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.put('/settings', async (c) => {
  try {
    const body = await c.req.json<Record<string, string>>();
    const allowed = [
      'site_title',
      'site_description',
      'site_logo_url',
      'alert_template_down',
      'alert_template_up',
      'alert_template_error_rate',
    ];
    const now = new Date().toISOString();
    for (const key of allowed) {
      if (body[key] !== undefined) {
        await c.env.DB.prepare(
          'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at'
        ).bind(key, body[key], now).run();
      }
    }
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.get('/health', async (c) => {
  try {
    const [monitors, logs, channels, daily, lastLog] = await Promise.all([
      c.env.DB.prepare('SELECT COUNT(*) as c FROM monitors').first<{ c: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM logs').first<{ c: number }>(),
      c.env.DB.prepare('SELECT COUNT(*) as c FROM notification_channels WHERE enabled = 1').first<{ c: number }>(),
      c.env.DB.prepare('SELECT MAX(date) as d FROM daily_uptime').first<{ d: string | null }>(),
      c.env.DB.prepare('SELECT MAX(created_at) as t FROM logs').first<{ t: string | null }>(),
    ]);
    return c.json({
      ok: true,
      checked_at: new Date().toISOString(),
      monitors: monitors?.c ?? 0,
      logs: logs?.c ?? 0,
      enabled_channels: channels?.c ?? 0,
      latest_daily_uptime: daily?.d || null,
      latest_log_at: lastLog?.t || null,
    });
  } catch (e: unknown) {
    return c.json({ ok: false, error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ============================================================
// 通知渠道管理
// ============================================================

function maskSecret(val: string): string {
  if (!val || val.length <= 8) return '****';
  return val.slice(0, 4) + '****' + val.slice(-4);
}

function maskChannelConfig(channel: NotificationChannel): NotificationChannel {
  try {
    const cfg = JSON.parse(channel.config) as Record<string, unknown>;
    const masked: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(cfg)) {
      if (typeof v === 'string' && ['secret', 'token', 'access_token', 'bot_token', 'key'].some(s => k.toLowerCase().includes(s))) {
        masked[k] = maskSecret(v);
      } else {
        masked[k] = v;
      }
    }
    return { ...channel, config: JSON.stringify(masked) };
  } catch { return channel; }
}

app.get('/notification-channels', async (c) => {
  try {
    const { results } = await c.env.DB.prepare('SELECT * FROM notification_channels ORDER BY created_at DESC').all<NotificationChannel>();
    return c.json((results || []).map(maskChannelConfig));
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/notification-channels', async (c) => {
  try {
    const body = await c.req.json<{ type: string; name: string; config: Record<string, unknown>; enabled?: number }>();
    if (!body.type || !body.name || !body.config) return c.json({ error: 'Missing required fields' }, 400);
    const validTypes = ['dingtalk', 'wecom', 'feishu', 'telegram', 'webhook', 'email'];
    if (!validTypes.includes(body.type)) return c.json({ error: `Invalid type. Valid: ${validTypes.join(', ')}` }, 400);
    await c.env.DB.prepare('INSERT INTO notification_channels (type, name, enabled, config) VALUES (?, ?, ?, ?)')
      .bind(body.type, body.name, body.enabled ?? 1, JSON.stringify(body.config)).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.patch('/notification-channels/:id', async (c) => {
  const id = c.req.param('id');
  try {
    const body = await c.req.json<{ name?: string; enabled?: number; config?: Record<string, unknown> }>();
    const fields: string[] = [];
    const values: unknown[] = [];
    if (body.name !== undefined) { fields.push('name = ?'); values.push(body.name); }
    if (body.enabled !== undefined) { fields.push('enabled = ?'); values.push(body.enabled); }
    if (body.config !== undefined && Object.keys(body.config).length > 0) {
      const existing = await c.env.DB.prepare('SELECT config FROM notification_channels WHERE id = ?')
        .bind(id).first<{ config: string }>();
      let mergedConfig: Record<string, unknown> = {};
      if (existing?.config) { try { mergedConfig = JSON.parse(existing.config) as Record<string, unknown>; } catch { /**/ } }
      for (const [k, v] of Object.entries(body.config)) {
        if (v !== '' && v !== null && v !== undefined) mergedConfig[k] = v;
      }
      fields.push('config = ?'); values.push(JSON.stringify(mergedConfig));
    }
    if (fields.length === 0) return c.json({ error: 'No valid fields' }, 400);
    values.push(id);
    await c.env.DB.prepare(`UPDATE notification_channels SET ${fields.join(', ')} WHERE id = ?`).bind(...values).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.delete('/notification-channels/:id', async (c) => {
  const id = c.req.param('id');
  try {
    await c.env.DB.prepare('DELETE FROM notification_channels WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/notification-channels/:id/test', async (c) => {
  const id = c.req.param('id');
  try {
    const channel = await c.env.DB.prepare('SELECT * FROM notification_channels WHERE id = ?').bind(id).first<NotificationChannel>();
    if (!channel) return c.json({ error: 'Channel not found' }, 404);
    const mockMonitor = { name: 'Test Monitor', url: 'https://example.com' } as Monitor;
    const sent = await sendToChannel(channel, mockMonitor, 'DOWN', '这是一条测试消息，用于验证通知渠道是否配置正确。');
    return c.json({ success: sent });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

app.post('/test-alert', async (c) => {
  try {
    const mockMonitor = { name: 'Test Monitor', url: 'https://example.com' } as Monitor;
    const sent = await sendAlertToAllChannels(c.env, mockMonitor, 'DOWN', '这是一条测试消息，用于验证通知渠道配置。');
    return c.json({ success: sent });
  } catch (e: unknown) {
    return c.json({ error: e instanceof Error ? e.message : 'Unknown error' }, 500);
  }
});

// ============================================================
// 每日统计聚合
// ============================================================

async function aggregateDailyUptime(env: Bindings) {
  console.log('Aggregating daily uptime...');
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS daily_uptime (
      monitor_id INTEGER NOT NULL, date TEXT NOT NULL,
      total_checks INTEGER DEFAULT 0, successful_checks INTEGER DEFAULT 0,
      avg_latency INTEGER DEFAULT 0, PRIMARY KEY (monitor_id, date)
    )`).run();
    await env.DB.prepare(`
      INSERT OR REPLACE INTO daily_uptime (monitor_id, date, total_checks, successful_checks, avg_latency)
      SELECT monitor_id, date(created_at), COUNT(*), SUM(CASE WHEN is_fail=0 THEN 1 ELSE 0 END),
             COALESCE(CAST(AVG(CASE WHEN is_fail=0 THEN latency END) AS INTEGER), 0)
      FROM logs
      WHERE created_at >= date('now','-1 day') AND created_at < date('now')
      GROUP BY monitor_id, date(created_at)
    `).run();
    await env.DB.prepare("DELETE FROM daily_uptime WHERE date < date('now','-90 days')").run();
    console.log('Daily uptime aggregation completed.');
  } catch (e) { console.error('Daily uptime aggregation error:', e); }
}

// ============================================================
// 定时任务入口
// ============================================================

export default {
  fetch: app.fetch,

  async scheduled(_event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
    ctx.waitUntil(runScheduledTasks(env));
  },
};

async function runScheduledTasks(env: Bindings) {
  const hour = new Date().getUTCHours();
  const tasks: Promise<void>[] = [checkSites(env)];
  if (hour === 2) {
    tasks.push(cleanupLogs(env));
    tasks.push(checkExpiryAlerts(env));
    tasks.push(aggregateDailyUptime(env));
  }
  await Promise.all(tasks);
}

// ============================================================
// 核心监测逻辑
// ============================================================

async function checkSites(env: Bindings) {
  console.log('Starting scheduled check...');
  const now = Date.now();
  const { results } = await env.DB.prepare(`
    SELECT id, name, url, method, request_headers, request_body, interval, status,
           retry_count, last_check, keyword, user_agent, check_info_status, paused,
           alert_silence_uptime, alert_error_rate, last_alert_uptime
    FROM monitors
  `).all<Monitor>();
  const tasks = results.map(async (monitor) => {
    if (monitor.paused === 1) return;
    if (isTimeToCheck(monitor, now)) await performCheck(monitor, env);
  });
  await Promise.all(tasks);
}

function isTimeToCheck(monitor: Monitor, now: number): boolean {
  if (monitor.status === 'RETRYING') return true;
  const lastCheck = monitor.last_check ? new Date(monitor.last_check).getTime() : 0;
  const intervalMs = (monitor.interval || 300) * 1000;
  return now - lastCheck >= intervalMs;
}

async function performCheck(monitor: Monitor, env: Bindings) {
  const startTime = Date.now();
  let status = 200;
  let isFail = false;
  let reason = '';

  try {
    // 构建请求头
    let headers: Record<string, string> = {
      'User-Agent': monitor.user_agent || 'Uptime-Monitor/1.0',
    };
    if (monitor.request_headers) {
      try {
        const customHeaders = JSON.parse(monitor.request_headers) as Record<string, string>;
        headers = { ...headers, ...customHeaders };
      } catch { /* ignore malformed headers */ }
    }

    const fetchOptions: RequestInit = {
      method: monitor.method || 'GET',
      headers,
      cf: { cacheTtl: 0, cacheEverything: false } as RequestInitCfProperties,
    };

    // POST body
    if (['POST', 'PUT', 'PATCH'].includes(monitor.method || 'GET') && monitor.request_body) {
      fetchOptions.body = monitor.request_body;
      if (!headers['Content-Type']) {
        (fetchOptions.headers as Record<string, string>)['Content-Type'] = 'application/json';
      }
    }

    const response = await fetch(monitor.url, fetchOptions);
    status = response.status;

    if (!response.ok) {
      isFail = true;
      reason = `HTTP ${status}`;
    } else {
      // 每 24 小时刷新证书/域名信息
      const lastInfoCheck = monitor.check_info_status ? new Date(monitor.check_info_status).getTime() : 0;
      if (Date.now() - lastInfoCheck > 86400000) {
        env.DB.prepare('UPDATE monitors SET check_info_status = ? WHERE id = ?')
          .bind(new Date().toISOString(), monitor.id).run()
          .then(() => updateDomainCertInfo(env, monitor)).catch(console.error);
      }

      if (monitor.keyword) {
        const text = await response.text();
        if (!text.includes(monitor.keyword)) {
          isFail = true;
          reason = `Keyword "${monitor.keyword}" not found`;
        }
      }
    }
  } catch (e: unknown) {
    isFail = true;
    status = 0;
    const errorMsg = e instanceof Error ? e.message : 'Unknown error';
    if (errorMsg.includes('handshake') || errorMsg.includes('certificate') || errorMsg.includes('SSL') || errorMsg.includes('TLS')) {
      reason = `SSL Error: ${errorMsg}`;
    } else if (errorMsg.includes('time') || errorMsg.includes('timeout')) {
      reason = 'Timeout';
    } else {
      reason = errorMsg || 'Network Error';
    }
  }

  const latency = Date.now() - startTime;

  // 先写日志，再检查错误率
  await env.DB.prepare('INSERT INTO logs (monitor_id, status_code, latency, is_fail, reason) VALUES (?, ?, ?, ?, ?)')
    .bind(monitor.id, status, latency, isFail ? 1 : 0, reason || null).run();

  // 错误率阈值告警
  if (!isFail && monitor.alert_error_rate > 0) {
    await checkErrorRateAlert(env, monitor);
  }

  // 状态机
  let newStatus: Monitor['status'] = monitor.status;
  let newRetryCount = monitor.retry_count;

  // 检查是否在计划维护窗口内（如果是，跳过告警）
  try {
    const { results: activeMaint } = await env.DB.prepare(
      "SELECT affected_monitors FROM incidents WHERE type = 'maintenance' AND status = 'active' AND scheduled_start <= datetime('now') AND scheduled_end >= datetime('now')"
    ).all<{ affected_monitors: string | null }>();
    if (activeMaint && activeMaint.length > 0) {
      const inMaintenance = activeMaint.some(m => {
        if (!m.affected_monitors) return false;
        return m.affected_monitors.split(',').map(s => s.trim()).includes(String(monitor.id));
      });
      if (inMaintenance) {
        // 在维护窗口内，跳过状态变更告警
        await env.DB.prepare('UPDATE monitors SET last_check = ?, status = ?, retry_count = ? WHERE id = ?')
          .bind(new Date().toISOString(), newStatus, newRetryCount, monitor.id).run();
        return;
      }
    }
  } catch { /* ignore maintenance check errors */ }

  const silenceHoursUptime = monitor.alert_silence_uptime ?? 24;
  const lastAlertUptimeMs = monitor.last_alert_uptime ? new Date(monitor.last_alert_uptime).getTime() : 0;
  const silenced = silenceHoursUptime > 0 && (Date.now() - lastAlertUptimeMs) < silenceHoursUptime * 3_600_000;

  if (isFail) {
    if (monitor.status === 'UP') {
      newStatus = 'RETRYING';
      newRetryCount = 1;
    } else if (monitor.status === 'RETRYING') {
      if (newRetryCount < 3) {
        newRetryCount++;
      } else {
        newStatus = 'DOWN';
        if (!silenced) {
          const detail = await renderAlertDetail(env, 'alert_template_down', '错误原因: {reason}', {
            reason,
            status: String(status),
            latency: String(latency),
            type: 'DOWN',
          }, monitor);
          const sent = await sendAlertToAllChannels(env, monitor, 'DOWN', detail);
          if (sent) await env.DB.prepare('UPDATE monitors SET last_alert_uptime = ? WHERE id = ?')
            .bind(new Date().toISOString(), monitor.id).run();
        }
      }
    }
  } else {
    if (monitor.status === 'DOWN') {
      const detail = await renderAlertDetail(env, 'alert_template_up', '响应耗时: {latency}ms', {
        reason,
        status: String(status),
        latency: String(latency),
        type: 'UP',
      }, monitor);
      const sent = await sendAlertToAllChannels(env, monitor, 'UP', detail);
      if (sent) await env.DB.prepare('UPDATE monitors SET last_alert_uptime = ? WHERE id = ?')
        .bind(new Date().toISOString(), monitor.id).run();
    }
    newStatus = 'UP';
    newRetryCount = 0;
  }

  await env.DB.prepare('UPDATE monitors SET last_check = ?, status = ?, retry_count = ? WHERE id = ?')
    .bind(new Date().toISOString(), newStatus, newRetryCount, monitor.id).run();
}

async function renderAlertDetail(
  env: Bindings,
  key: string,
  fallback: string,
  vars: Record<string, string>,
  monitor: Pick<Monitor, 'name' | 'url'>
): Promise<string> {
  let template = fallback;
  try {
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first<{ value: string }>();
    if (row?.value) template = row.value;
  } catch { /* keep fallback */ }
  const values: Record<string, string> = {
    name: monitor.name,
    url: monitor.url,
    time: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    ...vars,
  };
  return template.replace(/\{([a-z_]+)\}/g, (_, name: string) => values[name] ?? '');
}

// 错误率阈值告警
async function checkErrorRateAlert(env: Bindings, monitor: Monitor) {
  try {
    const since = new Date(Date.now() - 5 * 60_000).toISOString(); // 过去 5 分钟
    const row = await env.DB.prepare(
      'SELECT COUNT(*) as total, SUM(is_fail) as fails FROM logs WHERE monitor_id = ? AND created_at >= ?'
    ).bind(monitor.id, since).first<{ total: number; fails: number }>();

    if (!row || row.total < 3) return; // 样本不足，忽略

    const errorRate = Math.round((row.fails / row.total) * 100);
    if (errorRate >= monitor.alert_error_rate) {
      const silenceHoursUptime = monitor.alert_silence_uptime ?? 24;
      const lastAlertMs = monitor.last_alert_uptime ? new Date(monitor.last_alert_uptime).getTime() : 0;
      if (silenceHoursUptime > 0 && (Date.now() - lastAlertMs) < silenceHoursUptime * 3_600_000) return;

      const detail = await renderAlertDetail(
        env,
        'alert_template_error_rate',
        '错误率告警：过去 5 分钟内错误率 {error_rate}%，超过阈值 {threshold}%',
        {
          error_rate: String(errorRate),
          threshold: String(monitor.alert_error_rate),
          type: 'DOWN',
        },
        monitor
      );
      const sent = await sendAlertToAllChannels(env, monitor, 'DOWN', detail);
      if (sent) await env.DB.prepare('UPDATE monitors SET last_alert_uptime = ? WHERE id = ?')
        .bind(new Date().toISOString(), monitor.id).run();
    }
  } catch (e) {
    console.error('Error rate check failed:', e);
  }
}

// ============================================================
// 日志自动清理
// ============================================================

async function cleanupLogs(env: Bindings) {
  console.log('Starting log cleanup...');
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const { meta: deletedOld } = await env.DB.prepare('DELETE FROM logs WHERE created_at < ?').bind(thirtyDaysAgo).run();
    console.log(`Deleted ${deletedOld.changes} old logs (>30d).`);

    const { results } = await env.DB.prepare('SELECT id FROM monitors').all<{ id: number }>();
    for (const monitor of results) {
      await env.DB.prepare(`
        DELETE FROM logs WHERE id IN (
          SELECT id FROM logs WHERE monitor_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET 1000
        )
      `).bind(monitor.id).run();
    }
    console.log('Log cleanup completed.');
  } catch (e: unknown) { console.error('Log cleanup error:', e); }
}

// ============================================================
// SSL / 域名到期主动告警
// ============================================================

async function checkExpiryAlerts(env: Bindings) {
  console.log('Checking expiry alerts...');
  try {
    const { results } = await env.DB.prepare(
      `SELECT id, name, url, cert_expiry, domain_expiry,
              check_ssl, check_domain,
              alert_silence_ssl, alert_silence_domain,
              last_alert_ssl, last_alert_domain
       FROM monitors WHERE paused = 0`
    ).all<Pick<Monitor, 'id' | 'name' | 'url' | 'cert_expiry' | 'domain_expiry' | 'check_ssl' | 'check_domain' | 'alert_silence_ssl' | 'alert_silence_domain' | 'last_alert_ssl' | 'last_alert_domain'>>();

    const now = Date.now();
    const tasks = results.map(async (monitor) => {
      const checks = [
        { label: 'SSL 证书', dateStr: monitor.cert_expiry, enabled: (monitor.check_ssl ?? 1) === 1, silenceHours: monitor.alert_silence_ssl ?? 24, lastAlertAt: monitor.last_alert_ssl, lastAlertField: 'last_alert_ssl' },
        { label: '域名', dateStr: monitor.domain_expiry, enabled: (monitor.check_domain ?? 1) === 1, silenceHours: monitor.alert_silence_domain ?? 24, lastAlertAt: monitor.last_alert_domain, lastAlertField: 'last_alert_domain' },
      ];
      for (const check of checks) {
        if (!check.enabled || !check.dateStr) continue;
        const lastMs = check.lastAlertAt ? new Date(check.lastAlertAt).getTime() : 0;
        if (check.silenceHours > 0 && (now - lastMs) < check.silenceHours * 3_600_000) continue;
        const daysLeft = Math.ceil((new Date(check.dateStr).getTime() - now) / (1000 * 60 * 60 * 24));
        let detail = '';
        if (daysLeft <= 0) detail = `❌ ${check.label}已过期，请立即续期处理！`;
        else if (daysLeft <= 7) detail = `🚨 ${check.label}紧急预警，仅剩 ${daysLeft} 天到期，请尽快续期！`;
        else if (daysLeft <= 30) detail = `⏰ ${check.label}到期提醒，还有 ${daysLeft} 天到期，请注意续期。`;
        if (detail) {
          const sent = await sendAlertToAllChannels(env, monitor as Monitor, 'DOWN', detail);
          if (sent) await env.DB.prepare(`UPDATE monitors SET ${check.lastAlertField} = ? WHERE id = ?`)
            .bind(new Date().toISOString(), monitor.id).run();
        }
      }
    });
    await Promise.all(tasks);
    console.log('Expiry alert check completed.');
  } catch (e: unknown) { console.error('Expiry alert check error:', e); }
}

// ============================================================
// 多渠道通知分发
// ============================================================

function buildAlertMessage(monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string) {
  const isDown = type === 'DOWN';
  const title = isDown ? '🔴 服务故障报警' : '🟢 服务恢复通知';
  const statusText = isDown ? '故障' : '正常';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  return { title, statusText, time, isDown, detail, monitorName: monitor.name, monitorUrl: monitor.url };
}

async function sendAlertToAllChannels(env: Bindings, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  try {
    const { results } = await env.DB.prepare('SELECT * FROM notification_channels WHERE enabled = 1').all<NotificationChannel>();
    if (results && results.length > 0) {
      const tasks = results.map(ch => sendToChannel(ch, monitor, type, detail));
      const outcomes = await Promise.allSettled(tasks);
      return outcomes.some(o => o.status === 'fulfilled' && o.value === true);
    }
  } catch (e) { console.error('Failed to read notification channels from DB:', e); }

  if (env.DINGTALK_ACCESS_TOKEN && env.DINGTALK_SECRET) {
    const fallbackChannel: NotificationChannel = {
      id: 0, type: 'dingtalk', name: 'ENV DingTalk', enabled: 1,
      config: JSON.stringify({ access_token: env.DINGTALK_ACCESS_TOKEN, secret: env.DINGTALK_SECRET }),
      created_at: '',
    };
    return sendToChannel(fallbackChannel, monitor, type, detail);
  }

  console.warn('No notification channels configured.');
  return false;
}

async function sendToChannel(channel: NotificationChannel, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const cfg = JSON.parse(channel.config) as Record<string, string>;
  try {
    switch (channel.type) {
      case 'dingtalk': return await sendDingTalk(cfg, monitor, type, detail);
      case 'wecom':    return await sendWeCom(cfg, monitor, type, detail);
      case 'feishu':   return await sendFeishu(cfg, monitor, type, detail);
      case 'telegram': return await sendTelegram(cfg, monitor, type, detail);
      case 'webhook':  return await sendWebhook(cfg, monitor, type, detail);
      case 'email':    return await sendEmail(cfg, monitor, type, detail);
      default: console.warn(`Unknown channel type: ${channel.type}`); return false;
    }
  } catch (e) {
    console.error(`Failed to send via ${channel.type} (${channel.name}):`, e);
    return false;
  }
}

// ── 钉钉 ──────────────────────────────────────────────────────
async function sendDingTalk(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { access_token, secret } = cfg;
  if (!access_token || !secret) { console.warn('DingTalk config missing.'); return false; }
  const timestamp = Date.now();
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestamp}\n${secret}`));
  const signEncoded = encodeURIComponent(btoa(String.fromCharCode(...new Uint8Array(signature))));
  const webhookUrl = `https://oapi.dingtalk.com/robot/send?access_token=${access_token}&timestamp=${timestamp}&sign=${signEncoded}`;
  const isDown = type === 'DOWN';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const title = isDown ? '🚨 突发！服务又双叒叕挂了 (╯°□°)╯︵ ┻━┻' : '🎉 仰卧起坐成功！服务满血复活 ヾ(≧▽≦*)o';
  const statusLabel = isDown ? '<font color="#cc0000">💥 彻底躺平 (DOWN)</font>' : '<font color="#00aa55">✨ 支楞起来了 (UP)</font>';
  const markdownText = [
    `### ${title}`,
    `---`,
    `- **⚡ 大名：** ${monitor.name}`,
    `- **🏠 门牌：** [${monitor.url}](${monitor.url})`,
    `- **🚥 医嘱：** ${statusLabel}`,
    `- **📝 八卦：** ${detail}`,
    `---`,
    `> ${isDown ? '☕ 稳住别慌，带上薪水去拯救世界~' : '🚀 虚惊一场，接着奏乐接着舞~'}`,
    ``,
    `<font color="#999999">📅 ${time} &nbsp;·&nbsp; Uptime Monitor</font>`,
  ].join('\n');
  const resp = await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ msgtype: 'markdown', markdown: { title, text: markdownText } }) });
  const result = await resp.json<DingTalkResult>();
  if (result.errcode !== 0) { console.error('DingTalk API Error:', result); return false; }
  return true;
}

// ── 企业微信 ──────────────────────────────────────────────────
async function sendWeCom(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { key } = cfg;
  if (!key) { console.warn('WeCom config missing.'); return false; }
  const isDown = type === 'DOWN';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const title = isDown ? '🚨 突发！服务又双叒叕挂了 (╯°□°)╯︵ ┻━┻' : '🎉 仰卧起坐成功！服务满血复活 ヾ(≧▽≦*)o';
  const statusLabel = isDown ? '<font color="warning">💥 彻底躺平 (DOWN)</font>' : '<font color="info">✨ 支楞起来了 (UP)</font>';
  const content = [
    `### ${title}`,
    ``,
    `> **⚡ 大名：** <font color="comment">${monitor.name}</font>`,
    `> **🏠 门牌：** [${monitor.url}](${monitor.url})`,
    `> **🚥 医嘱：** ${statusLabel}`,
    `> **📝 八卦：** <font color="comment">${detail}</font>`,
    ``,
    `> <font color="comment">${isDown ? '☕ 稳住别慌，带上薪水去拯救世界~' : '🚀 虚惊一场，接着奏乐接着舞~'}</font>`,
    `<font color="comment">📅 ${time} · Uptime Monitor</font>`
  ].join('\n');
  const resp = await fetch(`https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=${key}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ msgtype: 'markdown', markdown: { content } }) });
  const result = await resp.json<{ errcode: number }>();
  if (result.errcode !== 0) { console.error('WeCom API Error:', result); return false; }
  return true;
}

// ── 飞书 ──────────────────────────────────────────────────────
async function sendFeishu(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { webhook_url, secret } = cfg;
  if (!webhook_url) { console.warn('Feishu config missing.'); return false; }
  const isDown = type === 'DOWN';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const title = isDown ? '🚨 突发！服务又双叒叕挂了 (╯°□°)╯︵ ┻━┻' : '🎉 仰卧起坐成功！服务满血复活 ヾ(≧▽≦*)o';
  const statusFeishu = isDown ? '<font color="red">💥 彻底躺平 (DOWN)</font>' : '<font color="green">✨ 支楞起来了 (UP)</font>';
  const card = {
    config: { wide_screen_mode: true },
    header: { title: { tag: 'plain_text', content: title }, template: isDown ? 'red' : 'green' },
    elements: [
      {
        tag: 'div',
        fields: [
          { is_short: true, text: { tag: 'lark_md', content: `**⚡ 大名**\n${monitor.name}` } },
          { is_short: true, text: { tag: 'lark_md', content: `**🚥 医嘱**\n${statusFeishu}` } }
        ]
      },
      { tag: 'div', text: { tag: 'lark_md', content: `**🏠 门牌**\n[${monitor.url}](${monitor.url})` } },
      { tag: 'div', text: { tag: 'lark_md', content: `**📝 八卦**\n${detail}` } },
      { tag: 'hr' },
      { tag: 'note', elements: [{ tag: 'plain_text', content: `${isDown ? '☕ 稳住别慌，带上薪水去拯救世界~' : '🚀 虚惊一场，接着奏乐接着舞~'}  |  📅 ${time}` }] },
    ],
  };
  const body: Record<string, unknown> = { msg_type: 'interactive', card };
  if (secret) {
    const timestamp = Math.floor(Date.now() / 1000);
    const enc = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey('raw', enc.encode(`${timestamp}\n${secret}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(''));
    body.timestamp = String(timestamp);
    body.sign = btoa(String.fromCharCode(...new Uint8Array(signature)));
  }
  const resp = await fetch(webhook_url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const result = await resp.json<{ code: number }>();
  if (result.code !== 0) { console.error('Feishu API Error:', result); return false; }
  return true;
}

// ── Telegram ──────────────────────────────────────────────────
async function sendTelegram(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { bot_token, chat_id } = cfg;
  if (!bot_token || !chat_id) { console.warn('Telegram config missing.'); return false; }
  const isDown = type === 'DOWN';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const text = [
    isDown ? '🚨 <b>突发！服务又双叒叕挂了 (╯°□°)╯︵ ┻━┻</b>' : '🎉 <b>仰卧起坐成功！服务满血复活 ヾ(≧▽≦*)o</b>',
    ``,
    `⚡ <b>大名：</b> <code>${monitor.name}</code>`,
    `🏠 <b>门牌：</b> <a href="${monitor.url}">${monitor.url}</a>`,
    `🚥 <b>医嘱：</b> ${isDown ? '💥 彻底躺平 (DOWN)' : '✨ 支楞起来了 (UP)'}`,
    `📝 <b>八卦：</b> <i>${detail}</i>`,
    ``,
    `☕ <i>${isDown ? '稳住别慌，带上薪水去拯救世界~' : '虚惊一场，接着奏乐接着舞~'}</i>`,
    `📅 <i>${time} · Uptime Monitor</i>`,
  ].join('\n');
  const resp = await fetch(`https://api.telegram.org/bot${bot_token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id, text, parse_mode: 'HTML', disable_web_page_preview: true }) });
  const result = await resp.json<{ ok: boolean }>();
  if (!result.ok) { console.error('Telegram API Error:', result); return false; }
  return true;
}

// ── 自定义 Webhook ────────────────────────────────────────────
async function sendWebhook(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { url, method, headers: headersStr } = cfg;
  if (!url) { console.warn('Webhook config missing.'); return false; }
  const msg = buildAlertMessage(monitor, type, detail);
  const payload = { event: type === 'DOWN' ? 'monitor.down' : 'monitor.up', monitor: { name: msg.monitorName, url: msg.monitorUrl }, status: msg.statusText, detail: msg.detail, timestamp: msg.time };
  let parsedHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
  if (headersStr) { try { parsedHeaders = { ...parsedHeaders, ...JSON.parse(headersStr) }; } catch { /* ignore */ } }
  const resp = await fetch(url, { method: (method || 'POST').toUpperCase(), headers: parsedHeaders, body: JSON.stringify(payload) });
  return resp.ok;
}

// ── Email（Resend API）──────────────────────────────────────
async function sendEmail(cfg: Record<string, string>, monitor: Pick<Monitor, 'name' | 'url'>, type: 'DOWN' | 'UP', detail: string): Promise<boolean> {
  const { api_key, from_email, to_email } = cfg;
  if (!api_key || !to_email) { console.warn('Email config missing.'); return false; }
  const isDown = type === 'DOWN';
  const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  const title = isDown ? '🚨 突发！服务又双叒叕挂了 (╯°□°)╯︵ ┻━┻' : '🎉 仰卧起坐成功！服务满血复活 ヾ(≧▽≦*)o';
  const subject = title;
  const statusColor = isDown ? '#f43f5e' : '#10b981';
  const statusText = isDown ? '💥 彻底躺平 (DOWN)' : '✨ 支楞起来了 (UP)';
  const quote = isDown ? '☕ 稳住别慌，带上薪水去拯救世界~' : '🚀 虚惊一场，接着奏乐接着舞~';
  const html = `
<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:0 auto;background:#0f172a;border-radius:16px;overflow:hidden;border:1px solid #1e293b;box-shadow:0 10px 25px -5px rgba(0,0,0,0.5)">
  <div style="padding:28px;background:linear-gradient(135deg,${isDown ? '#4c0519' : '#064e3b'},#0f172a);border-bottom:1px solid #1e293b">
    <h2 style="margin:0;color:#f8fafc;font-size:18px;line-height:1.4">${title}</h2>
  </div>
  <div style="padding:28px;color:#cbd5e1;line-height:1.8;font-size:15px">
    <p style="margin:0 0 12px"><strong>⚡ 大名：</strong> <span style="color:#f1f5f9">${monitor.name}</span></p>
    <p style="margin:0 0 12px"><strong>🏠 门牌：</strong> <a href="${monitor.url}" style="color:#38bdf8;text-decoration:none">${monitor.url}</a></p>
    <p style="margin:0 0 12px"><strong>🚥 医嘱：</strong> <span style="color:${statusColor};font-weight:700">${statusText}</span></p>
    <div style="margin:16px 0;padding:16px;background:#1e293b;border-radius:12px;border-left:4px solid ${statusColor}">
      <p style="margin:0;font-size:14px;color:#94a3b8"><strong>📝 八卦：</strong> ${detail}</p>
    </div>
    <p style="margin:24px 0 0;text-align:center;font-style:italic;color:#64748b">${quote}</p>
  </div>
  <div style="padding:16px 28px;background:#0b1120;text-align:center;font-size:12px;color:#475569">
    📅 ${time} · Uptime Monitor
  </div>
</div>`;
  const fromAddr = from_email || 'Uptime Monitor <noreply@resend.dev>';
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${api_key}` },
    body: JSON.stringify({ from: fromAddr, to: to_email.split(',').map(s => s.trim()), subject, html }),
  });
  if (!resp.ok) { console.error('Resend API Error:', await resp.text()); return false; }
  return true;
}

// ============================================================
// 域名 / 证书信息更新逻辑
// ============================================================

async function updateDomainCertInfo(env: Bindings, monitor: Monitor) {
  console.log(`Updating info for ${monitor.url}`);
  try {
    const urlObj = new URL(monitor.url);
    const domain = urlObj.hostname;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
      console.log(`Skipping cert/domain check for IP address: ${domain}`);
      return;
    }

    let certExpiry: string | null = null;
    try {
      const browserUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
      const fetchCerts = async (searchDomain: string): Promise<Record<string, unknown>[]> => {
        try {
          const res = await fetch(`https://crt.sh/?q=${searchDomain}&output=json`, { headers: { 'User-Agent': browserUA } });
          if (!res.ok) return [];
          try { return JSON.parse(await res.text()) as Record<string, unknown>[]; } catch { return []; }
        } catch { return []; }
      };

      let certs = await fetchCerts(domain);
      if (domain.split('.').length > 2) {
        const parts = domain.split('.');
        const rootDomain = parts.slice(parts.length - 2).join('.');
        
        const [rootCerts, wildcardCerts] = await Promise.all([
          fetchCerts(rootDomain),
          fetchCerts(`%25.${rootDomain}`)
        ]);
        
        certs = [...certs, ...rootCerts, ...wildcardCerts];
      }

      if (certs.length > 0) {
        const nowMs = Date.now();
        const parseExpiry = (s: string) => new Date(s.replace(' ', 'T')).getTime();
        const validCerts = certs.filter(c => { const exp = parseExpiry(c.not_after as string); return !isNaN(exp) && exp > nowMs; });
        const source = validCerts.length > 0 ? validCerts : certs;
        const sorted = source.sort((a, b) => parseExpiry(b.not_after as string) - parseExpiry(a.not_after as string));
        certExpiry = (sorted[0].not_after as string).replace(' ', 'T');
        console.log(`Found cert expiry for ${domain}: ${certExpiry}`);
      }
    } catch (e) { console.warn('Failed to fetch cert info:', e); }

    let domainExpiry: string | null = null;
    try {
      const rdapRes = await fetch(`https://rdap.org/domain/${domain}`);
      if (rdapRes.ok) {
        const rdapData = await rdapRes.json<{ events?: { eventAction: string; eventDate: string }[] }>();
        const expEvent = (rdapData.events || []).find(e => e.eventAction.includes('expiration'));
        if (expEvent) domainExpiry = expEvent.eventDate;
      }
    } catch (e) { console.warn('Failed to fetch RDAP info:', e); }

    if (certExpiry || domainExpiry) {
      await env.DB.prepare('UPDATE monitors SET cert_expiry = ?, domain_expiry = ? WHERE id = ?')
        .bind(certExpiry, domainExpiry, monitor.id).run();
      console.log(`Updated info for ${domain}: Cert=${certExpiry}, Domain=${domainExpiry}`);
    }
  } catch (e: unknown) { console.error('Error in updateDomainCertInfo:', e); }
}


'use strict';

const http = require('node:http');
const fs   = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// bcrypt for password hashing. We use `bcryptjs` (pure-JS bcrypt — same
// algorithm, no native build to compile on the server). If it isn't
// installed we transparently fall back to Node's built-in scrypt so auth
// still works zero-dependency. Hashes are self-describing so verify knows which.
let bcrypt = null;
try { bcrypt = require('bcryptjs'); } catch { /* fall back to scrypt */ }

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DB_FILE = path.join(ROOT, 'nexus.db');
const ROLES = ['admin', 'editor', 'viewer'];
const SESSION_TTL = 1000 * 60 * 60 * 24 * 7;   // 7 days

/* =====================================================================
   SQLite (default data source + app storage)
   ===================================================================== */
const db = new DatabaseSync(DB_FILE);
db.exec(`CREATE TABLE IF NOT EXISTS app_dashboards (
  id TEXT PRIMARY KEY, name TEXT, state TEXT, updated INTEGER
)`);
// Named app_users (not "users") to avoid colliding with a sample data
// table that may already be named "users" in an existing database.
db.exec(`CREATE TABLE IF NOT EXISTS app_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','editor','viewer')),
  created_at INTEGER NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
)`);
db.exec(`CREATE TABLE IF NOT EXISTS dashboards (
  id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  state_json TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'private',
  share_token TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
)`);
// migrate older DBs that predate newer columns
try {
  const cols = db.prepare('PRAGMA table_info(dashboards)').all().map(c => c.name);
  if (!cols.includes('visibility')) db.exec("ALTER TABLE dashboards ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'");
  if (!cols.includes('share_token')) db.exec('ALTER TABLE dashboards ADD COLUMN share_token TEXT');
} catch { /* fresh db already has them */ }
// Per-user read-only grants: admin/owner grants a specific user view access.
db.exec(`CREATE TABLE IF NOT EXISTS dashboard_grants (
  dashboard_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (dashboard_id, user_id)
)`);
// Per-user, per-widget permission: 'none' | 'view' | 'edit'.
// A non-owner sees a widget only if granted view/edit, and gets edit
// controls only with 'edit'. Owners/admins always have full access.
db.exec(`CREATE TABLE IF NOT EXISTS widget_permissions (
  widget_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  can_view INTEGER NOT NULL DEFAULT 1,
  permission TEXT NOT NULL DEFAULT 'view',
  PRIMARY KEY (widget_id, user_id)
)`);
// migrate older rows that only had can_view
try {
  const cols = db.prepare('PRAGMA table_info(widget_permissions)').all().map(c => c.name);
  if (!cols.includes('permission')) {
    db.exec("ALTER TABLE widget_permissions ADD COLUMN permission TEXT NOT NULL DEFAULT 'view'");
    db.exec("UPDATE widget_permissions SET permission = CASE WHEN can_view=0 THEN 'none' ELSE 'view' END");
  }
} catch { /* fresh db already has it */ }
db.exec(`CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT)`);
// Saved database connections (credentials encrypted at rest, never echoed).
db.exec(`CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  engine TEXT NOT NULL DEFAULT 'postgres',
  host TEXT, port INTEGER, database TEXT, username TEXT,
  password_encrypted TEXT,
  created_at INTEGER NOT NULL
)`);

/* Tables that are app-internal, not user data sources */
const INTERNAL = new Set(['app_dashboards', 'sqlite_sequence', 'app_users', 'sessions',
  'dashboards', 'widget_permissions', 'app_meta', 'connections']);

/* ---- helpers ---- */
function sanitize(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+|_+$/g, '') || 'dataset';
}
function inferType(orig, rows) {
  // numeric only if every non-null value is a finite number
  const vals = rows.map(r => r[orig]).filter(v => v !== null && v !== undefined && v !== '');
  if (!vals.length) return 'TEXT';
  return vals.every(v => typeof v === 'number' || (!isNaN(Number(v)) && String(v).trim() !== '')) ? 'REAL' : 'TEXT';
}
/* read-only guard for the /api/query endpoint */
function isReadOnly(sql) {
  const s = String(sql).trim().replace(/;+\s*$/, '');
  if (/;/.test(s)) return false;                 // no multiple statements
  if (!/^(select|with)\b/i.test(s)) return false;
  if (/\b(insert|update|delete|drop|alter|create|attach|detach|replace|truncate|pragma|vacuum)\b/i.test(s)) return false;
  return true;
}

/* =====================================================================
   Seed sample tables on first run (so Browse has real data immediately)
   ===================================================================== */
function ym(d){ const p=n=>String(n).padStart(2,'0'); return `${d.getFullYear()}-${p(d.getMonth()+1)}`; }
function ymd(d){ const p=n=>String(n).padStart(2,'0'); return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}`; }
function pseudo(a,b){ const x=Math.sin(a*12.9898+b*78.233)*43758.5453; return x-Math.floor(x); }

function seed() {
  const existing = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(r => r.name);
  if (!existing.includes('sales')) {
    const cats=['Electronics','Apparel','Home & Garden','Sports','Beauty'];
    const regions=['North','South','East','West']; const rows=[];
    const start=new Date(2024,0,1);
    for(let mo=0;mo<24;mo++){ const d=new Date(start.getFullYear(),start.getMonth()+mo,1);
      cats.forEach((cat,ci)=>{ const seasonal=1+0.3*Math.sin((mo/12)*Math.PI*2+ci);
        const revenue=Math.round((8000+ci*2500)*seasonal+pseudo(mo,ci)*4000);
        rows.push({ date:ym(d), category:cat, region:regions[(mo+ci)%4], revenue,
          units_sold:Math.round(revenue/(40+ci*12)),
          profit_margin:+(0.12+ci*0.03+pseudo(mo*3,ci)*0.08).toFixed(3) }); });
    }
    createTable('sales', ['date','category','region','revenue','units_sold','profit_margin'], rows);
  }
  if (!existing.includes('users')) {
    const plans=['Free','Pro','Team','Enterprise']; const rows=[];
    for(let i=0;i<60;i++) rows.push({ date:ymd(new Date(2024,0,1+i*6)), plan:plans[i%4],
      signups:Math.round(40+pseudo(i,1)*200), churn:+(pseudo(i,3)*0.15).toFixed(3),
      mrr:Math.round(500+pseudo(i,7)*9000) });
    createTable('users', ['date','plan','signups','churn','mrr'], rows);
  }
  if (!existing.includes('traffic')) {
    const src=['Organic','Paid','Social','Referral','Direct']; const rows=[];
    for(let i=0;i<50;i++) rows.push({ date:ymd(new Date(2024,3,1+i*3)), source:src[i%5],
      sessions:Math.round(200+pseudo(i,2)*3000), bounce_rate:+(0.2+pseudo(i,5)*0.5).toFixed(3),
      conversions:Math.round(pseudo(i,9)*120) });
    createTable('traffic', ['date','source','sessions','bounce_rate','conversions'], rows);
  }
}

/* Create a table from columns + array-of-row-objects, then insert rows. */
function createTable(rawName, columns, rows) {
  const name = sanitize(rawName);
  const cols = columns.map(sanitize);
  const typeFor = columns.map(orig => inferType(orig, rows));
  const colDefs = cols.map((c, i) => `"${c}" ${typeFor[i]}`).join(', ');
  db.exec(`DROP TABLE IF EXISTS "${name}"`);
  db.exec(`CREATE TABLE "${name}" (${colDefs})`);
  const placeholders = cols.map(() => '?').join(', ');
  const stmt = db.prepare(`INSERT INTO "${name}" (${cols.map(c=>`"${c}"`).join(', ')}) VALUES (${placeholders})`);
  db.exec('BEGIN');
  try {
    for (const r of rows) {
      stmt.run(...columns.map(orig => {
        let v = r[orig];
        if (v === undefined || v === '') v = null;
        return v;
      }));
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  return { name, rowCount: rows.length };
}

/* =====================================================================
   Active data source: 'sqlite' (default) or 'postgres' (after connect)
   ===================================================================== */
let activeSource = 'sqlite';
let pgPool = null;   // set once Connect DB succeeds

async function listTables() {
  if (activeSource === 'postgres') {
    const t = await pgPool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema='public' ORDER BY table_name`);
    const out = [];
    for (const row of t.rows) {
      const c = await pgPool.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position`, [row.table_name]);
      out.push({ name: row.table_name, columns: c.rows.map(x => x.column_name) });
    }
    return out;
  }
  // sqlite
  const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all()
    .map(r => r.name).filter(n => !INTERNAL.has(n) && !n.startsWith('sqlite_'));
  return names.map(name => ({
    name,
    columns: db.prepare(`PRAGMA table_info("${name}")`).all().map(c => c.name)
  }));
}

async function runQuery(sql) {
  if (!isReadOnly(sql)) throw new Error('Only read-only SELECT queries are allowed.');
  if (activeSource === 'postgres') {
    const r = await pgPool.query(sql);
    return r.rows;
  }
  return db.prepare(sql).all();
}

/* =====================================================================
   HTTP helpers
   ===================================================================== */
const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.png':'image/png', '.svg':'image/svg+xml',
  '.ico':'image/x-icon', '.map':'application/json' };

function sendJson(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 25e6) reject(new Error('Body too large')); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function safeParse(s) { try { return JSON.parse(s); } catch { return {}; } }

/* =====================================================================
   Auth — password hashing, sessions, cookies
   ===================================================================== */
function hashPassword(pw) {
  if (bcrypt) return bcrypt.hashSync(pw, 10);
  const salt = crypto.randomBytes(16).toString('hex');
  const dk = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `scrypt$${salt}$${dk}`;
}
function verifyPassword(pw, hash) {
  if (!hash) return false;
  if (hash.startsWith('scrypt$')) {
    const [, salt, dk] = hash.split('$');
    const calc = crypto.scryptSync(pw, salt, 64).toString('hex');
    return calc.length === dk.length &&
      crypto.timingSafeEqual(Buffer.from(dk, 'hex'), Buffer.from(calc, 'hex'));
  }
  return bcrypt ? bcrypt.compareSync(pw, hash) : false;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token,user_id,created_at,expires_at) VALUES (?,?,?,?)')
    .run(token, userId, now, now + SESSION_TTL);
  return token;
}
function getSessionUser(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if (!s) return null;
  if (s.expires_at < Date.now()) { db.prepare('DELETE FROM sessions WHERE token=?').run(token); return null; }
  return db.prepare('SELECT id,email,name,role,created_at FROM app_users WHERE id=?').get(s.user_id) || null;
}
function destroySession(req) {
  const token = parseCookies(req).sid;
  if (token) db.prepare('DELETE FROM sessions WHERE token=?').run(token);
}
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL / 1000)}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
}
const publicUser = u => ({ id: u.id, email: u.email, name: u.name, role: u.role, created_at: u.created_at });

/* =====================================================================
   Permissions — per-user, per-widget: 'none' | 'view' | 'edit'
   ===================================================================== */
const PERMS = ['none', 'view', 'edit'];
function userWidgetPerm(userId, widgetId) {
  const r = db.prepare('SELECT permission FROM widget_permissions WHERE user_id=? AND widget_id=?').get(userId, widgetId);
  return r ? r.permission : 'none';
}
function userWidgetPermMap(userId) {
  const map = {};
  db.prepare('SELECT widget_id, permission FROM widget_permissions WHERE user_id=?').all(userId)
    .forEach(r => { map[r.widget_id] = r.permission; });
  return map;
}
// Returns a filtered copy of the dashboard state for `user`. Owners/admins see
// everything (each widget tagged _perm:'edit'); everyone else sees only widgets
// they were granted view/edit, tagged with their permission.
function filterStateForUser(stateObj, user, ownerId) {
  if (!stateObj) return stateObj;
  const full = user.id === ownerId || user.role === 'admin';
  const perms = full ? null : userWidgetPermMap(user.id);
  (stateObj.views || []).forEach(v => {
    if (!Array.isArray(v.widgets)) return;
    v.widgets = v.widgets.filter(w => {
      if (full) { w._perm = 'edit'; return true; }
      const p = perms[w.id] || 'none';
      if (p === 'none') return false;
      w._perm = p;
      return true;
    });
  });
  return stateObj;
}
// Does the user have any view/edit grant on a widget in this dashboard?
function hasWidgetAccess(userId, stateObj) {
  const perms = userWidgetPermMap(userId);
  return (stateObj.views || []).some(v => (v.widgets || []).some(w => (perms[w.id] || 'none') !== 'none'));
}
// Every widget across every dashboard (for the admin visibility panel).
function collectAllWidgets() {
  const out = [];
  for (const d of db.prepare('SELECT id,title,state_json FROM dashboards').all()) {
    const st = safeParse(d.state_json);
    (st.views || []).forEach(v => (v.widgets || []).forEach(w => {
      if (w && w.id) out.push({ widget_id: w.id, title: w.title || w.type || w.id, dashboard_id: d.id, dashboard_title: d.title });
    }));
  }
  return out;
}

/* =====================================================================
   Saved DB connections — AES-256-GCM encryption at rest + live pool registry
   ===================================================================== */
const ENC_KEY = (() => {
  let row = db.prepare('SELECT value FROM app_meta WHERE key=?').get('enc_key');
  if (!row) {
    const k = process.env.APP_SECRET
      ? crypto.createHash('sha256').update(process.env.APP_SECRET).digest('hex')
      : crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO app_meta (key,value) VALUES (?,?)').run('enc_key', k);
    row = { value: k };
  }
  return Buffer.from(row.value, 'hex');
})();
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), enc.toString('hex')].join(':');
}
function decrypt(blob) {
  try {
    const [iv, tag, data] = String(blob).split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(iv, 'hex'));
    d.setAuthTag(Buffer.from(tag, 'hex'));
    return d.update(Buffer.from(data, 'hex'), undefined, 'utf8') + d.final('utf8');
  } catch { return ''; }
}

const livePools = new Map();   // connection id -> pg Pool
const connStatus = id => (livePools.has(id) ? 'connected' : 'disconnected');
// public shape — NEVER includes the password
const publicConn = r => ({ id: r.id, name: r.name, engine: r.engine, host: r.host, port: r.port, database: r.database, username: r.username, status: connStatus(r.id) });
function connectionString(r) {
  const pw = r.password_encrypted ? decrypt(r.password_encrypted) : '';
  const auth = r.username ? encodeURIComponent(r.username) + (pw ? ':' + encodeURIComponent(pw) : '') + '@' : '';
  return `postgres://${auth}${r.host || 'localhost'}:${r.port || 5432}/${r.database || 'postgres'}`;
}
function getPg() {
  try { return require('pg').Pool; }
  catch { return null; }
}

/* =====================================================================
   Server
   ===================================================================== */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  const m = req.method;

  // CORS preflight
  if (m === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  try {
    /* ---------------- Auth API (public) ---------------- */
    if (p === '/api/auth/signup' && m === 'POST') {
      const { email, password, name, role } = await readBody(req);
      const mail = String(email || '').trim().toLowerCase();
      if (!mail || !password) return sendJson(res, 400, { error: 'Email and password are required' });
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) return sendJson(res, 400, { error: 'Enter a valid email' });
      if (String(password).length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });
      if (db.prepare('SELECT id FROM app_users WHERE email=?').get(mail))
        return sendJson(res, 409, { error: 'An account with that email already exists' });

      const userCount = db.prepare('SELECT COUNT(*) n FROM app_users').get().n;
      const requester = getSessionUser(req);
      // First-ever user bootstraps as admin. Otherwise an admin may assign a
      // role when creating a user; everyone else defaults to viewer.
      let finalRole = 'viewer';
      if (userCount === 0) finalRole = 'admin';
      else if (role && requester && requester.role === 'admin' && ROLES.includes(role)) finalRole = role;

      const info = db.prepare('INSERT INTO app_users (email,password_hash,name,role,created_at) VALUES (?,?,?,?,?)')
        .run(mail, hashPassword(String(password)), String(name || '').trim(), finalRole, Date.now());
      const user = db.prepare('SELECT id,email,name,role,created_at FROM app_users WHERE id=?').get(Number(info.lastInsertRowid));
      // Log in the new user only when this is a self-signup (not an admin creating others).
      if (!requester) setSessionCookie(res, createSession(user.id));
      return sendJson(res, 200, { user });
    }

    if (p === '/api/auth/login' && m === 'POST') {
      const { email, password } = await readBody(req);
      const u = db.prepare('SELECT * FROM app_users WHERE email=?').get(String(email || '').trim().toLowerCase());
      if (!u || !verifyPassword(String(password || ''), u.password_hash))
        return sendJson(res, 401, { error: 'Invalid email or password' });
      setSessionCookie(res, createSession(u.id));
      return sendJson(res, 200, { user: publicUser(u) });
    }

    if (p === '/api/auth/logout' && m === 'POST') {
      destroySession(req);
      clearSessionCookie(res);
      return sendJson(res, 200, { ok: true });
    }

    if (p === '/api/auth/me' && m === 'GET') {
      const u = getSessionUser(req);
      if (!u) return sendJson(res, 401, { error: 'Not authenticated' });
      return sendJson(res, 200, { user: u });
    }

    /* ---------------- Public read-only share link (no login required) ------- */
    if (p.startsWith('/api/shared/') && m === 'GET') {
      const token = decodeURIComponent(p.slice('/api/shared/'.length));
      const row = db.prepare('SELECT * FROM dashboards WHERE share_token=?').get(token);
      if (!row) return sendJson(res, 404, { error: 'This shared link is invalid or has been revoked' });
      return sendJson(res, 200, { id: row.id, title: row.title, state: safeParse(row.state_json), readOnly: true });
    }

    /* ---------------- Session gate: every other /api/* needs a login ------- */
    const authUser = getSessionUser(req);
    if (p.startsWith('/api/') && !authUser)
      return sendJson(res, 401, { error: 'Not authenticated' });

    /* ---------------- API ---------------- */
    if (p === '/api/health' && m === 'GET')
      return sendJson(res, 200, { ok: true, engine: activeSource, time: Date.now() });

    if (p === '/api/tables' && m === 'GET')
      return sendJson(res, 200, { tables: await listTables() });

    if (p === '/api/query' && m === 'POST') {
      const { sql } = await readBody(req);
      if (!sql) return sendJson(res, 400, { error: 'sql is required' });
      return sendJson(res, 200, { rows: await runQuery(sql) });
    }

    if (p === '/api/datasets' && m === 'POST') {
      const { name, columns, rows } = await readBody(req);
      if (!name || !Array.isArray(columns) || !Array.isArray(rows))
        return sendJson(res, 400, { error: 'name, columns, rows required' });
      const result = createTable(name, columns, rows);
      activeSource = 'sqlite';   // newly created table lives in sqlite — make it visible
      return sendJson(res, 200, result);
    }

    /* ---------------- User directory (for sharing/grants) ---------------- */
    if (p === '/api/users' && m === 'GET') {
      const rows = db.prepare('SELECT id,name,email,role FROM app_users ORDER BY name, email').all();
      return sendJson(res, 200, { users: rows });
    }

    /* ---------------- Admin (admin-only) ---------------- */
    if (p.startsWith('/api/admin/')) {
      if (authUser.role !== 'admin') return sendJson(res, 403, { error: 'Admin only' });

      if (p === '/api/admin/users' && m === 'GET')
        return sendJson(res, 200, { users: db.prepare('SELECT id,email,name,role,created_at FROM app_users ORDER BY created_at').all() });

      if (p.match(/^\/api\/admin\/users\/\d+\/role$/) && m === 'PUT') {
        const uid = Number(p.split('/')[4]);
        const { role } = await readBody(req);
        if (!ROLES.includes(role)) return sendJson(res, 400, { error: 'Invalid role' });
        const target = db.prepare('SELECT * FROM app_users WHERE id=?').get(uid);
        if (!target) return sendJson(res, 404, { error: 'User not found' });
        // never leave the system with zero admins
        if (target.role === 'admin' && role !== 'admin') {
          const admins = db.prepare("SELECT COUNT(*) n FROM app_users WHERE role='admin'").get().n;
          if (admins <= 1) return sendJson(res, 400, { error: 'Cannot demote the last admin' });
        }
        db.prepare('UPDATE app_users SET role=? WHERE id=?').run(role, uid);
        return sendJson(res, 200, { ok: true });
      }

      if (p === '/api/admin/widgets' && m === 'GET')
        return sendJson(res, 200, { widgets: collectAllWidgets() });

      if (p === '/api/admin/permissions' && m === 'GET') {
        const uid = Number(url.searchParams.get('user_id'));
        const rows = db.prepare('SELECT widget_id,permission FROM widget_permissions WHERE user_id=?').all(uid);
        return sendJson(res, 200, { permissions: rows });
      }

      // Bulk save all per-widget grants for a user (used by the per-user modal).
      if (p === '/api/admin/permissions' && m === 'POST') {
        const { user_id, grants } = await readBody(req);
        if (!user_id || !Array.isArray(grants)) return sendJson(res, 400, { error: 'user_id and grants[] required' });
        const upsert = db.prepare(`INSERT INTO widget_permissions (widget_id,user_id,can_view,permission) VALUES (?,?,?,?)
                    ON CONFLICT(widget_id,user_id) DO UPDATE SET can_view=excluded.can_view, permission=excluded.permission`);
        const del = db.prepare('DELETE FROM widget_permissions WHERE widget_id=? AND user_id=?');
        db.exec('BEGIN');
        try {
          for (const g of grants) {
            const perm = PERMS.includes(g.permission) ? g.permission : 'none';
            if (perm === 'none') del.run(g.widget_id, Number(user_id));
            else upsert.run(g.widget_id, Number(user_id), perm === 'none' ? 0 : 1, perm);
          }
          db.exec('COMMIT');
        } catch (e) { db.exec('ROLLBACK'); throw e; }
        return sendJson(res, 200, { ok: true });
      }

      return sendJson(res, 404, { error: 'Unknown admin endpoint' });
    }

    /* ---------------- Saved DB connections (multi-connection) ---------------- */
    if (p === '/api/connections' && m === 'GET') {
      const rows = db.prepare('SELECT * FROM connections WHERE user_id=? ORDER BY created_at').all(authUser.id);
      return sendJson(res, 200, { connections: rows.map(publicConn) });   // never includes password
    }
    if (p === '/api/connections' && m === 'POST') {
      // every signed-in user manages their own connections
      const b = await readBody(req);
      if (!b.host || !b.database) return sendJson(res, 400, { error: 'host and database are required' });
      const id = 'conn_' + crypto.randomBytes(6).toString('hex');
      db.prepare(`INSERT INTO connections (id,user_id,name,engine,host,port,database,username,password_encrypted,created_at)
                  VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(id, authUser.id, String(b.name || b.database), 'postgres', String(b.host), Number(b.port) || 5432,
             String(b.database), String(b.username || ''), b.password ? encrypt(b.password) : null, Date.now());
      return sendJson(res, 200, { connection: publicConn(db.prepare('SELECT * FROM connections WHERE id=?').get(id)) });
    }
    if (p.startsWith('/api/connections/')) {
      const parts = p.split('/');               // ['', 'api', 'connections', ':id', 'action?']
      const cid = decodeURIComponent(parts[3] || '');
      const action = parts[4] || '';
      const row = db.prepare('SELECT * FROM connections WHERE id=?').get(cid);
      if (!row) return sendJson(res, 404, { error: 'Connection not found' });
      if (row.user_id !== authUser.id && authUser.role !== 'admin') return sendJson(res, 403, { error: 'Forbidden' });

      if (!action && m === 'DELETE') {
        const pool = livePools.get(cid); if (pool) { await pool.end().catch(() => {}); livePools.delete(cid); }
        db.prepare('DELETE FROM connections WHERE id=?').run(cid);
        return sendJson(res, 200, { ok: true });
      }
      if (action === 'connect' && m === 'POST') {
        const Pool = getPg();
        if (!Pool) return sendJson(res, 500, { error: 'Postgres support not installed (npm install pg)' });
        const pool = new Pool({ connectionString: connectionString(row), connectionTimeoutMillis: 8000 });
        try {
          await pool.query('SELECT 1');
          const old = livePools.get(cid); if (old) await old.end().catch(() => {});
          livePools.set(cid, pool);
          return sendJson(res, 200, { status: 'connected', connection: publicConn(row) });
        } catch (e) {
          await pool.end().catch(() => {});
          return sendJson(res, 400, { error: 'Connection failed: ' + e.message });   // note: e.message never contains the password
        }
      }
      if (action === 'disconnect' && m === 'POST') {
        const pool = livePools.get(cid); if (pool) { await pool.end().catch(() => {}); livePools.delete(cid); }
        return sendJson(res, 200, { status: 'disconnected' });
      }
      if (action === 'tables' && m === 'GET') {
        const pool = livePools.get(cid);
        if (!pool) return sendJson(res, 409, { error: 'Connection is not active' });
        const t = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name`);
        const out = [];
        for (const tr of t.rows) {
          const c = await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position`, [tr.table_name]);
          out.push({ name: tr.table_name, columns: c.rows.map(x => x.column_name) });
        }
        return sendJson(res, 200, { tables: out });
      }
      if (action === 'query' && m === 'POST') {
        const pool = livePools.get(cid);
        if (!pool) return sendJson(res, 409, { error: 'Connection is not active' });
        const { sql } = await readBody(req);
        if (!isReadOnly(sql)) return sendJson(res, 400, { error: 'Only read-only SELECT queries are allowed.' });
        const r = await pool.query(sql);
        return sendJson(res, 200, { rows: r.rows });
      }
      return sendJson(res, 404, { error: 'Unknown connection endpoint' });
    }

    /* ---------------- Dashboards (hybrid: private-by-default + sharing) ----------------
       Model:
        - Every user privately OWNS their dashboards and has full control of them.
        - An owner may mark a dashboard 'shared' so others can view it.
        - editor can edit others' shared dashboards; viewer can only view them.
        - admin has full control over everything (sees/edits/deletes all, can
          change any dashboard's visibility).
    */
    const isAdminUser = authUser && authUser.role === 'admin';
    if (p === '/api/dashboards' && m === 'GET') {
      // Own dashboards + any shared-with-everyone + any granted to me (admins: all).
      const rows = isAdminUser
        ? db.prepare('SELECT id,title,owner_id,visibility,share_token,updated_at FROM dashboards ORDER BY updated_at DESC').all()
        : db.prepare(`SELECT id,title,owner_id,visibility,share_token,updated_at FROM dashboards
                      WHERE owner_id=? OR visibility='shared'
                         OR id IN (SELECT dashboard_id FROM dashboard_grants WHERE user_id=?)
                      ORDER BY updated_at DESC`).all(authUser.id, authUser.id);
      return sendJson(res, 200, { dashboards: rows.map(r => ({ ...r, mine: r.owner_id === authUser.id })) });
    }

    if (p === '/api/dashboards' && m === 'POST') {
      // Anyone signed in can create their OWN dashboard (they fully own it).
      const d = await readBody(req);
      const id = 'dash_' + crypto.randomBytes(6).toString('hex');
      const now = Date.now();
      const vis = d.visibility === 'shared' ? 'shared' : 'private';
      db.prepare('INSERT INTO dashboards (id,owner_id,title,state_json,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?)')
        .run(id, authUser.id, String(d.title || 'Untitled dashboard'), JSON.stringify(d.state || {}), vis, now, now);
      return sendJson(res, 200, { id, title: d.title || 'Untitled dashboard', owner_id: authUser.id, visibility: vis, created_at: now, updated_at: now });
    }

    if (p.startsWith('/api/dashboards/')) {
      const parts = p.split('/');                 // ['', 'api', 'dashboards', ':id', 'action?']
      const id = decodeURIComponent(parts[3] || '');
      const action = parts[4] || '';
      const row = db.prepare('SELECT * FROM dashboards WHERE id=?').get(id);
      if (!row) return sendJson(res, 404, { error: 'Dashboard not found' });
      const isOwner = row.owner_id === authUser.id;
      const isShared = row.visibility === 'shared';
      const isGranted = !!db.prepare('SELECT 1 FROM dashboard_grants WHERE dashboard_id=? AND user_id=?').get(id, authUser.id);
      let mayView = isOwner || isAdminUser || isShared || isGranted;
      if (!mayView) mayView = hasWidgetAccess(authUser.id, safeParse(row.state_json));  // per-widget grants grant access
      const mayEdit = isOwner || isAdminUser;      // dashboard-level edit; per-widget edit handled below

      /* --- base dashboard resource --- */
      if (!action && m === 'GET') {
        if (!mayView) return sendJson(res, 403, { error: 'You do not have access to this dashboard' });
        const stateObj = filterStateForUser(safeParse(row.state_json), authUser, row.owner_id);   // per-user widget filtering + _perm tags
        return sendJson(res, 200, { id: row.id, title: row.title, state: stateObj, owner_id: row.owner_id, visibility: row.visibility, share_token: (isOwner || isAdminUser) ? row.share_token : undefined, canEdit: mayEdit, updated_at: row.updated_at });
      }
      if (!action && m === 'PUT') {
        if (!mayEdit) return sendJson(res, 403, { error: 'You do not have permission to edit this dashboard' });
        const d = await readBody(req);
        const title = d.title !== undefined ? String(d.title) : row.title;
        const stateJson = d.state !== undefined ? JSON.stringify(d.state) : row.state_json;
        let vis = row.visibility;
        if (d.visibility !== undefined) vis = d.visibility === 'shared' ? 'shared' : 'private';
        const now = Date.now();
        db.prepare('UPDATE dashboards SET title=?, state_json=?, visibility=?, updated_at=? WHERE id=?').run(title, stateJson, vis, now, id);
        return sendJson(res, 200, { ok: true, id, visibility: vis, updated_at: now });
      }
      if (!action && m === 'DELETE') {
        if (!mayEdit) return sendJson(res, 403, { error: 'Only the owner or an admin can delete this dashboard' });
        db.prepare('DELETE FROM dashboards WHERE id=?').run(id);
        db.prepare('DELETE FROM dashboard_grants WHERE dashboard_id=?').run(id);
        return sendJson(res, 200, { ok: true });
      }

      /* --- share link (owner/admin) --- */
      if (action === 'share') {
        if (!mayEdit) return sendJson(res, 403, { error: 'Only the owner or an admin can share' });
        if (m === 'POST') {                        // create/rotate a public read-only link
          const token = 'shr_' + crypto.randomBytes(12).toString('hex');
          db.prepare('UPDATE dashboards SET share_token=? WHERE id=?').run(token, id);
          return sendJson(res, 200, { share_token: token });
        }
        if (m === 'DELETE') {                       // revoke
          db.prepare('UPDATE dashboards SET share_token=NULL WHERE id=?').run(id);
          return sendJson(res, 200, { ok: true });
        }
      }

      /* --- per-user read-only grants (owner/admin) --- */
      if (action === 'grants') {
        if (!mayEdit) return sendJson(res, 403, { error: 'Only the owner or an admin can manage access' });
        if (m === 'GET') {
          const ids = db.prepare('SELECT user_id FROM dashboard_grants WHERE dashboard_id=?').all(id).map(r => r.user_id);
          return sendJson(res, 200, { user_ids: ids });
        }
        if (m === 'POST') {
          const { user_id, granted } = await readBody(req);
          if (granted) db.prepare('INSERT OR IGNORE INTO dashboard_grants (dashboard_id,user_id) VALUES (?,?)').run(id, Number(user_id));
          else db.prepare('DELETE FROM dashboard_grants WHERE dashboard_id=? AND user_id=?').run(id, Number(user_id));
          return sendJson(res, 200, { ok: true });
        }
      }

      /* --- single-widget edit/delete: owner/admin OR a user granted 'edit' --- */
      if (action === 'widgets') {
        const wid = decodeURIComponent(parts[5] || '');
        const canEditWidget = mayEdit || userWidgetPerm(authUser.id, wid) === 'edit';
        if (!canEditWidget) return sendJson(res, 403, { error: 'You do not have edit access to this widget' });
        const state = safeParse(row.state_json);
        let found = null, ownerView = null;
        for (const v of (state.views || [])) { const w = (v.widgets || []).find(x => x.id === wid); if (w) { found = w; ownerView = v; break; } }
        if (m === 'PUT') {
          const { widget } = await readBody(req);
          if (!widget) return sendJson(res, 400, { error: 'widget required' });
          if (!found) return sendJson(res, 404, { error: 'Widget not found' });
          Object.assign(found, widget, { id: wid });        // never allow the id to change
          db.prepare('UPDATE dashboards SET state_json=?, updated_at=? WHERE id=?').run(JSON.stringify(state), Date.now(), id);
          return sendJson(res, 200, { ok: true });
        }
        if (m === 'DELETE') {
          if (ownerView) ownerView.widgets = ownerView.widgets.filter(x => x.id !== wid);
          db.prepare('DELETE FROM widget_permissions WHERE widget_id=?').run(wid);
          db.prepare('UPDATE dashboards SET state_json=?, updated_at=? WHERE id=?').run(JSON.stringify(state), Date.now(), id);
          return sendJson(res, 200, { ok: true });
        }
      }
      return sendJson(res, 404, { error: 'Unknown dashboard endpoint' });
    }

    if (p === '/api/clear' && m === 'POST') {
      const { table } = await readBody(req);
      if (table) db.exec(`DROP TABLE IF EXISTS "${sanitize(table)}"`);
      return sendJson(res, 200, { ok: true });
    }

    if (p === '/api/connect' && m === 'POST') {
      const { connectionString } = await readBody(req);
      if (!connectionString) return sendJson(res, 400, { error: 'connectionString required' });
      let Pool;
      try { ({ Pool } = require('pg')); }
      catch { return sendJson(res, 500, { error: 'Postgres support not installed (run: npm install pg)' }); }
      const pool = new Pool({ connectionString, connectionTimeoutMillis: 8000 });
      try {
        await pool.query('SELECT 1');           // verify the connection works
        if (pgPool) await pgPool.end().catch(() => {});
        pgPool = pool;
        activeSource = 'postgres';
        return sendJson(res, 200, { ok: true, engine: 'postgres' });
      } catch (e) {
        await pool.end().catch(() => {});
        return sendJson(res, 400, { error: 'Connection failed: ' + e.message });
      }
    }

    if (p === '/api/disconnect' && m === 'POST') {
      // End any live DB connection and fall back to the default sqlite source.
      // Called on every page load so a refresh never reuses a stale connection.
      if (pgPool) { await pgPool.end().catch(() => {}); pgPool = null; }
      activeSource = 'sqlite';
      return sendJson(res, 200, { ok: true, engine: 'sqlite' });
    }

    if (p.startsWith('/api/'))
      return sendJson(res, 404, { error: 'Unknown endpoint' });

    /* ---------------- Static files ---------------- */
    // Pretty routes
    let rel = p;
    if (p === '/' )       rel = '/dashboard.html';
    else if (p === '/login')  rel = '/login.html';
    else if (p === '/signup') rel = '/signup.html';
    else if (p.startsWith('/view/')) rel = '/dashboard.html';   // public read-only share link

    // The dashboard requires login — EXCEPT the public /view/<token> read-only route.
    if (rel === '/dashboard.html' && !authUser && !p.startsWith('/view/')) {
      res.writeHead(302, { Location: '/login' });
      return res.end();
    }

    let filePath = path.normalize(path.join(ROOT, decodeURIComponent(rel)));
    if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end('Forbidden'); }
    fs.readFile(filePath, (err, buf) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
      res.end(buf);
    });
  } catch (e) {
    sendJson(res, 500, { error: e.message });
  }
});

seed();
server.listen(PORT, () => {
  console.log(`Nexus Analytics running on http://localhost:${PORT}`);
  console.log(`  Data source: sqlite (${DB_FILE})`);
  console.log(`  Auth: ${bcrypt ? 'bcryptjs' : 'scrypt (bcryptjs not installed)'} · sessions in sqlite`);
  console.log(`  API: /api/auth/(signup|login|logout|me)  /api/tables  /api/query  /api/dashboards  /api/connect`);
});

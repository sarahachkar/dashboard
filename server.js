
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
const PERMISSIONS = ['viewer', 'editor'];
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
// account_type: 'admin' | 'user'. permission: 'viewer' | 'editor' (NULL for admins).
db.exec(`CREATE TABLE IF NOT EXISTS app_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  account_type TEXT NOT NULL DEFAULT 'user',
  permission TEXT,
  last_active INTEGER,
  created_at INTEGER NOT NULL
)`);
// Migrate the old single `role` column → account_type + permission.
try {
  const cols = db.prepare('PRAGMA table_info(app_users)').all().map(c => c.name);
  if (!cols.includes('account_type')) db.exec("ALTER TABLE app_users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'user'");
  if (!cols.includes('permission'))   db.exec('ALTER TABLE app_users ADD COLUMN permission TEXT');
  if (!cols.includes('last_active'))  db.exec('ALTER TABLE app_users ADD COLUMN last_active INTEGER');
  if (cols.includes('role')) {
    db.exec("UPDATE app_users SET account_type='admin', permission=NULL WHERE role='admin'");
    db.exec("UPDATE app_users SET account_type='user', permission='editor' WHERE role='editor'");
    db.exec("UPDATE app_users SET account_type='user', permission='viewer' WHERE role='viewer'");
  }
} catch { /* fresh db already matches */ }
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
// Per-dashboard, per-user permission: 'view' | 'edit' (admin/owner grants it).
db.exec(`CREATE TABLE IF NOT EXISTS dashboard_permissions (
  dashboard_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  permission TEXT NOT NULL DEFAULT 'view',
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
// In-app notifications (e.g. "the admin shared a graph with you").
db.exec(`CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  link TEXT,
  read INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
)`);
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
  const u = db.prepare('SELECT id,email,name,account_type,permission,last_active,created_at FROM app_users WHERE id=?').get(s.user_id);
  if (u) { const now = Date.now(); if (!u.last_active || now - u.last_active > 60000) db.prepare('UPDATE app_users SET last_active=? WHERE id=?').run(now, u.id); }
  return u || null;
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
const publicUser = u => ({ id: u.id, email: u.email, name: u.name, account_type: u.account_type, permission: u.permission, last_active: u.last_active, created_at: u.created_at });

/* =====================================================================
   Account model + reusable auth guards
     account_type: 'admin' | 'user'
     permission (users only): 'viewer' | 'editor'
   ===================================================================== */
const isAdminAcct = u => !!u && u.account_type === 'admin';
const canEditAcct = u => !!u && (u.account_type === 'admin' || u.permission === 'editor');
// Guard middlewares: return true if allowed; otherwise send an opaque 403.
function requireAdmin(u, res) { if (!isAdminAcct(u)) { sendJson(res, 403, { error: 'Forbidden' }); return false; } return true; }
function requireEditorOrAdmin(u, res) { if (!canEditAcct(u)) { sendJson(res, 403, { error: 'Forbidden' }); return false; } return true; }

/* =====================================================================
   Graph-access grants — admin grants a user access to specific widgets.
   Access is boolean (a row = granted); whether that access is view or edit
   is decided by the account's permission (viewer→view, editor→edit).
   ===================================================================== */
// Per-widget permission for a user: { widget_id: 'viewer' | 'editor' }.
function userWidgetPermMap(userId) {
  const map = {};
  db.prepare('SELECT widget_id, permission FROM widget_permissions WHERE user_id=?').all(userId)
    .forEach(r => { map[r.widget_id] = r.permission; });
  return map;
}
// Filtered copy of dashboard state for `user`. Owners/admins see all (editable);
// everyone else sees ONLY widgets with an explicit permission row, and their
// capability is that row's permission (viewer→view, editor→edit).
function filterStateForUser(stateObj, user, ownerId) {
  if (!stateObj) return stateObj;
  const full = user.id === ownerId || isAdminAcct(user);
  const perms = full ? null : userWidgetPermMap(user.id);
  (stateObj.views || []).forEach(v => {
    if (!Array.isArray(v.widgets)) return;
    v.widgets = v.widgets.filter(w => {
      if (full) { w._perm = 'edit'; return true; }
      const p = perms[w.id];
      if (!p) return false;                          // no row = no access, hidden
      w._perm = p === 'editor' ? 'edit' : 'view';
      return true;
    });
  });
  return stateObj;
}
function hasWidgetAccess(userId, stateObj) {
  const perms = userWidgetPermMap(userId);
  return (stateObj.views || []).some(v => (v.widgets || []).some(w => !!perms[w.id]));
}
function stateHasGrantedWidget(stateJson, permMap) {
  return (safeParse(stateJson).views || []).some(v => (v.widgets || []).some(w => !!permMap[w.id]));
}
function notify(userId, message, link) {
  db.prepare('INSERT INTO notifications (user_id,message,link,read,created_at) VALUES (?,?,?,0,?)')
    .run(userId, message, link || null, Date.now());
}
// A user's granted permission on a dashboard ('view' | 'edit' | null).
function dashboardPermFor(dashId, userId) {
  const r = db.prepare('SELECT permission FROM dashboard_permissions WHERE dashboard_id=? AND user_id=?').get(dashId, userId);
  return r ? r.permission : null;
}
// Every widget across every dashboard (for the admin visibility panel).
function collectAllWidgets() {
  const out = [];
  for (const d of db.prepare('SELECT id,title,state_json FROM dashboards').all()) {
    const st = safeParse(d.state_json);
    (st.views || []).forEach(v => (v.widgets || []).forEach(w => {
      if (w && w.id) out.push({ widget_id: w.id, title: w.title || w.type || w.id, type: w.type || 'bar', dashboard_id: d.id, dashboard_title: d.title });
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
      const { email, password, name } = await readBody(req);
      const mail = String(email || '').trim().toLowerCase();
      if (!mail || !password) return sendJson(res, 400, { error: 'Email and password are required' });
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) return sendJson(res, 400, { error: 'Enter a valid email' });
      if (String(password).length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });
      if (db.prepare('SELECT id FROM app_users WHERE email=?').get(mail))
        return sendJson(res, 409, { error: 'An account with that email already exists' });

      // First-ever account is the admin. Every other account is a regular
      // user who is the full owner ("admin") of their own single dashboard —
      // cross-user graph access is controlled per-graph by the admin.
      const isFirst = db.prepare('SELECT COUNT(*) n FROM app_users').get().n === 0;
      const account_type = isFirst ? 'admin' : 'user';
      const permission = isFirst ? null : 'editor';
      const now = Date.now();
      const info = db.prepare('INSERT INTO app_users (email,password_hash,name,account_type,permission,last_active,created_at) VALUES (?,?,?,?,?,?,?)')
        .run(mail, hashPassword(String(password)), String(name || '').trim(), account_type, permission, now, now);
      const user = db.prepare('SELECT id,email,name,account_type,permission,created_at FROM app_users WHERE id=?').get(Number(info.lastInsertRowid));
      setSessionCookie(res, createSession(user.id));
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

    /* ---------------- Notifications ---------------- */
    if (p === '/api/notifications' && m === 'GET') {
      const rows = db.prepare('SELECT id,message,link,read,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(authUser.id);
      return sendJson(res, 200, { notifications: rows, unread: rows.filter(r => !r.read).length });
    }
    if (p === '/api/notifications/read' && m === 'POST') {
      db.prepare('UPDATE notifications SET read=1 WHERE user_id=?').run(authUser.id);
      return sendJson(res, 200, { ok: true });
    }

    /* ---------------- User directory (for sharing) ---------------- */
    if (p === '/api/users' && m === 'GET') {
      const rows = db.prepare('SELECT id,name,email,account_type,permission FROM app_users ORDER BY name, email').all();
      return sendJson(res, 200, { users: rows });
    }

    /* ---------------- Admin (admin accounts only) ---------------- */
    if (p.startsWith('/api/admin/')) {
      if (!requireAdmin(authUser, res)) return;

      // Everyone who isn't an admin is manageable here (NULL/legacy → treated as user).
      if (p === '/api/admin/users' && m === 'GET')
        return sendJson(res, 200, { users: db.prepare("SELECT id,email,name,permission,last_active,created_at FROM app_users WHERE account_type IS NULL OR account_type <> 'admin' ORDER BY created_at").all() });

      // Dashboards created by a specific user (admin enters that user's space).
      if (p.match(/^\/api\/admin\/users\/\d+\/dashboards$/) && m === 'GET') {
        const uid = Number(p.split('/')[4]);
        const rows = db.prepare('SELECT id,title,owner_id,updated_at FROM dashboards WHERE owner_id=? ORDER BY updated_at DESC').all(uid);
        return sendJson(res, 200, { dashboards: rows });
      }

      // Set a user's permission (viewer|editor). Admins cannot be edited here.
      if (p.match(/^\/api\/admin\/users\/\d+\/permission$/) && m === 'PATCH') {
        const uid = Number(p.split('/')[4]);
        const { permission } = await readBody(req);
        if (!PERMISSIONS.includes(permission)) return sendJson(res, 400, { error: 'Invalid permission' });
        const target = db.prepare('SELECT * FROM app_users WHERE id=?').get(uid);
        if (!target || target.account_type !== 'user') return sendJson(res, 404, { error: 'User not found' });
        db.prepare('UPDATE app_users SET permission=? WHERE id=?').run(permission, uid);
        return sendJson(res, 200, { ok: true });
      }

      if (p === '/api/admin/widgets' && m === 'GET')
        return sendJson(res, 200, { widgets: collectAllWidgets() });

      // Which widgets a user is granted access to.
      // A user's per-graph permission rows: [{ widget_id, permission }].
      if (p === '/api/admin/permissions' && m === 'GET') {
        const uid = Number(url.searchParams.get('user_id'));
        const rows = db.prepare('SELECT widget_id, permission FROM widget_permissions WHERE user_id=?').all(uid);
        return sendJson(res, 200, { permissions: rows });
      }

      // Replace ALL of a user's graph permissions at once. Any widget not in
      // the list gets NO access (its row is removed).
      if (p.match(/^\/api\/admin\/users\/\d+\/permissions$/) && m === 'PATCH') {
        const uid = Number(p.split('/')[4]);
        const target = db.prepare('SELECT account_type FROM app_users WHERE id=?').get(uid);
        if (!target || target.account_type !== 'user') return sendJson(res, 404, { error: 'User not found' });
        const { permissions } = await readBody(req);
        if (!Array.isArray(permissions)) return sendJson(res, 400, { error: 'permissions[] required' });
        // remember what they had before, so we can notify only on NEW grants
        const before = {};
        db.prepare('SELECT widget_id, permission FROM widget_permissions WHERE user_id=?').all(uid)
          .forEach(r => { before[r.widget_id] = r.permission; });
        const ins = db.prepare(`INSERT INTO widget_permissions (widget_id,user_id,can_view,permission) VALUES (?,?,1,?)
                    ON CONFLICT(widget_id,user_id) DO UPDATE SET permission=excluded.permission`);
        db.exec('BEGIN');
        try {
          db.prepare('DELETE FROM widget_permissions WHERE user_id=?').run(uid);   // clear then re-add
          for (const r of permissions) {
            const perm = PERMISSIONS.includes(r.permission) ? r.permission : 'viewer';
            if (r.widget_id) ins.run(String(r.widget_id), uid, perm);
          }
          db.exec('COMMIT');
        } catch (e) { db.exec('ROLLBACK'); throw e; }
        // Notify the user about graphs newly shared with them (or access changed).
        const info = {}; collectAllWidgets().forEach(w => { info[w.widget_id] = w; });
        for (const r of permissions) {
          const perm = PERMISSIONS.includes(r.permission) ? r.permission : 'viewer';
          if (before[r.widget_id] !== perm) {
            const w = info[r.widget_id];
            const cap = perm === 'editor' ? 'edit' : 'view';
            notify(uid, `You were given ${cap} access to “${(w && w.title) || 'a graph'}”`, w ? w.dashboard_id : null);
          }
        }
        return sendJson(res, 200, { ok: true });
      }

      return sendJson(res, 404, { error: 'Forbidden' });
    }

    /* ---------------- Saved DB connections (multi-connection) ---------------- */
    if (p === '/api/connections' && m === 'GET') {
      const rows = db.prepare('SELECT * FROM connections WHERE user_id=? ORDER BY created_at').all(authUser.id);
      return sendJson(res, 200, { connections: rows.map(publicConn) });   // never includes password
    }
    if (p === '/api/connections' && m === 'POST') {
      if (!requireEditorOrAdmin(authUser, res)) return;   // viewers cannot add connections
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
      if (row.user_id !== authUser.id && !isAdminAcct(authUser)) return sendJson(res, 403, { error: 'Forbidden' });

      if (!action && m === 'DELETE') {
        const pool = livePools.get(cid); if (pool) { await pool.end().catch(() => {}); livePools.delete(cid); }
        db.prepare('DELETE FROM connections WHERE id=?').run(cid);
        return sendJson(res, 200, { ok: true });
      }
      if (action === 'connect' && m === 'POST') {
        if (!requireEditorOrAdmin(authUser, res)) return;   // viewers cannot open connections
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
        if (!requireEditorOrAdmin(authUser, res)) return;   // viewers cannot disconnect
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

    /* ---------------- Dashboards (per-dashboard permissions) ----------------
       Model:
        - Every user can create MANY dashboards and fully owns/edits their own.
        - An admin can view (and edit) all dashboards.
        - On any dashboard, the owner or an admin grants each user a per-dashboard
          permission: 'view' (read-only) or 'edit'.
    */
    const isAdminUser = isAdminAcct(authUser);
    if (p === '/api/dashboards' && m === 'GET') {
      const rows = isAdminUser
        ? db.prepare('SELECT id,title,owner_id,share_token,updated_at FROM dashboards ORDER BY updated_at DESC').all()
        : db.prepare(`SELECT id,title,owner_id,share_token,updated_at FROM dashboards
                      WHERE owner_id=? OR id IN (SELECT dashboard_id FROM dashboard_permissions WHERE user_id=?)
                      ORDER BY updated_at DESC`).all(authUser.id, authUser.id);
      return sendJson(res, 200, { dashboards: rows.map(r => ({ ...r, mine: r.owner_id === authUser.id })) });
    }

    if (p === '/api/dashboards' && m === 'POST') {
      if (!requireEditorOrAdmin(authUser, res)) return;
      const d = await readBody(req);
      const id = 'dash_' + crypto.randomBytes(6).toString('hex');
      const now = Date.now();
      db.prepare('INSERT INTO dashboards (id,owner_id,title,state_json,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?)')
        .run(id, authUser.id, String(d.title || 'My Dashboard'), JSON.stringify(d.state || {}), 'private', now, now);
      return sendJson(res, 200, { id, title: d.title || 'My Dashboard', owner_id: authUser.id, created_at: now, updated_at: now });
    }

    if (p.startsWith('/api/dashboards/')) {
      const parts = p.split('/');                 // ['', 'api', 'dashboards', ':id', 'action?']
      const id = decodeURIComponent(parts[3] || '');
      const action = parts[4] || '';
      const row = db.prepare('SELECT * FROM dashboards WHERE id=?').get(id);
      if (!row) return sendJson(res, 404, { error: 'Dashboard not found' });
      const isOwner = row.owner_id === authUser.id;
      const dperm = (isOwner || isAdminUser) ? 'edit' : dashboardPermFor(id, authUser.id);   // 'view' | 'edit' | null
      const mayView = !!dperm;
      const mayEdit = isOwner || isAdminUser || dperm === 'edit';

      /* --- base dashboard resource --- */
      if (!action && m === 'GET') {
        if (!mayView) return sendJson(res, 403, { error: 'Forbidden' });
        const st = safeParse(row.state_json);
        const cap = mayEdit ? 'edit' : 'view';
        (st.views || []).forEach(v => (v.widgets || []).forEach(w => { w._perm = cap; }));   // per-dashboard capability
        return sendJson(res, 200, { id: row.id, title: row.title, state: st, owner_id: row.owner_id, share_token: (isOwner || isAdminUser) ? row.share_token : undefined, canEdit: mayEdit, updated_at: row.updated_at });
      }
      if (!action && m === 'PUT') {
        if (!mayEdit) return sendJson(res, 403, { error: 'Forbidden' });
        const d = await readBody(req);
        const title = d.title !== undefined ? String(d.title) : row.title;
        const stateJson = d.state !== undefined ? JSON.stringify(d.state) : row.state_json;
        const now = Date.now();
        db.prepare('UPDATE dashboards SET title=?, state_json=?, updated_at=? WHERE id=?').run(title, stateJson, now, id);
        return sendJson(res, 200, { ok: true, id, updated_at: now });
      }
      if (!action && m === 'DELETE') {
        if (!(isOwner || isAdminUser)) return sendJson(res, 403, { error: 'Forbidden' });
        db.prepare('DELETE FROM dashboards WHERE id=?').run(id);
        db.prepare('DELETE FROM dashboard_permissions WHERE dashboard_id=?').run(id);
        return sendJson(res, 200, { ok: true });
      }

      /* --- public share link (ADMIN ONLY — only the admin manages sharing) --- */
      if (action === 'share') {
        if (!requireAdmin(authUser, res)) return;
        if (m === 'POST') {
          const token = 'shr_' + crypto.randomBytes(12).toString('hex');
          db.prepare('UPDATE dashboards SET share_token=? WHERE id=?').run(token, id);
          return sendJson(res, 200, { share_token: token });
        }
        if (m === 'DELETE') { db.prepare('UPDATE dashboards SET share_token=NULL WHERE id=?').run(id); return sendJson(res, 200, { ok: true }); }
      }

      /* --- per-user permissions ON THIS dashboard (ADMIN ONLY) --- */
      if (action === 'permissions') {
        if (!requireAdmin(authUser, res)) return;
        if (m === 'GET') {
          const users = db.prepare("SELECT id,name,email FROM app_users WHERE account_type IS NULL OR account_type <> 'admin'").all()
            .filter(u => u.id !== row.owner_id);
          const pm = {}; db.prepare('SELECT user_id,permission FROM dashboard_permissions WHERE dashboard_id=?').all(id).forEach(r => { pm[r.user_id] = r.permission; });
          return sendJson(res, 200, { users: users.map(u => ({ ...u, permission: pm[u.id] || 'none' })) });
        }
        if (m === 'POST') {
          const { user_id, permission } = await readBody(req);
          const before = dashboardPermFor(id, Number(user_id));
          if (permission === 'view' || permission === 'edit') {
            db.prepare(`INSERT INTO dashboard_permissions (dashboard_id,user_id,permission) VALUES (?,?,?)
                        ON CONFLICT(dashboard_id,user_id) DO UPDATE SET permission=excluded.permission`).run(id, Number(user_id), permission);
            if (before !== permission) notify(Number(user_id), `You were given ${permission} access to the dashboard “${row.title}”`, id);
          } else {
            db.prepare('DELETE FROM dashboard_permissions WHERE dashboard_id=? AND user_id=?').run(id, Number(user_id));
          }
          return sendJson(res, 200, { ok: true });
        }
      }

      /* --- single-widget edit/delete (owner/admin/edit) --- */
      if (action === 'widgets') {
        const wid = decodeURIComponent(parts[5] || '');
        if (!mayEdit) return sendJson(res, 403, { error: 'Forbidden' });
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


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
db.exec(`CREATE TABLE IF NOT EXISTS users (
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

/* Tables that are app-internal, not user data sources */
const INTERNAL = new Set(['app_dashboards', 'sqlite_sequence']);

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
  return db.prepare('SELECT id,email,name,role,created_at FROM users WHERE id=?').get(s.user_id) || null;
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
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
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
      if (db.prepare('SELECT id FROM users WHERE email=?').get(mail))
        return sendJson(res, 409, { error: 'An account with that email already exists' });

      const userCount = db.prepare('SELECT COUNT(*) n FROM users').get().n;
      const requester = getSessionUser(req);
      // First-ever user bootstraps as admin. Otherwise an admin may assign a
      // role when creating a user; everyone else defaults to viewer.
      let finalRole = 'viewer';
      if (userCount === 0) finalRole = 'admin';
      else if (role && requester && requester.role === 'admin' && ROLES.includes(role)) finalRole = role;

      const info = db.prepare('INSERT INTO users (email,password_hash,name,role,created_at) VALUES (?,?,?,?,?)')
        .run(mail, hashPassword(String(password)), String(name || '').trim(), finalRole, Date.now());
      const user = db.prepare('SELECT id,email,name,role,created_at FROM users WHERE id=?').get(Number(info.lastInsertRowid));
      // Log in the new user only when this is a self-signup (not an admin creating others).
      if (!requester) setSessionCookie(res, createSession(user.id));
      return sendJson(res, 200, { user });
    }

    if (p === '/api/auth/login' && m === 'POST') {
      const { email, password } = await readBody(req);
      const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(email || '').trim().toLowerCase());
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

    if (p === '/api/dashboards' && m === 'GET') {
      const rows = db.prepare('SELECT id,name,state,updated FROM app_dashboards ORDER BY updated DESC').all();
      return sendJson(res, 200, { dashboards: rows.map(r => ({ ...r, state: safeParse(r.state) })) });
    }

    if (p === '/api/dashboards' && m === 'POST') {
      const d = await readBody(req);
      const id = d.id || 'dash_' + Math.random().toString(36).slice(2, 10);
      db.prepare(`INSERT INTO app_dashboards (id,name,state,updated) VALUES (?,?,?,?)
                  ON CONFLICT(id) DO UPDATE SET name=excluded.name, state=excluded.state, updated=excluded.updated`)
        .run(id, d.name || 'Untitled', JSON.stringify(d.state || {}), Date.now());
      return sendJson(res, 200, { ok: true, id });
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
    // Pretty routes for the auth pages
    let rel = p;
    if (p === '/' )       rel = '/dashboard.html';
    else if (p === '/login')  rel = '/login.html';
    else if (p === '/signup') rel = '/signup.html';

    // The dashboard requires a logged-in session; bounce guests to /login.
    if (rel === '/dashboard.html' && !authUser) {
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

/* =====================================================================
   Nexus Analytics — backend
   Zero-dependency core: Node's built-in HTTP server + node:sqlite.
   Optional Postgres support (via the `pg` package) for "Connect DB".

   Run:  node --experimental-sqlite server.js     (Node >= 22.5)
   ===================================================================== */
'use strict';

const http = require('node:http');
const fs   = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DB_FILE = path.join(ROOT, 'nexus.db');

/* =====================================================================
   SQLite (default data source + app storage)
   ===================================================================== */
const db = new DatabaseSync(DB_FILE);
db.exec(`CREATE TABLE IF NOT EXISTS app_dashboards (
  id TEXT PRIMARY KEY, name TEXT, state TEXT, updated INTEGER
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
    let filePath = p === '/' ? '/dashboard.html' : decodeURIComponent(p);
    filePath = path.normalize(path.join(ROOT, filePath));
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
  console.log(`  API: /api/health  /api/tables  /api/query  /api/datasets  /api/dashboards  /api/connect`);
});

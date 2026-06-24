/* =====================================================================
   Nexus Analytics — backend server
   Zero npm dependencies. Uses Node's built-in node:sqlite for REAL SQL
   execution, with a pure-JS in-memory engine as automatic fallback.

   Run:   node --experimental-sqlite server.js
   or:    npm start
   Then open http://localhost:4000
   ===================================================================== */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000;
const DB_FILE = path.join(__dirname, 'nexus.db');
const ROOT = __dirname;

/* ---------------------------------------------------------------------
   Storage layer: try real SQLite, fall back to in-memory JS engine
   --------------------------------------------------------------------- */
let store;
try {
  const { DatabaseSync } = require('node:sqlite');
  store = sqliteStore(new DatabaseSync(DB_FILE));
  console.log('✔ Storage: node:sqlite (real SQL) →', DB_FILE);
} catch (e) {
  console.log('⚠ node:sqlite unavailable (' + e.message + ')');
  console.log('  Falling back to in-memory JS query engine.');
  store = memoryStore();
}

/* =====================================================================
   Seed data — mirrors the frontend sample dataset
   ===================================================================== */
function pseudo(a, b) { const x = Math.sin(a * 12.9898 + b * 78.233) * 43758.5453; return x - Math.floor(x); }
/* timezone-safe date formatting (avoids toISOString UTC shift) */
function ymd(d) { const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; }
function ym(d) { const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}`; }

function seedSales() {
  const cats = ['Electronics', 'Apparel', 'Home & Garden', 'Sports', 'Beauty'];
  const regions = ['North', 'South', 'East', 'West'];
  const rows = [];
  for (let m = 0; m < 24; m++) {
    const d = new Date(2024, m, 1);
    const ds = ym(d);
    cats.forEach((cat, ci) => {
      const seasonal = 1 + 0.3 * Math.sin((m / 12) * Math.PI * 2 + ci);
      const base = (8000 + ci * 2500) * seasonal;
      const revenue = Math.round(base + pseudo(m, ci) * 4000);
      const units = Math.round(revenue / (40 + ci * 12));
      rows.push({
        date: ds, category: cat, region: regions[(m + ci) % regions.length],
        revenue, units_sold: units,
        profit_margin: +(0.12 + ci * 0.03 + pseudo(m * 3, ci) * 0.08).toFixed(3)
      });
    });
  }
  return rows;
}
function seedUsers() {
  const plans = ['Free', 'Pro', 'Team', 'Enterprise']; const rows = [];
  for (let i = 0; i < 60; i++) rows.push({
    date: ymd(new Date(2024, 0, 1 + i * 6)),
    plan: plans[i % 4], signups: Math.round(40 + pseudo(i, 1) * 200),
    churn: +(pseudo(i, 3) * 0.15).toFixed(3), mrr: Math.round(500 + pseudo(i, 7) * 9000)
  });
  return rows;
}
function seedTraffic() {
  const src = ['Organic', 'Paid', 'Social', 'Referral', 'Direct']; const rows = [];
  for (let i = 0; i < 50; i++) rows.push({
    date: ymd(new Date(2024, 3, 1 + i * 3)),
    source: src[i % 5], sessions: Math.round(200 + pseudo(i, 2) * 3000),
    bounce_rate: +(0.2 + pseudo(i, 5) * 0.5).toFixed(3), conversions: Math.round(pseudo(i, 9) * 120)
  });
  return rows;
}

/* =====================================================================
   SQLite-backed store
   ===================================================================== */
function sqliteStore(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS app_dashboards(
      id TEXT PRIMARY KEY, name TEXT, state TEXT, updated INTEGER);
    CREATE TABLE IF NOT EXISTS app_datasets(
      name TEXT PRIMARY KEY, columns TEXT, updated INTEGER);
  `);

  const datasetExists = (name) =>
    db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).get(name);

  function createDataset(name, columns, rows) {
    const t = sanitize(name);
    db.exec(`DROP TABLE IF EXISTS "${t}"`);
    const types = inferTypes(columns, rows);
    const cols = columns.map(c => `"${c}" ${types[c]}`).join(', ');
    db.exec(`CREATE TABLE "${t}" (${cols})`);
    const ph = columns.map(() => '?').join(', ');
    const ins = db.prepare(`INSERT INTO "${t}" (${columns.map(c => `"${c}"`).join(',')}) VALUES (${ph})`);
    for (const r of rows) ins.run(...columns.map(c => normCell(r[c])));
    db.prepare(`INSERT INTO app_datasets(name,columns,updated) VALUES(?,?,?)
                ON CONFLICT(name) DO UPDATE SET columns=excluded.columns, updated=excluded.updated`)
      .run(t, JSON.stringify(columns), Date.now());
    return { name: t, columns, rowCount: rows.length };
  }

  function seedIfEmpty(name, rows) {
    if (datasetExists(name)) return;
    createDataset(name, Object.keys(rows[0]), rows);
  }
  seedIfEmpty('sales', seedSales());
  seedIfEmpty('users', seedUsers());
  seedIfEmpty('traffic', seedTraffic());

  return {
    kind: 'sqlite',
    query(sql) {
      const rows = db.prepare(sql).all();
      const columns = rows.length ? Object.keys(rows[0]) : columnsFromSelect(sql);
      return { columns, rows };
    },
    listTables() {
      const tbls = db.prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'app_%' AND name NOT LIKE 'sqlite_%'`
      ).all().map(r => r.name);
      return tbls.map(t => ({
        name: t,
        columns: db.prepare(`PRAGMA table_info("${t}")`).all().map(c => c.name),
        rows: db.prepare(`SELECT COUNT(*) n FROM "${t}"`).get().n
      }));
    },
    createDataset,
    saveDashboard(d) {
      db.prepare(`INSERT INTO app_dashboards(id,name,state,updated) VALUES(?,?,?,?)
                  ON CONFLICT(id) DO UPDATE SET name=excluded.name, state=excluded.state, updated=excluded.updated`)
        .run(d.id, d.name, JSON.stringify(d.state), Date.now());
      return { id: d.id };
    },
    listDashboards() {
      return db.prepare(`SELECT id,name,updated FROM app_dashboards ORDER BY updated DESC`).all();
    },
    getDashboard(id) {
      const r = db.prepare(`SELECT id,name,state,updated FROM app_dashboards WHERE id=?`).get(id);
      if (!r) return null;
      r.state = JSON.parse(r.state); return r;
    },
    deleteDashboard(id) { db.prepare(`DELETE FROM app_dashboards WHERE id=?`).run(id); return { id }; }
  };
}

/* =====================================================================
   In-memory JS store (fallback) — supports a SQL subset
   SELECT cols | * , aggregates (SUM/AVG/COUNT/MIN/MAX), FROM, WHERE (1 cond),
   GROUP BY, ORDER BY, LIMIT
   ===================================================================== */
function memoryStore() {
  const tables = {
    sales: seedSales(), users: seedUsers(), traffic: seedTraffic()
  };
  const dashboards = new Map();

  function query(sql) {
    const rows = execSelect(sql, tables);
    const columns = rows.length ? Object.keys(rows[0]) : columnsFromSelect(sql);
    return { columns, rows };
  }
  return {
    kind: 'memory',
    query,
    listTables() {
      return Object.entries(tables).map(([name, rows]) => ({
        name, columns: rows.length ? Object.keys(rows[0]) : [], rows: rows.length
      }));
    },
    createDataset(name, columns, rows) {
      const t = sanitize(name);
      tables[t] = rows.map(r => { const o = {}; columns.forEach(c => o[c] = normCell(r[c])); return o; });
      return { name: t, columns, rowCount: rows.length };
    },
    saveDashboard(d) { dashboards.set(d.id, { ...d, updated: Date.now() }); return { id: d.id }; },
    listDashboards() { return [...dashboards.values()].map(({ id, name, updated }) => ({ id, name, updated })).sort((a, b) => b.updated - a.updated); },
    getDashboard(id) { return dashboards.get(id) || null; },
    deleteDashboard(id) { dashboards.delete(id); return { id }; }
  };
}

/* ---- tiny SQL-subset executor for the memory fallback ---- */
function execSelect(sql, tables) {
  const fromM = sql.match(/from\s+([a-z_][\w]*)/i);
  const tname = fromM ? sanitize(fromM[1]) : 'sales';
  let rows = (tables[tname] || []).map(r => ({ ...r }));
  if (!tables[tname]) throw new Error(`Unknown table: ${tname}`);

  const whereM = sql.match(/where\s+([\w]+)\s*(=|>=|<=|>|<)\s*('?[\w .%-]+'?)/i);
  if (whereM) {
    const [, col, op, raw] = whereM; const val = raw.replace(/^'|'$/g, ''); const num = parseFloat(val);
    rows = rows.filter(r => {
      const c = r[col]; if (c === undefined) return true;
      if (!isNaN(num) && typeof c === 'number') {
        return op === '=' ? c == num : op === '>' ? c > num : op === '<' ? c < num : op === '>=' ? c >= num : c <= num;
      }
      return String(c).toLowerCase() === val.toLowerCase();
    });
  }

  const selM = sql.match(/select\s+(.+?)\s+from/is);
  const selRaw = selM ? selM[1].trim() : '*';
  const groupM = sql.match(/group\s+by\s+([\w]+)/i);
  const aggRe = /(sum|avg|count|min|max)\s*\(\s*([\w*]+)\s*\)(?:\s+as\s+(\w+))?/ig;
  const aggs = [...selRaw.matchAll(aggRe)].map(m => ({ fn: m[1].toLowerCase(), col: m[2], alias: m[3] || `${m[1].toLowerCase()}_${m[2]}` }));

  if (groupM || aggs.length) {
    const gcol = groupM ? groupM[1] : null;
    const groups = new Map();
    rows.forEach(r => { const k = gcol ? r[gcol] : '__all__'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); });
    rows = [...groups.entries()].map(([k, rs]) => {
      const o = {}; if (gcol) o[gcol] = k;
      aggs.forEach(a => {
        const vals = rs.map(r => +r[a.col]).filter(v => !isNaN(v));
        o[a.alias] = a.fn === 'count' ? (a.col === '*' ? rs.length : vals.length)
          : a.fn === 'avg' ? +(vals.reduce((x, y) => x + y, 0) / (vals.length || 1)).toFixed(3)
            : a.fn === 'min' ? Math.min(...vals) : a.fn === 'max' ? Math.max(...vals)
              : vals.reduce((x, y) => x + y, 0);
      });
      return o;
    });
  } else if (selRaw !== '*') {
    const cols = selRaw.split(',').map(c => c.trim().split(/\s+as\s+/i)[0].trim());
    rows = rows.map(r => { const o = {}; cols.forEach(c => { if (c in r) o[c] = r[c]; }); return o; });
  }

  const orderM = sql.match(/order\s+by\s+([\w]+)\s*(asc|desc)?/i);
  if (orderM) { const c = orderM[1], dir = (orderM[2] || 'asc').toLowerCase() === 'desc' ? -1 : 1; rows.sort((a, b) => a[c] > b[c] ? dir : a[c] < b[c] ? -dir : 0); }
  const limM = sql.match(/limit\s+(\d+)/i);
  if (limM) rows = rows.slice(0, +limM[1]);
  return rows;
}

/* =====================================================================
   Helpers
   ===================================================================== */
function sanitize(name) { return String(name).toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/^_+|_+$/g, '') || 'dataset'; }
function normCell(v) { if (v === '' || v === undefined || v === null) return null; const n = Number(v); return (!isNaN(n) && String(v).trim() !== '') ? n : v; }
function inferTypes(columns, rows) {
  const t = {};
  columns.forEach(c => {
    const vals = rows.map(r => normCell(r[c])).filter(v => v !== null);
    t[c] = vals.length && vals.every(v => typeof v === 'number')
      ? (vals.every(v => Number.isInteger(v)) ? 'INTEGER' : 'REAL') : 'TEXT';
  });
  return t;
}
function columnsFromSelect(sql) {
  const m = sql.match(/select\s+(.+?)\s+from/is); if (!m || m[1].trim() === '*') return [];
  return m[1].split(',').map(c => { const parts = c.trim().split(/\s+as\s+/i); return (parts[1] || parts[0]).replace(/.*\(([\w*]+)\).*/, '$1').trim(); });
}

/* ---- SQL safety guard for /api/query (read-only) ---- */
function isReadOnly(sql) {
  const s = sql.trim().toLowerCase();
  if (!/^(select|with)\b/.test(s)) return false;
  if (/;\s*\S/.test(sql.replace(/;\s*$/, ''))) return false;                 // no chained statements
  if (/\b(attach|pragma|insert|update|delete|drop|alter|create|replace|vacuum)\b/.test(s)) return false;
  return true;
}

/* =====================================================================
   HTTP server + routing
   ===================================================================== */
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' };

function send(res, code, body, type = 'application/json') {
  const payload = type === 'application/json' ? JSON.stringify(body) : body;
  res.writeHead(code, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(payload);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''; req.on('data', c => { data += c; if (data.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('Invalid JSON body')); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  if (req.method === 'OPTIONS') return send(res, 204, '');

  try {
    /* ---------- API ---------- */
    if (p === '/api/health') return send(res, 200, { ok: true, engine: store.kind, time: Date.now() });

    if (p === '/api/tables' && req.method === 'GET') return send(res, 200, { tables: store.listTables() });

    if (p === '/api/query' && req.method === 'POST') {
      const { sql } = await readBody(req);
      if (!sql || !sql.trim()) return send(res, 400, { error: 'Empty query' });
      if (!isReadOnly(sql)) return send(res, 400, { error: 'Only single read-only SELECT/WITH queries are allowed' });
      try { return send(res, 200, store.query(sql)); }
      catch (e) { return send(res, 400, { error: e.message }); }
    }

    if (p === '/api/datasets' && req.method === 'POST') {
      const { name, columns, rows } = await readBody(req);
      if (!name || !Array.isArray(columns) || !Array.isArray(rows)) return send(res, 400, { error: 'name, columns[], rows[] required' });
      try { return send(res, 200, store.createDataset(name, columns, rows)); }
      catch (e) { return send(res, 400, { error: e.message }); }
    }

    if (p === '/api/dashboards' && req.method === 'GET') return send(res, 200, { dashboards: store.listDashboards() });
    if (p === '/api/dashboards' && req.method === 'POST') {
      const d = await readBody(req);
      if (!d.id) return send(res, 400, { error: 'id required' });
      return send(res, 200, store.saveDashboard(d));
    }
    const dm = p.match(/^\/api\/dashboards\/([\w-]+)$/);
    if (dm && req.method === 'GET') { const r = store.getDashboard(dm[1]); return r ? send(res, 200, r) : send(res, 404, { error: 'Not found' }); }
    if (dm && req.method === 'DELETE') return send(res, 200, store.deleteDashboard(dm[1]));

    if (p.startsWith('/api/')) return send(res, 404, { error: 'Unknown endpoint' });

    /* ---------- Static files ---------- */
    let file = p === '/' ? '/dashboard.html' : p;
    const full = path.join(ROOT, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if (!full.startsWith(ROOT)) return send(res, 403, 'Forbidden', 'text/plain');
    fs.readFile(full, (err, buf) => {
      if (err) return send(res, 404, 'Not found', 'text/plain');
      send(res, 200, buf, MIME[path.extname(full)] || 'application/octet-stream');
    });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`\n  Nexus Analytics backend running`);
  console.log(`  → http://localhost:${PORT}\n`);
  console.log(`  API: /api/health  /api/tables  /api/query  /api/datasets  /api/dashboards`);
});

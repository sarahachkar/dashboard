# Nexus Analytics

A polished, data-dense analytics dashboard (Kibana/Grafana/Superset vibe) with a
zero-dependency Node backend.

## Run

```bash
npm start          # → http://localhost:4000
```

That's it — no `npm install`, no build step. The backend uses Node's built-in
`node:sqlite` (Node ≥ 22.5) for **real SQL execution**, and automatically falls
back to an in-memory JS query engine if SQLite isn't available.

The dashboard (`dashboard.html`) also works **standalone** by just opening the file
— it runs in local-simulation mode and persists to `localStorage`. When the backend
is reachable it upgrades automatically (a 🛢 badge in the toolbar turns green) and
routes queries + dashboard saves through the server.

## Backend API

| Method | Endpoint | Purpose |
| ------ | -------- | ------- |
| GET    | `/api/health`           | Liveness + which engine is active (`sqlite`/`memory`) |
| GET    | `/api/tables`           | List queryable tables with columns + row counts |
| POST   | `/api/query`            | `{ "sql": "SELECT ..." }` → `{ columns, rows }` (read-only SELECT/WITH only) |
| POST   | `/api/datasets`         | `{ name, columns[], rows[] }` → registers a real queryable table |
| GET    | `/api/dashboards`       | List saved dashboard layouts |
| POST   | `/api/dashboards`       | Upsert `{ id, name, state }` |
| GET    | `/api/dashboards/:id`   | Load one |
| DELETE | `/api/dashboards/:id`   | Delete one |

### Examples

```bash
curl localhost:4000/api/health
curl localhost:4000/api/tables
curl -X POST localhost:4000/api/query -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT category, SUM(revenue) AS revenue FROM sales GROUP BY category ORDER BY revenue DESC"}'
```

## Data

Three tables are seeded on first run: `sales` (24 months × 5 categories),
`users`, and `traffic`. Upload your own via the **Manual** / **CSV** input in the
UI (registered through `/api/datasets`), then `SELECT ... FROM your_table`.

## Security note

`/api/query` is restricted to single read-only `SELECT`/`WITH` statements
(no `INSERT/UPDATE/DROP/PRAGMA/ATTACH`, no chained statements). It's a local demo
server — don't expose it to untrusted networks as-is.

## Files

- `dashboard.html` — the entire frontend (HTML + CSS + JS inline)
- `server.js` — the backend (zero npm dependencies)
- `nexus.db` — SQLite file, created automatically on first run

/* =====================================================================
   Reset accounts — wipes ALL users, sessions, and per-widget permissions
   so you can start fresh. The NEXT person to sign up becomes the admin.

   Dashboards, saved connections, and data are left untouched.

   Run:  npm run reset       (or: node --experimental-sqlite reset-accounts.js)
   ===================================================================== */
'use strict';

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const db = new DatabaseSync(path.join(__dirname, 'nexus.db'));

let removed = 0;
try { removed = db.prepare('SELECT COUNT(*) n FROM app_users').get().n; } catch { /* table may not exist yet */ }

for (const t of ['app_users', 'sessions', 'widget_permissions']) {
  try { db.exec(`DELETE FROM ${t}`); } catch { /* ignore missing table */ }
}
// Reset the auto-increment so the next account is id 1
try { db.exec("DELETE FROM sqlite_sequence WHERE name='app_users'"); } catch { /* ignore */ }

console.log(`✓ Cleared ${removed} account(s), all sessions, and widget permissions.`);
console.log('  Go to /signup and create your account — it will be the new admin.');

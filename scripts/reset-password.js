'use strict';

// Sets a new temporary password for an account directly in the database.
// Usage:  npm run reset-password -- someone@example.com
// The server may keep running while you do this.

require('dotenv').config();
const path = require('node:path');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const email = (process.argv[2] || '').trim().toLowerCase();
if (!email) {
  console.error('Използване: npm run reset-password -- имейл@пример.bg');
  process.exit(1);
}

const databasePath = path.resolve(process.env.DATABASE_PATH || './data/tracker.sqlite');
const db = new Database(databasePath, { fileMustExist: true });
const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
if (!user) {
  const all = db.prepare('SELECT email FROM users ORDER BY id').all().map((row) => row.email);
  console.error(`Няма акаунт с имейл ${email}.`);
  console.error(all.length ? `Съществуващи акаунти: ${all.join(', ')}` : 'В базата още няма акаунти.');
  process.exit(1);
}

const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
let temporary = '';
for (let i = 0; i < 14; i += 1) temporary += alphabet[crypto.randomInt(alphabet.length)];

db.transaction(() => {
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(temporary, 12), user.id);
  db.prepare("DELETE FROM sessions WHERE json_extract(session, '$.userId') = ?").run(user.id);
})();
db.close();

console.log(`\nНова временна парола за ${user.email}:  ${temporary}\n`);
console.log('Влез с нея и я смени от „Смяна на парола“ в приложението.\n');

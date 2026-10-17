'use strict';

require('dotenv').config();

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('node:crypto');
const { rateLimit } = require('express-rate-limit');

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be configured with at least 32 characters.');
}

const allowedEmails = new Set((process.env.ALLOWED_EMAILS || '')
  .split(',').map((value) => value.trim().toLowerCase()).filter(Boolean));

const databasePath = path.resolve(process.env.DATABASE_PATH || './data/tracker.sqlite');
fs.mkdirSync(path.dirname(databasePath), { recursive: true });

const db = new Database(databasePath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    profile_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tracker_data (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS password_resets (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS competition_data (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const userColumns = new Set(db.pragma('table_info(users)').map((column) => column.name));
if (!userColumns.has('display_name')) db.exec('ALTER TABLE users ADD COLUMN display_name TEXT');
if (!userColumns.has('profile_key')) db.exec('ALTER TABLE users ADD COLUMN profile_key TEXT');
db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS users_profile_key_idx ON users(profile_key) WHERE profile_key IS NOT NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS users_display_name_idx ON users(display_name COLLATE NOCASE) WHERE display_name IS NOT NULL;
`);

class SqliteSessionStore extends session.Store {
  get(sid, callback) {
    try {
      const row = db.prepare('SELECT session, expires_at FROM sessions WHERE sid = ?').get(sid);
      if (!row) return callback(null, null);
      if (row.expires_at <= Date.now()) {
        db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(row.session));
    } catch (error) {
      callback(error);
    }
  }

  set(sid, value, callback) {
    try {
      const cookieExpiry = value.cookie && value.cookie.expires
        ? new Date(value.cookie.expires).getTime()
        : Date.now() + 7 * 24 * 60 * 60 * 1000;
      db.prepare(`
        INSERT INTO sessions (sid, session, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET session = excluded.session, expires_at = excluded.expires_at
      `).run(sid, JSON.stringify(value), cookieExpiry);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  destroy(sid, callback) {
    try {
      db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  touch(sid, value, callback) {
    this.set(sid, value, callback);
  }
}

function purgeExpiredSessions() {
  try {
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
    db.prepare('DELETE FROM password_resets WHERE expires_at <= ?').run(Date.now());
  } catch (error) {
    console.error('Неуспешно почистване на изтекли сесии:', error);
  }
}
purgeExpiredSessions();
setInterval(purgeExpiredSessions, 60 * 60 * 1000).unref();

// Used when the e-mail is unknown so failed logins take the same time either way.
const dummyPasswordHash = bcrypt.hashSync('timing-equalizer-not-a-real-password', 12);

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'"
  ].join('; '));
  if (isProduction) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '2mb' }));
app.use(session({
  name: 'kilos.sid',
  secret: sessionSecret,
  store: new SqliteSessionStore(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'Твърде много опити. Опитай отново след 15 минути.' })
});

function todayInBulgaria() {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Sofia',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validNumber(value, min, max) {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max;
}

function validateMeasurement(value, allowNote) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !validDate(value.d) || value.d > todayInBulgaria()) {
    return false;
  }
  if (!validNumber(value.w, 20, 400)) return false;
  for (const key of ['c', 'wa', 'h']) {
    if (value[key] !== undefined && !validNumber(value[key], 20, 250)) return false;
  }
  if (allowNote && value.n !== undefined && (typeof value.n !== 'string' || value.n.length > 200)) return false;
  return true;
}

function validateProfile(value, previous) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const goal = value.goal;
  if (!goal || typeof goal !== 'object' || Array.isArray(goal)) return false;
  if (goal.weight !== null && goal.weight !== undefined && !validNumber(goal.weight, 20, 400)) return false;
  // A new goal date must lie in the future, but a goal date that was already saved
  // stays valid after it passes, otherwise every later save would be rejected.
  const unchangedGoalDate = previous && previous.goal && previous.goal.date === goal.date;
  if (goal.date !== null && goal.date !== undefined
    && (!validDate(goal.date) || (goal.date <= todayInBulgaria() && !unchangedGoalDate))) return false;
  if (value.start !== null && value.start !== undefined && !validateMeasurement(value.start, false)) return false;
  if (!Array.isArray(value.entries) || value.entries.length > 5000) return false;
  const dates = new Set();
  for (const entry of value.entries) {
    if (!validateMeasurement(entry, true) || dates.has(entry.d)) return false;
    dates.add(entry.d);
  }
  return true;
}

function validateTrackerData(value, previousProfiles) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (!['irka', 'mirko'].includes(value.activeProfile)) return false;
  if (!value.profiles || typeof value.profiles !== 'object' || Array.isArray(value.profiles)) return false;
  return ['irka', 'mirko'].every((key) => validateProfile(value.profiles[key], previousProfiles && previousProfiles[key]));
}

function emptyTrackerData() {
  const emptyProfile = () => ({ goal: { weight: null, date: null }, start: null, entries: [] });
  return { v: 1, activeProfile: 'irka', profiles: { irka: emptyProfile(), mirko: emptyProfile() } };
}

function participantList() {
  return db.prepare('SELECT profile_key, display_name FROM users WHERE profile_key IS NOT NULL')
    .all()
    .map((user) => ({ profileKey: user.profile_key, displayName: user.display_name }));
}

function profileSummary(profile) {
  const entries = profile.entries.slice().sort((a, b) => a.d.localeCompare(b.d));
  const latest = entries[entries.length - 1] || null;
  const today = entries.find((entry) => entry.d === todayInBulgaria()) || null;
  return {
    start: profile.start,
    goal: profile.goal,
    todayWeight: today ? today.w : null,
    latestWeight: latest ? latest.w : null,
    latestDate: latest ? latest.d : null
  };
}

function assignProfile(userId, displayName) {
  return db.transaction(() => {
    const user = db.prepare('SELECT id, profile_key FROM users WHERE id = ?').get(userId);
    if (!user) throw new Error('Потребителят не съществува.');
    if (user.profile_key) {
      return db.prepare('SELECT id, email, display_name, profile_key FROM users WHERE id = ?').get(userId);
    }

    const occupied = new Set(db.prepare('SELECT profile_key FROM users WHERE profile_key IS NOT NULL')
      .all().map((row) => row.profile_key));
    const profileKey = ['irka', 'mirko'].find((key) => !occupied.has(key));
    if (!profileKey) {
      const error = new Error('Състезанието вече има двама участници.');
      error.status = 409;
      throw error;
    }

    const legacyRow = db.prepare('SELECT data FROM tracker_data WHERE user_id = ?').get(userId);
    const competitionRow = db.prepare('SELECT data FROM competition_data WHERE id = 1').get();
    const data = competitionRow ? JSON.parse(competitionRow.data) : emptyTrackerData();
    if (legacyRow) {
      const legacy = JSON.parse(legacyRow.data);
      const oldProfile = legacy.profiles && legacy.profiles[profileKey]
        ? legacy.profiles[profileKey]
        : profileKey === 'irka' && !legacy.profiles ? legacy : null;
      if (oldProfile && validateProfile(oldProfile)) data.profiles[profileKey] = oldProfile;
    }

    db.prepare('UPDATE users SET display_name = ?, profile_key = ? WHERE id = ?')
      .run(displayName, profileKey, userId);
    db.prepare(`
      INSERT INTO competition_data (id, data, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
    `).run(JSON.stringify(data));
    return db.prepare('SELECT id, email, display_name, profile_key FROM users WHERE id = ?').get(userId);
  })();
}

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Влез в акаунта си, за да продължиш.' });
  next();
}

function establishSession(req, user, statusCode, res, next) {
  req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.save((saveError) => {
      if (saveError) return next(saveError);
      res.status(statusCode).json({ user: {
        email: user.email,
        displayName: user.display_name,
        profileKey: user.profile_key
      } });
    });
  });
}

app.post('/api/auth/register', authRateLimit, async (req, res, next) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Заявката за регистрация е невалидна.' });
    }
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const displayName = typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
    if (!displayName || displayName.length > 40 || /[\u0000-\u001f\u007f]/.test(displayName)) {
      return res.status(400).json({ error: 'Въведи име за таба (до 40 символа).' });
    }
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Въведи валиден имейл адрес.' });
    }
    if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Паролата трябва да е поне 12 символа и до 72 байта.' });
    }

    if (allowedEmails.size && !allowedEmails.has(email)) {
      return res.status(403).json({ error: 'Регистрацията е разрешена само за поканените участници.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    let user;
    try {
      user = db.transaction(() => {
        const occupied = new Set(db.prepare('SELECT profile_key FROM users WHERE profile_key IS NOT NULL')
          .all().map((row) => row.profile_key));
        const profileKey = ['irka', 'mirko'].find((key) => !occupied.has(key));
        if (!profileKey) {
          const error = new Error('Състезанието вече има двама участници.');
          error.status = 409;
          throw error;
        }
        const result = db.prepare(
          'INSERT INTO users (email, password_hash, display_name, profile_key) VALUES (?, ?, ?, ?)'
        ).run(email, passwordHash, displayName, profileKey);
        return { id: Number(result.lastInsertRowid), email, display_name: displayName, profile_key: profileKey };
      })();
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        const message = error.message.includes('display_name')
          ? 'Това име вече е заето.'
          : 'Вече има акаунт с този имейл адрес.';
        return res.status(409).json({ error: message });
      }
      if (error.status) return res.status(error.status).json({ error: error.message });
      throw error;
    }

    establishSession(req, user, 201, res, next);
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res, next) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Заявката за вход е невалидна.' });
    }
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const user = db.prepare('SELECT id, email, password_hash, display_name, profile_key FROM users WHERE email = ?').get(email);
    const passwordMatches = await bcrypt.compare(password, user ? user.password_hash : dummyPasswordHash);
    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'Имейлът или паролата са неправилни.' });
    }
    establishSession(req, user, 200, res, next);
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/session', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT email, display_name, profile_key FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.json({ user: null });
  res.json({ user: {
    email: user.email,
    displayName: user.display_name,
    profileKey: user.profile_key
  } });
});

app.post('/api/auth/profile', requireUser, (req, res, next) => {
  try {
    const displayName = req.body && typeof req.body.displayName === 'string' ? req.body.displayName.trim() : '';
    if (!displayName || displayName.length > 40 || /[\u0000-\u001f\u007f]/.test(displayName)) {
      return res.status(400).json({ error: 'Въведи име за таба (до 40 символа).' });
    }
    const user = assignProfile(req.session.userId, displayName);
    res.json({ user: {
      email: user.email,
      displayName: user.display_name,
      profileKey: user.profile_key
    } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Това име вече е заето.' });
    }
    if (error.status) return res.status(error.status).json({ error: error.message });
    next(error);
  }
});

app.post('/api/auth/password', authRateLimit, requireUser, async (req, res, next) => {
  try {
    const currentPassword = req.body && typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
    const newPassword = req.body && typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
    if (newPassword.length < 12 || Buffer.byteLength(newPassword, 'utf8') > 72) {
      return res.status(400).json({ error: 'Новата парола трябва да е поне 12 символа и до 72 байта.' });
    }
    const user = db.prepare('SELECT id, email, password_hash, display_name, profile_key FROM users WHERE id = ?')
      .get(req.session.userId);
    if (!user || !await bcrypt.compare(currentPassword, user.password_hash)) {
      return res.status(401).json({ error: 'Текущата парола е неправилна.' });
    }
    const passwordHash = await bcrypt.hash(newPassword, 12);
    db.transaction(() => {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, user.id);
      // Sign out every other device that was logged in with the old password.
      db.prepare("DELETE FROM sessions WHERE json_extract(session, '$.userId') = ?").run(user.id);
    })();
    establishSession(req, user, 200, res, next);
  } catch (error) {
    next(error);
  }
});

const RESET_CODE_TTL_MS = 30 * 60 * 1000;
const RESET_MAX_ATTEMPTS = 5;
function hashResetCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}
function newResetCode() {
  // 8 characters without look-alikes (0/O, 1/I/L), shown as XXXX-XXXX.
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i += 1) code += alphabet[crypto.randomInt(alphabet.length)];
  return code;
}
function normalizeResetCode(value) {
  return typeof value === 'string' ? value.toUpperCase().replace(/[^A-Z0-9]/g, '') : '';
}

// Step 1: ask for a one-time code. There is no e-mail service, so the code is
// printed in the terminal where the server runs — only whoever runs the server
// can read it and pass it on.
app.post('/api/auth/forgot', authRateLimit, (req, res, next) => {
  try {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const user = email ? db.prepare('SELECT id, email FROM users WHERE email = ?').get(email) : null;
    if (user) {
      const code = newResetCode();
      db.prepare(`
        INSERT INTO password_resets (user_id, code_hash, expires_at, attempts) VALUES (?, ?, ?, 0)
        ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, attempts = 0
      `).run(user.id, hashResetCode(code), Date.now() + RESET_CODE_TTL_MS);
      const shown = `${code.slice(0, 4)}-${code.slice(4)}`;
      console.log([
        '',
        '==================== ЗАБРАВЕНА ПАРОЛА ====================',
        `  Акаунт: ${user.email}`,
        `  Еднократен код: ${shown}   (валиден 30 минути)`,
        '==========================================================',
        ''
      ].join('\n'));
    }
    // Same answer whether or not the e-mail exists.
    res.json({ ok: true, message: 'Ако има акаунт с този имейл, кодът за смяна е показан в прозореца, в който работи сървърът.' });
  } catch (error) {
    next(error);
  }
});

// Step 2: use the code to set a new password.
app.post('/api/auth/reset', authRateLimit, async (req, res, next) => {
  try {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const code = normalizeResetCode(req.body && req.body.code);
    const newPassword = req.body && typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
    if (newPassword.length < 12 || Buffer.byteLength(newPassword, 'utf8') > 72) {
      return res.status(400).json({ error: 'Новата парола трябва да е поне 12 символа и до 72 байта.' });
    }
    const invalid = () => res.status(400).json({ error: 'Кодът е невалиден или е изтекъл. Поискай нов код.' });
    const user = email ? db.prepare('SELECT id, email, display_name, profile_key FROM users WHERE email = ?').get(email) : null;
    if (!user || !code) return invalid();
    const reset = db.prepare('SELECT code_hash, expires_at, attempts FROM password_resets WHERE user_id = ?').get(user.id);
    if (!reset || reset.expires_at <= Date.now() || reset.attempts >= RESET_MAX_ATTEMPTS) return invalid();
    const given = Buffer.from(hashResetCode(code), 'hex');
    const expected = Buffer.from(reset.code_hash, 'hex');
    if (!crypto.timingSafeEqual(given, expected)) {
      db.prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = ?').run(user.id);
      return invalid();
    }
    const passwordHash = await bcrypt.hash(newPassword, 12);
    db.transaction(() => {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, user.id);
      db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);
      db.prepare("DELETE FROM sessions WHERE json_extract(session, '$.userId') = ?").run(user.id);
    })();
    establishSession(req, user, 200, res, next);
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', requireUser, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie('kilos.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ ok: true });
  });
});

app.get('/api/data', requireUser, (req, res, next) => {
  try {
    const user = db.prepare('SELECT profile_key FROM users WHERE id = ?').get(req.session.userId);
    if (!user || !user.profile_key) {
      return res.status(409).json({ error: 'Преди да продължиш, задай име за своя таб.' });
    }
    const row = db.prepare('SELECT data FROM competition_data WHERE id = 1').get();
    const sharedData = row ? JSON.parse(row.data) : emptyTrackerData();
    const otherKey = user.profile_key === 'irka' ? 'mirko' : 'irka';
    const otherProfile = sharedData.profiles[otherKey];
    const data = emptyTrackerData();
    data.activeProfile = user.profile_key;
    data.profiles[user.profile_key] = sharedData.profiles[user.profile_key];
    res.json({
      data,
      summary: profileSummary(otherProfile),
      participants: participantList()
    });
  } catch (error) {
    next(error);
  }
});

app.put('/api/data', requireUser, (req, res, next) => {
  try {
    const user = db.prepare('SELECT profile_key FROM users WHERE id = ?').get(req.session.userId);
    if (!user || !user.profile_key) {
      return res.status(409).json({ error: 'Преди запис трябва да зададеш име за своя таб.' });
    }
    const row = db.prepare('SELECT data FROM competition_data WHERE id = 1').get();
    const sharedData = row ? JSON.parse(row.data) : emptyTrackerData();
    if (!validateTrackerData(req.body, sharedData.profiles)) {
      return res.status(400).json({ error: 'Данните са невалидни. Провери измерванията и опитай отново.' });
    }
    sharedData.profiles[user.profile_key] = req.body.profiles[user.profile_key];
    sharedData.activeProfile = user.profile_key;
    db.prepare(`
      INSERT INTO competition_data (id, data, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
    `).run(JSON.stringify(sharedData));
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API маршрутът не съществува.' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error(error);
  const status = error.status || error.statusCode;
  if (status === 400) return res.status(400).json({ error: 'Заявката съдържа невалиден JSON.' });
  if (status === 413) return res.status(413).json({ error: 'Заявката е твърде голяма.' });
  res.status(500).json({ error: 'Възникна сървърна грешка. Опитай отново.' });
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
app.listen(port, host, () => console.log(`KilosCalendAI is running at http://${host}:${port}`));

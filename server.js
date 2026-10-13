'use strict';

require('dotenv').config();

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { rateLimit } = require('express-rate-limit');

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  throw new Error('SESSION_SECRET must be configured with at least 32 characters.');
}

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

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

app.disable('x-powered-by');
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

function validateProfile(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const goal = value.goal;
  if (!goal || typeof goal !== 'object' || Array.isArray(goal)) return false;
  if (goal.weight !== null && goal.weight !== undefined && !validNumber(goal.weight, 20, 400)) return false;
  if (goal.date !== null && goal.date !== undefined
    && (!validDate(goal.date) || goal.date <= todayInBulgaria())) return false;
  if (value.start !== null && value.start !== undefined && !validateMeasurement(value.start, false)) return false;
  if (!Array.isArray(value.entries) || value.entries.length > 5000) return false;
  const dates = new Set();
  for (const entry of value.entries) {
    if (!validateMeasurement(entry, true) || dates.has(entry.d)) return false;
    dates.add(entry.d);
  }
  return true;
}

function validateTrackerData(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (!['irka', 'mirko'].includes(value.activeProfile)) return false;
  if (!value.profiles || typeof value.profiles !== 'object' || Array.isArray(value.profiles)) return false;
  return ['irka', 'mirko'].every((key) => validateProfile(value.profiles[key]));
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
      res.status(statusCode).json({ user: { email: user.email } });
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
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Въведи валиден имейл адрес.' });
    }
    if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({ error: 'Паролата трябва да е поне 12 символа и до 72 байта.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    let result;
    try {
      result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'Вече има акаунт с този имейл адрес.' });
      }
      throw error;
    }

    establishSession(req, { id: Number(result.lastInsertRowid), email }, 201, res, next);
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
    const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Имейлът или паролата са неправилни.' });
    }
    establishSession(req, user, 200, res, next);
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/session', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  res.json({ user: { email: req.session.email } });
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
    const row = db.prepare('SELECT data FROM tracker_data WHERE user_id = ?').get(req.session.userId);
    res.json({ data: row ? JSON.parse(row.data) : null });
  } catch (error) {
    next(error);
  }
});

app.put('/api/data', requireUser, (req, res, next) => {
  try {
    if (!validateTrackerData(req.body)) {
      return res.status(400).json({ error: 'Данните са невалидни. Провери измерванията и опитай отново.' });
    }
    db.prepare(`
      INSERT INTO tracker_data (user_id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
    `).run(req.session.userId, JSON.stringify(req.body));
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

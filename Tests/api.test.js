'use strict';

const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { test } = require('node:test');
const {
  blankProfile,
  dateAfterToday,
  request,
  startTestServer,
  todayInBulgaria
} = require('./helpers');

async function serverFor(t, options) {
  const server = await startTestServer(options);
  t.after(() => server.stop());
  return server;
}

async function register(baseUrl, email, displayName, password = 'Test-password-2026') {
  return request(baseUrl, '/api/auth/register', {
    method: 'POST',
    body: { email, password, displayName }
  });
}

test('registration, login, session, logout, and input validation', async (t) => {
  const { baseUrl } = await serverFor(t);

  const anonymous = await request(baseUrl, '/api/auth/session');
  assert.deepEqual(anonymous.body, { user: null });
  assert.equal((await request(baseUrl, '/api/data')).status, 401);
  assert.equal((await request(baseUrl, '/api/data', { method: 'PUT', body: {} })).status, 401);
  assert.equal((await request(baseUrl, '/api/auth/logout', { method: 'POST' })).status, 401);

  const malformed = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{'
  });
  assert.equal(malformed.status, 400);
  assert.match((await malformed.json()).error, /невалиден JSON/);

  assert.equal((await register(baseUrl, 'not-an-email', 'Tester')).status, 400);
  assert.equal((await register(baseUrl, 'short@example.test', 'Tester', 'short')).status, 400);
  assert.equal((await register(baseUrl, 'long@example.test', 'Tester', 'я'.repeat(37))).status, 400);
  assert.equal((await request(baseUrl, '/api/auth/register', {
    method: 'POST',
    body: { email: 'missing-name@example.test', password: 'Test-password-2026' }
  })).status, 400);
  assert.equal((await register(baseUrl, 'control@example.test', 'Bad\nName')).status, 400);

  const created = await register(baseUrl, ' Irka@Example.Test ', 'Irena');
  assert.equal(created.status, 201);
  assert.equal(created.body.user.email, 'irka@example.test');
  assert.equal(created.body.user.displayName, 'Irena');
  assert.equal(created.body.user.profileKey, 'irka');
  assert.ok(created.cookie);

  const duplicateEmail = await register(baseUrl, 'IRKA@example.test', 'Other Name');
  assert.equal(duplicateEmail.status, 409);
  assert.match(duplicateEmail.body.error, /имейл/);
  const duplicateName = await register(baseUrl, 'other@example.test', 'IRENA');
  assert.equal(duplicateName.status, 409);
  assert.match(duplicateName.body.error, /име/);

  const badLogin = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    body: { email: 'irka@example.test', password: 'Wrong-password-2026' }
  });
  assert.equal(badLogin.status, 401);
  const login = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    body: { email: 'IRKA@example.test', password: 'Test-password-2026' }
  });
  assert.equal(login.status, 200);
  assert.equal(login.body.user.displayName, 'Irena');
  assert.equal(login.body.user.profileKey, 'irka');
  assert.notEqual(login.cookie, created.cookie);

  const session = await request(baseUrl, '/api/auth/session', { cookie: login.cookie });
  assert.deepEqual(session.body.user, login.body.user);
  const logout = await request(baseUrl, '/api/auth/logout', {
    method: 'POST',
    cookie: login.cookie
  });
  assert.equal(logout.status, 200);
  const afterLogout = await request(baseUrl, '/api/auth/session', { cookie: logout.cookie });
  assert.deepEqual(afterLogout.body, { user: null });
});

test('two participant accounts share only summaries and cannot overwrite each other', async (t) => {
  const { baseUrl } = await serverFor(t);
  const irka = await register(baseUrl, 'irka@example.test', 'Ирка');
  const mirko = await register(baseUrl, 'mirko@example.test', 'Мирко');
  assert.equal(irka.status, 201);
  assert.equal(mirko.status, 201);
  assert.equal(irka.body.user.profileKey, 'irka');
  assert.equal(mirko.body.user.profileKey, 'mirko');

  const third = await register(baseUrl, 'third@example.test', 'Трети');
  assert.equal(third.status, 409);

  const today = todayInBulgaria();
  const tomorrow = dateAfterToday();
  const irkaProfile = {
    goal: { weight: 70, date: tomorrow },
    start: { d: today, w: 90, c: 100, wa: 80, h: 100 },
    entries: [
      { d: today, w: 89, n: 'Днешен запис' },
      { d: dateAfterToday(-1), w: 90 }
    ]
  };
  const mirkoProfile = {
    goal: { weight: 80, date: tomorrow },
    start: { d: today, w: 100, c: 110, wa: 95, h: 105 },
    entries: [{ d: today, w: 99 }]
  };

  const saveIrka = await request(baseUrl, '/api/data', {
    method: 'PUT',
    cookie: irka.cookie,
    body: {
      v: 1,
      activeProfile: 'irka',
      profiles: { irka: irkaProfile, mirko: blankProfile() }
    }
  });
  assert.equal(saveIrka.status, 200);

  const mirkoView = await request(baseUrl, '/api/data', { cookie: mirko.cookie });
  assert.equal(mirkoView.status, 200);
  assert.deepEqual(mirkoView.body.data.profiles.mirko, blankProfile());
  assert.equal(mirkoView.body.summary.start.w, 90);
  assert.equal(mirkoView.body.summary.start.c, 100);
  assert.equal(mirkoView.body.summary.todayWeight, 89);
  assert.equal(mirkoView.body.summary.latestWeight, 89);
  assert.equal(mirkoView.body.summary.latestDate, today);
  assert.equal(mirkoView.body.summary.goal.weight, 70);
  assert.deepEqual(
    mirkoView.body.participants.map(({ profileKey, displayName }) => [profileKey, displayName]),
    [['irka', 'Ирка'], ['mirko', 'Мирко']]
  );
  assert.equal(JSON.stringify(mirkoView.body).includes('Днешен запис'), false);

  const saveMirko = await request(baseUrl, '/api/data', {
    method: 'PUT',
    cookie: mirko.cookie,
    body: {
      v: 1,
      activeProfile: 'mirko',
      profiles: {
        irka: { ...irkaProfile, entries: [{ d: today, w: 50 }] },
        mirko: mirkoProfile
      }
    }
  });
  assert.equal(saveMirko.status, 200);

  const irkaView = await request(baseUrl, '/api/data', { cookie: irka.cookie });
  assert.equal(irkaView.body.data.profiles.irka.entries[0].w, 89);
  assert.deepEqual(irkaView.body.data.profiles.mirko, blankProfile());
  assert.equal(irkaView.body.summary.todayWeight, 99);
  assert.equal(irkaView.body.summary.start.w, 100);
});

test('data API validates ranges, dates, entries, and profile shape without saving invalid data', async (t) => {
  const { baseUrl } = await serverFor(t);
  const account = await register(baseUrl, 'validation@example.test', 'Проверка');
  assert.equal(account.status, 201);

  const validProfile = {
    goal: { weight: 70, date: dateAfterToday() },
    start: { d: todayInBulgaria(), w: 90 },
    entries: [{ d: todayInBulgaria(), w: 89 }]
  };
  const invalidProfiles = [
    { ...validProfile, goal: null },
    { ...validProfile, goal: { weight: 401, date: null } },
    { ...validProfile, goal: { weight: 70, date: todayInBulgaria() } },
    { ...validProfile, start: { d: '2026-02-30', w: 90 } },
    { ...validProfile, start: { d: dateAfterToday(), w: 90 } },
    { ...validProfile, entries: [{ d: todayInBulgaria(), w: 19 }] },
    { ...validProfile, entries: [{ d: todayInBulgaria(), w: 401 }] },
    { ...validProfile, entries: [{ d: todayInBulgaria(), w: 90, c: 251 }] },
    { ...validProfile, entries: [{ d: todayInBulgaria(), w: 90, n: 'x'.repeat(201) }] },
    { ...validProfile, entries: [{ d: todayInBulgaria(), w: 90 }, { d: todayInBulgaria(), w: 89 }] },
    { ...validProfile, entries: Array.from({ length: 5001 }, () => ({ d: todayInBulgaria(), w: 90 })) }
  ];

  for (const profile of invalidProfiles) {
    const response = await request(baseUrl, '/api/data', {
      method: 'PUT',
      cookie: account.cookie,
      body: { v: 1, activeProfile: 'irka', profiles: { irka: profile, mirko: blankProfile() } }
    });
    assert.equal(response.status, 400);
  }

  const invalidTracker = await request(baseUrl, '/api/data', {
    method: 'PUT',
    cookie: account.cookie,
    body: { v: 1, activeProfile: 'unknown', profiles: { irka: validProfile, mirko: blankProfile() } }
  });
  assert.equal(invalidTracker.status, 400);
  const invalidProfilesContainer = await request(baseUrl, '/api/data', {
    method: 'PUT',
    cookie: account.cookie,
    body: { v: 1, activeProfile: 'irka', profiles: [] }
  });
  assert.equal(invalidProfilesContainer.status, 400);

  const unchanged = await request(baseUrl, '/api/data', { cookie: account.cookie });
  assert.deepEqual(unchanged.body.data.profiles.irka, blankProfile());
});

test('existing accounts can set their tab once and migrate their previous tracker data', async (t) => {
  const today = todayInBulgaria();
  const { baseUrl } = await serverFor(t, {
    seed(db) {
      db.exec(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE tracker_data (
          user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          data TEXT NOT NULL,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
      const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
        .run('legacy@example.test', bcrypt.hashSync('Legacy-password-2026', 4));
      db.prepare('INSERT INTO tracker_data (user_id, data) VALUES (?, ?)')
        .run(result.lastInsertRowid, JSON.stringify({
          goal: { weight: 75, date: null },
          start: { d: today, w: 95, wa: 100 },
          entries: [{ d: today, w: 94 }]
        }));
    }
  });

  const login = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    body: { email: 'legacy@example.test', password: 'Legacy-password-2026' }
  });
  assert.equal(login.status, 200);
  assert.equal(login.body.user.profileKey, null);

  const beforeSetup = await request(baseUrl, '/api/data', { cookie: login.cookie });
  assert.equal(beforeSetup.status, 409);
  const invalidSetup = await request(baseUrl, '/api/auth/profile', {
    method: 'POST',
    cookie: login.cookie,
    body: { displayName: '  ' }
  });
  assert.equal(invalidSetup.status, 400);

  const setup = await request(baseUrl, '/api/auth/profile', {
    method: 'POST',
    cookie: login.cookie,
    body: { displayName: 'Legacy user' }
  });
  assert.equal(setup.status, 200);
  assert.equal(setup.body.user.profileKey, 'irka');
  const migrated = await request(baseUrl, '/api/data', { cookie: login.cookie });
  assert.equal(migrated.body.data.profiles.irka.start.w, 95);
  assert.equal(migrated.body.data.profiles.irka.entries[0].w, 94);
  assert.equal(migrated.body.data.profiles.irka.goal.weight, 75);

  const setupAgain = await request(baseUrl, '/api/auth/profile', {
    method: 'POST',
    cookie: login.cookie,
    body: { displayName: 'Ignored rename' }
  });
  assert.equal(setupAgain.status, 200);
  assert.equal(setupAgain.body.user.displayName, 'Legacy user');

  const otherParticipant = await register(baseUrl, 'second@example.test', 'Second');
  assert.equal(otherParticipant.status, 201);
  assert.equal(otherParticipant.body.user.profileKey, 'mirko');
});

test('authentication endpoints enforce the attempt limit and API reports missing routes', async (t) => {
  const { baseUrl } = await serverFor(t);
  const missingRoute = await request(baseUrl, '/api/not-a-route');
  assert.equal(missingRoute.status, 404);
  assert.match(missingRoute.body.error, /не съществува/);

  const responses = [];
  for (let attempt = 0; attempt < 11; attempt++) {
    responses.push(await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'nobody@example.test', password: 'Wrong-password-2026' }
    }));
  }
  assert.equal(responses.filter((response) => response.status === 401).length, 10);
  assert.equal(responses[10].status, 429);
  assert.match(responses[10].body.error, /15 минути/);
});

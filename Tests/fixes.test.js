'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { blankProfile, dateAfterToday, request, startTestServer } = require('./helpers');

async function serverFor(t, options) {
  const server = await startTestServer(options);
  t.after(() => server.stop());
  return server;
}

function register(baseUrl, email, displayName, password = 'Test-password-2026') {
  return request(baseUrl, '/api/auth/register', { method: 'POST', body: { email, password, displayName } });
}

test('a saved goal date that has passed does not block later saves', async (t) => {
  const { baseUrl, databasePath } = await serverFor(t);
  const irka = await register(baseUrl, 'irka@example.test', 'Irena');
  const profile = blankProfile();
  profile.goal = { weight: 60, date: dateAfterToday(5) };
  const body = { v: 1, activeProfile: 'irka', profiles: { irka: profile, mirko: blankProfile() } };
  assert.equal((await request(baseUrl, '/api/data', { method: 'PUT', body, cookie: irka.cookie })).status, 200);

  // Simulate the goal date passing by moving it into the past directly in the database.
  const Database = require('better-sqlite3');
  const db = new Database(databasePath);
  const row = JSON.parse(db.prepare('SELECT data FROM competition_data WHERE id = 1').get().data);
  row.profiles.irka.goal.date = '2020-01-01';
  db.prepare('UPDATE competition_data SET data = ? WHERE id = 1').run(JSON.stringify(row));
  db.close();

  const kept = blankProfile();
  kept.goal = { weight: 60, date: '2020-01-01' };
  kept.entries = [{ d: '2021-01-01', w: 61 }];
  const keepBody = { v: 1, activeProfile: 'irka', profiles: { irka: kept, mirko: blankProfile() } };
  assert.equal((await request(baseUrl, '/api/data', { method: 'PUT', body: keepBody, cookie: irka.cookie })).status, 200);

  // A different past date is still rejected.
  kept.goal.date = '2020-02-02';
  assert.equal((await request(baseUrl, '/api/data', { method: 'PUT', body: keepBody, cookie: irka.cookie })).status, 400);
});

test('ALLOWED_EMAILS limits who can register', async (t) => {
  const { baseUrl } = await serverFor(t, { env: { ALLOWED_EMAILS: 'irka@example.test, Mirko@Example.test' } });
  const stranger = await register(baseUrl, 'stranger@example.test', 'Stranger');
  assert.equal(stranger.status, 403);
  assert.equal((await register(baseUrl, 'mirko@example.test', 'Mirko')).status, 201);
});

test('password change requires the current password and signs out other sessions', async (t) => {
  const { baseUrl } = await serverFor(t);
  const first = await register(baseUrl, 'irka@example.test', 'Irena');
  const second = await request(baseUrl, '/api/auth/login', {
    method: 'POST', body: { email: 'irka@example.test', password: 'Test-password-2026' }
  });
  const wrong = await request(baseUrl, '/api/auth/password', {
    method: 'POST', cookie: first.cookie, body: { currentPassword: 'nope-nope-nope', newPassword: 'Brand-new-password-1' }
  });
  assert.equal(wrong.status, 401);
  const short = await request(baseUrl, '/api/auth/password', {
    method: 'POST', cookie: first.cookie, body: { currentPassword: 'Test-password-2026', newPassword: 'short' }
  });
  assert.equal(short.status, 400);
  const changed = await request(baseUrl, '/api/auth/password', {
    method: 'POST', cookie: first.cookie, body: { currentPassword: 'Test-password-2026', newPassword: 'Brand-new-password-1' }
  });
  assert.equal(changed.status, 200);
  assert.deepEqual((await request(baseUrl, '/api/auth/session', { cookie: second.cookie })).body, { user: null });
  assert.equal((await request(baseUrl, '/api/auth/session', { cookie: changed.cookie })).body.user.email, 'irka@example.test');
  const oldLogin = await request(baseUrl, '/api/auth/login', {
    method: 'POST', body: { email: 'irka@example.test', password: 'Test-password-2026' }
  });
  assert.equal(oldLogin.status, 401);
});

test('responses carry security headers', async (t) => {
  const { baseUrl } = await serverFor(t);
  const page = await fetch(`${baseUrl}/`);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  const api = await fetch(`${baseUrl}/api/auth/session`);
  assert.equal(api.headers.get('cache-control'), 'no-store');
});

test('forgotten password: one-time code from the server console resets the password', async (t) => {
  const server = await serverFor(t);
  const { baseUrl } = server;
  await register(baseUrl, 'irka@example.test', 'Irena');

  // Unknown e-mail gets the same answer and prints nothing.
  const unknown = await request(baseUrl, '/api/auth/forgot', { method: 'POST', body: { email: 'nobody@example.test' } });
  assert.equal(unknown.status, 200);
  assert.doesNotMatch(server.output(), /nobody@example\.test/);

  const asked = await request(baseUrl, '/api/auth/forgot', { method: 'POST', body: { email: 'IRKA@example.test' } });
  assert.equal(asked.status, 200);
  await new Promise((resolve) => setTimeout(resolve, 100));
  const match = server.output().match(/Еднократен код: ([A-Z0-9]{4}-[A-Z0-9]{4})/);
  assert.ok(match, 'reset code should be printed in the server output');

  const wrong = await request(baseUrl, '/api/auth/reset', {
    method: 'POST', body: { email: 'irka@example.test', code: 'AAAA-AAAA', newPassword: 'Recovered-password-1' }
  });
  assert.equal(wrong.status, 400);

  const reset = await request(baseUrl, '/api/auth/reset', {
    method: 'POST', body: { email: 'irka@example.test', code: match[1].toLowerCase(), newPassword: 'Recovered-password-1' }
  });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.user.email, 'irka@example.test');

  // The code works only once.
  const again = await request(baseUrl, '/api/auth/reset', {
    method: 'POST', body: { email: 'irka@example.test', code: match[1], newPassword: 'Another-password-22' }
  });
  assert.equal(again.status, 400);

  const login = await request(baseUrl, '/api/auth/login', {
    method: 'POST', body: { email: 'irka@example.test', password: 'Recovered-password-1' }
  });
  assert.equal(login.status, 200);
});

test('reset-password script sets a temporary password', async (t) => {
  const server = await serverFor(t);
  await register(server.baseUrl, 'irka@example.test', 'Irena');
  const { execFileSync } = require('node:child_process');
  const path = require('node:path');
  const out = execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'reset-password.js'), 'irka@example.test'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DATABASE_PATH: server.databasePath },
    encoding: 'utf8'
  });
  const temporary = out.match(/irka@example\.test:\s+(\S+)/)[1];
  const login = await request(server.baseUrl, '/api/auth/login', {
    method: 'POST', body: { email: 'irka@example.test', password: temporary }
  });
  assert.equal(login.status, 200);
});

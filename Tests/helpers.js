'use strict';

const { spawn } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');

const projectRoot = path.resolve(__dirname, '..');

async function freePort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const { port } = listener.address();
  await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startTestServer({ seed, env: extraEnv } = {}) {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'kiloscalendai-tests-'));
  const databasePath = path.join(temporaryDirectory, 'tracker.sqlite');
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  if (seed) {
    const db = new Database(databasePath);
    try {
      seed(db);
    } finally {
      db.close();
    }
  }

  const child = spawn(process.execPath, ['server.js'], {
    cwd: projectRoot,
    env: {
      ...process.env,
      SESSION_SECRET: 'automated-test-session-secret-with-more-than-32-characters',
      DATABASE_PATH: databasePath,
      HOST: '127.0.0.1',
      PORT: String(port),
      ...(extraEnv || {})
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { output += chunk.toString(); });

  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      throw new Error(`Test server exited during startup: ${output}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/auth/session`);
      if (response.ok) break;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  if (Date.now() >= deadline) {
    child.kill();
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    throw new Error(`Test server did not start: ${output}`);
  }

  return {
    baseUrl,
    databasePath,
    output: () => output,
    async stop() {
      if (child.exitCode === null) {
        const exited = once(child, 'exit');
        child.kill();
        await exited;
      }
      fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
  };
}

async function request(baseUrl, route, { method = 'GET', body, cookie } = {}) {
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(cookie ? { cookie } : {})
    },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    cookie: response.headers.get('set-cookie')?.split(';')[0] || cookie,
    headers: response.headers
  };
}

function todayInBulgaria() {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Sofia',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());
}

function dateAfterToday(days = 1) {
  const date = new Date(`${todayInBulgaria()}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function blankProfile() {
  return {
    goal: { weight: null, date: null },
    start: null,
    entries: []
  };
}

module.exports = {
  dateAfterToday,
  blankProfile,
  request,
  startTestServer,
  todayInBulgaria
};

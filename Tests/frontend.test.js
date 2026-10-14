'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

test('page has the competition branding and no longer uses the pink accent', () => {
  assert.match(html, /<title>Надпревара с килограми<\/title>/);
  assert.match(html, /<h1 id="authTitle">Надпревара с килограми<\/h1>/);
  assert.match(html, /--accent:#087F83/);
  assert.match(html, /--accent:#55D6D2/);
  assert.doesNotMatch(html, /#B83272|#F08CB8|#2B0B1B|rgba\(184,50,114|rgba\(240,140,184/);
});

test('page markup exposes the login, registration, participant tabs, and reporting controls', () => {
  assert.match(html, /id="authPage"/);
  assert.match(html, /id="authModeToggle">Регистрация<\/button>/);
  assert.match(html, /id="registerName"/);
  assert.match(html, /id="profileSetupForm"/);
  assert.match(html, /id="appPage"/);
  assert.match(html, /class="profile-tab"[^>]+data-profile="irka"/);
  assert.match(html, /class="profile-tab"[^>]+data-profile="mirko"/);
  assert.match(html, /id="summary"/);
  assert.match(html, /id="logoutBtn">Изход<\/button>/);
  assert.match(html, /id="f-entry"/);
  assert.match(html, /Записвай теглото всеки ден\. В петък добавяй и мерките\./);
  assert.match(html, /id="f-start"/);
  assert.match(html, /id="f-goal"/);
  assert.match(html, /id="chartBox"/);
  assert.match(html, /id="hist"/);
});

test('logout is positioned in the page header and participant tabs are enlarged', () => {
  assert.match(html, /\.account-actions\.top-actions\{position:absolute;top:0;right:0/);
  assert.match(html, /\.profile-tab\{[^}]*padding:10px 18px/);
  assert.match(html, /<div class="account-buttons top-actions account-actions" id="accountActions"/);
});

test('inline browser JavaScript parses successfully', () => {
  const script = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(script, 'expected an inline application script');
  assert.doesNotThrow(() => new vm.Script(script[1]));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkIdentity, stripIdentityHeaders, baselineHeaders, crossSiteReadBlocked,
  PublicError, publicError, readBounded,
} from './sites-security.mjs';

const h = (o) => new Headers(o);

test('identity is unchanged until an allowlist is configured', () => {
  assert.deepEqual(checkIdentity(h({ 'oai-authenticated-user-id': 'u1', host: 'x.site' })),
    { userId: 'u1', allowed: true, reason: 'no-allowlist-configured' });
  assert.equal(checkIdentity(h({ host: 'x.site' })).reason, 'signed-out');
});

test('allowlisted ids and canonical hosts are enforced', () => {
  const env = { allowedUserIds: 'u1, u2', canonicalHosts: 'atlas.example.site' };
  assert.equal(checkIdentity(h({ 'oai-authenticated-user-id': 'u1', host: 'atlas.example.site' }), env).allowed, true);
  assert.equal(checkIdentity(h({ 'oai-authenticated-user-id': 'u1', host: 'ATLAS.example.site:443' }), env).allowed, true);
  assert.equal(checkIdentity(h({ 'oai-authenticated-user-id': 'u3', host: 'atlas.example.site' }), env).reason, 'user-not-allowed');
  assert.equal(checkIdentity(h({ 'oai-authenticated-user-id': 'u1', host: 'preview.workers.dev' }), env).reason, 'host-not-canonical');
});

test('dev servers drop forged identity headers', () => {
  const out = stripIdentityHeaders(h({ 'OAI-Authenticated-User-Id': 'forged', 'oai-authenticated-user-email': 'x@y', accept: '*/*' }));
  assert.equal(out.get('oai-authenticated-user-id'), null);
  assert.equal(out.get('oai-authenticated-user-email'), null);
  assert.equal(out.get('accept'), '*/*');
});

test('baseline headers refuse framing', () => {
  const headers = baselineHeaders();
  assert.equal(headers['X-Frame-Options'], 'DENY');
  assert.match(headers['Content-Security-Policy'], /frame-ancestors 'none'/);
});

test('cross-site reads are blocked, including sibling Sites (same-site)', () => {
  assert.equal(crossSiteReadBlocked(h({})), false);
  assert.equal(crossSiteReadBlocked(h({ 'sec-fetch-site': 'same-origin' })), false);
  assert.equal(crossSiteReadBlocked(h({ 'sec-fetch-site': 'none' })), false);
  assert.equal(crossSiteReadBlocked(h({ 'sec-fetch-site': 'same-site' })), true);
  assert.equal(crossSiteReadBlocked(h({ 'sec-fetch-site': 'cross-site' })), true);
});

test('errors never leak internals', () => {
  const logged = [];
  const log = (e) => logged.push(e);
  assert.deepEqual(publicError(new PublicError('Title is required.'), { log }), { status: 400, body: { error: 'Title is required.' } });
  const internal = publicError(new Error('D1_ERROR: no such table: secrets_v2'), { log });
  assert.equal(internal.status, 503);
  assert.doesNotMatch(internal.body.error, /secrets|D1/);
  const other = publicError(new TypeError("Cannot read properties of undefined (reading 'token')"), { log });
  assert.equal(other.status, 500);
  assert.doesNotMatch(other.body.error, /token/);
  assert.equal(logged.length, 2);
});

test('request bodies are bounded by declared and actual size', async () => {
  const ok = await readBounded(new Request('https://x/', { method: 'POST', body: 'hello' }), 10);
  assert.equal(new TextDecoder().decode(ok), 'hello');
  await assert.rejects(readBounded(new Request('https://x/', { method: 'POST', body: 'x'.repeat(11) }), 10), { status: 413 });
  const lying = new Request('https://x/', { method: 'POST', body: 'x'.repeat(50), headers: { 'content-length': '5' } });
  await assert.rejects(readBounded(lying, 10), { status: 413 });
});

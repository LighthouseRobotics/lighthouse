// node --test formats/bundle/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyBundle, strictJson, checkPath, crc32, BundleError } from '../js/bundle-verify.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const corpusDir = mkdtempSync(join(tmpdir(), 'bundle-corpus-'));
const made = spawnSync('python3', [join(here, 'corpus.py'), corpusDir], { encoding: 'utf8' });
if (made.status !== 0) throw new Error('corpus.py failed: ' + made.stderr);
const expected = JSON.parse(readFileSync(join(corpusDir, 'expected.json'), 'utf8'));
test.after(() => rmSync(corpusDir, { recursive: true, force: true }));

async function codeOf(bytes, options) {
  try {
    await verifyBundle(bytes, options);
    return 'OK';
  } catch (error) {
    if (error instanceof BundleError) return error.code;
    return 'CRASH ' + error.name + ': ' + error.message;
  }
}

test('the JS verifier agrees with the shared corpus on every case', async () => {
  const names = readdirSync(corpusDir).filter((n) => n.endsWith('.zip')).sort();
  assert.equal(names.length, Object.keys(expected).length);
  assert.ok(names.length >= 40, 'corpus is unexpectedly small');
  const mismatches = [];
  for (const name of names) {
    const got = await codeOf(readFileSync(join(corpusDir, name)));
    if (got !== expected[name]) mismatches.push(`${name}: expected ${expected[name]}, got ${got}`);
  }
  assert.deepEqual(mismatches, []);
});

test('a verified report carries the producer, reality and both boundaries', async () => {
  const report = await verifyBundle(readFileSync(join(corpusDir, 'ok_source_and_omission.zip')));
  assert.equal(report.status, 'verified');
  assert.equal(report.reality, 'synthetic');
  assert.deepEqual(report.producer, { app: 'corpus', version: '1' });
  assert.deepEqual(report.omissions, [{ what: 'originals', why: 'too large' }]);
  assert.match(report.boundary, /Sender authenticity/);
  assert.equal(report.producerBoundary, 'Synthetic conformance case.');
  assert.match(report.bundleSha256, /^[0-9a-f]{64}$/);
});

test('expected checksum mismatch is E_CHECKSUM and a match passes', async () => {
  const bytes = readFileSync(join(corpusDir, 'ok_basic.zip'));
  const report = await verifyBundle(bytes);
  assert.equal(await codeOf(bytes, { expectedSha256: '0'.repeat(64) }), 'E_CHECKSUM');
  assert.equal(await codeOf(bytes, { expectedSha256: report.bundleSha256 }), 'OK');
});

test('limits are enforced before reading members', async () => {
  const bytes = readFileSync(join(corpusDir, 'ok_basic.zip'));
  assert.equal(await codeOf(bytes, { limits: { entries: 2 } }), 'E_LIMIT');
  assert.equal(await codeOf(bytes, { limits: { archive_bytes: 100 } }), 'E_SIZE');
  assert.equal(await codeOf(bytes, { limits: { directory_bytes: 10 } }), 'E_LIMIT');
});

test('a deflate stream longer than recorded is rejected, not trusted', async () => {
  // Inflater that ignores the bound and returns extra bytes.
  const liar = async (data, max) => new Uint8Array(max + 10);
  assert.equal(await codeOf(readFileSync(join(corpusDir, 'ok_basic.zip')), { inflateRaw: liar }), 'E_ZIP');
});

test('strict JSON rejects duplicate keys, NaN and a BOM, and keeps integers exact', () => {
  const enc = (s) => new TextEncoder().encode(s);
  assert.throws(() => strictJson(enc('{"a":1,"a":2}')), { code: 'E_MANIFEST' });
  assert.throws(() => strictJson(enc('{"a":NaN}')), { code: 'E_MANIFEST' });
  assert.throws(() => strictJson(new Uint8Array([0xef, 0xbb, 0xbf, ...enc('{}')])), { code: 'E_MANIFEST' });
  assert.throws(() => strictJson(enc('{"a":"x\ny"}')), { code: 'E_MANIFEST' });
  const big = strictJson(enc('{"n":9007199254740993,"f":5.0}'));
  assert.equal(big.n.value, 9007199254740993n);
  assert.equal(big.f.isInt, false);
});

test('path rules', () => {
  for (const ok of ['payload/a', 'payload/sub/b.txt', 'lighthouse-bundle.json', 'payload/café']) checkPath(ok);
  for (const bad of ['', 'payload/../x', '/payload/x', 'payload\\x', 'x/y', 'payload/a:b', 'payload/aux', 'payload/x ', 'payload//x']) {
    assert.throws(() => checkPath(bad), { code: 'E_PATH' }, bad);
  }
});

test('crc32 matches the standard check value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

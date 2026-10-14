// lighthouse-bundle/v1 verifier for browsers and Node 20+.
//
// Mirrors formats/bundle/lighthouse_bundle.py check for check, in the same
// order, so both return the same rejection code for the same file. The shared
// corpus in formats/bundle/tests/corpus.py enforces that.
//
// No dependencies. Needs WebCrypto (globalThis.crypto.subtle) and either
// Node's zlib or the browser's DecompressionStream for deflated members.

export const SCHEMA = 'lighthouse-bundle/v1';
export const REPORT_SCHEMA = 'lighthouse-bundle-verification/v1';
export const MANIFEST = 'lighthouse-bundle.json';
export const PAYLOAD = 'payload/';
export const REALITY = ['physical', 'simulated', 'synthetic', 'unknown'];
export const LIMITS = Object.freeze({
  archive_bytes: 2 ** 30,
  total_uncompressed: 2 * 2 ** 30,
  entries: 20000,
  directory_bytes: 8 * 2 ** 20,
  manifest_bytes: 16 * 2 ** 20,
  ratio: 200,
  path_bytes: 512,
});
export const VERIFIER_BOUNDARY =
  'Verified that every listed file is present with the recorded byte count and SHA-256, ' +
  'and that the archive holds nothing else. Sender authenticity, completeness beyond the ' +
  "listed files and the truth of the payload's own claims are not established.";

const HEX64 = /^[0-9a-f]{64}$/;
const APP = /^[a-z0-9][a-z0-9-]{0,63}$/;
const COMMIT = /^[0-9a-f]{7,64}$/;
const CREATED = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$/;
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const TOP_KEYS = new Set(['schema', 'producer', 'created', 'payloadSchema', 'reality', 'files', 'omissions', 'boundary', 'source']);
const REQUIRED = ['schema', 'producer', 'created', 'payloadSchema', 'reality', 'files', 'omissions', 'boundary'];
const S_IFMT = 0o170000, S_IFREG = 0o100000, S_IFDIR = 0o040000;

export class BundleError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BundleError';
    this.code = code;
  }
}
const fail = (code, message) => { throw new BundleError(code, message); };

// ------------------------------------------------------------------ paths

const codePoints = (s) => [...s];

export function checkPath(name, limits = LIMITS) {
  if (typeof name !== 'string' || !name) fail('E_PATH', 'Empty member path.');
  if (new TextEncoder().encode(name).length > limits.path_bytes) fail('E_PATH', 'Member path is too long: ' + name.slice(0, 80));
  if (name.normalize('NFC') !== name) fail('E_PATH', 'Member path is not NFC-normalized: ' + name);
  if (name.includes('\\') || name.includes(':') || name.startsWith('/')) fail('E_PATH', 'Absolute or non-portable member path: ' + name);
  for (const ch of codePoints(name)) {
    const c = ch.codePointAt(0);
    if (c < 0x20 || c === 0x7f) fail('E_PATH', 'Control character in member path.');
  }
  const body = name.endsWith('/') ? name.slice(0, -1) : name;
  for (const segment of body.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') fail('E_PATH', "Empty, '.' or '..' segment in member path: " + name);
    if (/[ .]$/.test(segment) || RESERVED.test(segment)) fail('E_PATH', 'Segment not portable to Windows: ' + name);
  }
  if (name !== MANIFEST && !name.startsWith(PAYLOAD)) fail('E_PATH', 'Member outside payload/: ' + name);
  return name;
}

export const collisionKey = (name) => name.normalize('NFC').toLowerCase();

// ------------------------------------------------------------------ strict JSON
// JSON.parse silently keeps the last duplicate key and cannot tell 5 from 5.0,
// so the manifest is read with a small RFC 8259 parser that matches Python's
// json module with duplicate keys and non-finite constants rejected.

export class JsonNumber {
  constructor(text) {
    this.text = text;
    this.isInt = !/[.eE]/.test(text);
    this.value = this.isInt ? BigInt(text) : Number(text);
  }
}

export function strictJson(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail('E_MANIFEST', 'Manifest is not UTF-8.');
  }
  let i = 0;
  const bad = (what) => fail('E_MANIFEST', `Manifest is not valid JSON: ${what} at ${i}`);
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const value = (depth) => {
    if (depth > 512) bad('nesting too deep');
    ws();
    const ch = text[i];
    if (ch === '{') {
      i++;
      const out = Object.create(null);
      const keys = new Set();
      ws();
      if (text[i] === '}') { i++; return out; }
      for (;;) {
        ws();
        if (text[i] !== '"') bad('expected key');
        const key = string();
        if (keys.has(key)) fail('E_MANIFEST', 'Duplicate JSON key: ' + key);
        keys.add(key);
        ws();
        if (text[i] !== ':') bad('expected colon');
        i++;
        out[key] = value(depth + 1);
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return out; }
        bad('expected , or }');
      }
    }
    if (ch === '[') {
      i++;
      const out = [];
      ws();
      if (text[i] === ']') { i++; return out; }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return out; }
        bad('expected , or ]');
      }
    }
    if (ch === '"') return string();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    if (text.startsWith('NaN', i) || text.startsWith('Infinity', i) || text.startsWith('-Infinity', i)) {
      fail('E_MANIFEST', 'Non-finite JSON number.');
    }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 400));
    if (!m || !m[0]) bad('unexpected character');
    i += m[0].length;
    return new JsonNumber(m[0]);
  };
  const string = () => {
    i++;
    let out = '';
    for (;;) {
      if (i >= text.length) bad('unterminated string');
      const ch = text[i];
      const code = ch.charCodeAt(0);
      if (ch === '"') { i++; return out; }
      if (code < 0x20) bad('control character in string');
      if (ch === '\\') {
        const e = text[i + 1];
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e];
        if (simple !== undefined) { out += simple; i += 2; continue; }
        if (e === 'u') {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) bad('bad unicode escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        bad('bad escape');
      }
      out += ch;
      i++;
    }
  };
  const result = value(0);
  ws();
  if (i !== text.length) bad('extra data');
  return result;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof JsonNumber);
const keysOf = (o) => Object.keys(o);
const str = (v, limit, field) => {
  if (typeof v !== 'string' || !v || codePoints(v).length > limit) {
    fail('E_MANIFEST', `${field} must be a non-empty string of at most ${limit} characters.`);
  }
  return v;
};

export function checkManifest(m, limits = LIMITS) {
  if (!isObj(m)) fail('E_MANIFEST', 'Manifest must be a JSON object.');
  const unknown = keysOf(m).filter((k) => !TOP_KEYS.has(k) && !k.startsWith('x-'));
  if (unknown.length) fail('E_MANIFEST', 'Unknown manifest keys: ' + unknown.sort().join(', '));
  const missing = REQUIRED.filter((k) => !(k in m));
  if (missing.length) fail('E_MANIFEST', 'Missing manifest keys: ' + missing.sort().join(', '));
  if (m.schema !== SCHEMA) fail('E_MANIFEST', 'Unsupported schema: ' + JSON.stringify(m.schema));
  const p = m.producer;
  if (!isObj(p) || keysOf(p).some((k) => !['app', 'version', 'repository', 'commit'].includes(k))) {
    fail('E_MANIFEST', 'producer must hold only app, version, repository and commit.');
  }
  if (typeof p.app !== 'string' || !APP.test(p.app)) fail('E_MANIFEST', 'producer.app must be a lowercase slug.');
  str(p.version, 100, 'producer.version');
  if ('repository' in p) str(p.repository, 200, 'producer.repository');
  if ('commit' in p && (typeof p.commit !== 'string' || !COMMIT.test(p.commit))) {
    fail('E_MANIFEST', 'producer.commit must be 7-64 lowercase hex characters.');
  }
  if (typeof m.created !== 'string' || !CREATED.test(m.created)) fail('E_MANIFEST', 'created must be an RFC 3339 UTC time ending in Z.');
  str(m.payloadSchema, 200, 'payloadSchema');
  if (!REALITY.includes(m.reality)) fail('E_MANIFEST', 'reality must be one of ' + REALITY.join(', ') + '.');
  str(m.boundary, 4000, 'boundary');
  if (!Array.isArray(m.omissions) || m.omissions.length > 1000) fail('E_MANIFEST', 'omissions must be a list of at most 1000 entries.');
  for (const o of m.omissions) {
    if (!isObj(o) || keysOf(o).length !== 2 || !('what' in o) || !('why' in o)) fail('E_MANIFEST', "Each omission needs exactly 'what' and 'why'.");
    str(o.what, 500, 'omission.what');
    str(o.why, 2000, 'omission.why');
  }
  if ('source' in m) {
    const s = m.source;
    if (!isObj(s) || keysOf(s).some((k) => !['id', 'description'].includes(k)) || !('id' in s)) {
      fail('E_MANIFEST', 'source must hold id and optional description.');
    }
    str(s.id, 500, 'source.id');
    if ('description' in s) str(s.description, 2000, 'source.description');
  }
  const files = m.files;
  if (!Array.isArray(files) || !files.length || files.length > limits.entries) {
    fail('E_MANIFEST', 'files must be a non-empty list within the entry limit.');
  }
  let previous = null;
  for (const e of files) {
    const k = isObj(e) ? keysOf(e) : null;
    if (!k || k.some((x) => !['path', 'bytes', 'sha256', 'mediaType'].includes(x)) || !['path', 'bytes', 'sha256'].every((x) => k.includes(x))) {
      fail('E_MANIFEST', 'Each file needs path, bytes, sha256 and optional mediaType.');
    }
    const path = e.path;
    if (typeof path !== 'string' || !path.startsWith(PAYLOAD) || path.endsWith('/')) fail('E_MANIFEST', 'Listed file paths must be files under payload/.');
    try {
      checkPath(path, limits);
    } catch (error) {
      fail('E_MANIFEST', 'Listed path is unsafe: ' + error.message);
    }
    if (!(e.bytes instanceof JsonNumber) || !e.bytes.isInt || e.bytes.value < 0n) fail('E_MANIFEST', 'bytes must be a non-negative integer: ' + path);
    if (typeof e.sha256 !== 'string' || !HEX64.test(e.sha256)) fail('E_MANIFEST', 'sha256 must be 64 lowercase hex characters: ' + path);
    if ('mediaType' in e) str(e.mediaType, 200, 'mediaType');
    // Python compares str by code point; compare the same way, not by UTF-16 unit.
    if (previous !== null && comparePaths(path, previous) <= 0) fail('E_MANIFEST', 'files must be sorted by path with no duplicates.');
    previous = path;
  }
  return files;
}

function comparePaths(a, b) {
  const x = codePoints(a), y = codePoints(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
}

// ------------------------------------------------------------------ ZIP structure

const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u64 = (b, o) => u32(b, o) + u32(b, o + 4) * 2 ** 32;
const sig = (b, o, s) => o >= 0 && o + 4 <= b.length && b[o] === 0x50 && b[o + 1] === 0x4b && b[o + 2] === s[0] && b[o + 3] === s[1];
const EOCD = [5, 6], LOCATOR = [6, 7], ZIP64_EOCD = [6, 6], CENTRAL = [1, 2], LOCAL = [3, 4];

function lastIndexOfSig(bytes, s, from, lowest) {
  for (let p = from; p >= lowest; p--) if (sig(bytes, p, s)) return p;
  return -1;
}

export function directoryBounds(bytes, limits = LIMITS) {
  const size = bytes.length;
  if (size < 22) fail('E_ZIP', 'Missing ZIP end record.');
  const lowest = size - Math.min(size, 22 + 0xffff);
  let pos = lastIndexOfSig(bytes, EOCD, size - 4, lowest);
  while (pos >= 0) {
    if (pos + 22 <= size && pos + 22 + u16(bytes, pos + 20) === size) break;
    pos = lastIndexOfSig(bytes, EOCD, pos - 1, lowest);
  }
  if (pos < 0) fail('E_ZIP', 'Missing ZIP end record.');
  for (let p = pos + 22; p + 4 <= size; p++) {
    if (sig(bytes, p, EOCD)) fail('E_ZIP', 'Archive comment contains an end-record signature (ambiguous archive).');
  }
  const disk = u16(bytes, pos + 4), cdDisk = u16(bytes, pos + 6), onDisk = u16(bytes, pos + 8);
  let total = u16(bytes, pos + 10), cdSize = u32(bytes, pos + 12), cdOffset = u32(bytes, pos + 16);
  if (disk || cdDisk || onDisk !== total) fail('E_ZIP', 'Multipart ZIP archives are not supported.');
  let directoryEnd = pos;
  if (total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    if (pos < 20) fail('E_ZIP', 'Missing ZIP64 locator.');
    const l = pos - 20;
    const zOffset = u64(bytes, l + 8);
    if (!sig(bytes, l, LOCATOR) || u32(bytes, l + 4) || u32(bytes, l + 16) !== 1 || zOffset + 56 > l) fail('E_ZIP', 'Invalid ZIP64 locator.');
    if (!sig(bytes, zOffset, ZIP64_EOCD) || u32(bytes, zOffset + 16) || u32(bytes, zOffset + 20) || u64(bytes, zOffset + 24) !== u64(bytes, zOffset + 32)) {
      fail('E_ZIP', 'Invalid or multipart ZIP64 end record.');
    }
    total = u64(bytes, zOffset + 32);
    cdSize = u64(bytes, zOffset + 40);
    cdOffset = u64(bytes, zOffset + 48);
    directoryEnd = zOffset;
  }
  if (total > limits.entries) fail('E_LIMIT', `Archive has ${total} entries; the limit is ${limits.entries}.`);
  if (cdSize > limits.directory_bytes) fail('E_LIMIT', 'Central directory exceeds its size limit.');
  if (cdOffset + cdSize !== directoryEnd) fail('E_ZIP', 'Central directory location is inconsistent (prepended or trailing data).');
  if (total === 0) fail('E_ZIP', 'Archive is empty.');
  if (!sig(bytes, 0, LOCAL)) fail('E_ZIP', 'Archive does not start with a member (prepended data).');
  return { count: total, cdOffset, cdSize };
}

function decodeName(raw, utf8) {
  if (utf8) {
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    } catch {
      fail('E_ZIP', 'Member name is not valid UTF-8.');
    }
  }
  // CP437 is only used for messages and duplicate checks; any non-ASCII
  // unflagged name is rejected (E_PATH) before its spelling matters.
  return String.fromCharCode(...raw);
}

function readCentral(bytes, { cdOffset, cdSize }) {
  const entries = [];
  let p = cdOffset;
  const end = cdOffset + cdSize;
  while (p < end) {
    if (p + 46 > end || !sig(bytes, p, CENTRAL)) fail('E_ZIP', 'Bad central directory entry.');
    const flags = u16(bytes, p + 8), method = u16(bytes, p + 10), crc = u32(bytes, p + 16);
    let csize = u32(bytes, p + 20), usize = u32(bytes, p + 24);
    const nameLen = u16(bytes, p + 28), extraLen = u16(bytes, p + 30), commentLen = u16(bytes, p + 32);
    const external = u32(bytes, p + 38);
    let offset = u32(bytes, p + 42);
    const next = p + 46 + nameLen + extraLen + commentLen;
    if (next > end) fail('E_ZIP', 'Central directory entry runs past the directory.');
    const raw = bytes.subarray(p + 46, p + 46 + nameLen);
    const extra = bytes.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
    let e = 0;
    while (e + 4 <= extra.length) {
      const id = u16(extra, e), len = u16(extra, e + 2);
      if (e + 4 + len > extra.length) fail('E_ZIP', 'Corrupt extra field.');
      if (id === 1) {
        let q = e + 4;
        const take = () => {
          if (q + 8 > e + 4 + len) fail('E_ZIP', 'Corrupt ZIP64 extra field.');
          const v = u64(extra, q);
          q += 8;
          return v;
        };
        if (usize === 0xffffffff) usize = take();
        if (csize === 0xffffffff) csize = take();
        if (offset === 0xffffffff) offset = take();
      }
      e += 4 + len;
    }
    const isAscii = raw.every((c) => c < 0x80);
    entries.push({ raw, name: decodeName(raw, flags & 0x800), isAscii, flags, method, crc, csize, usize, external, offset });
    p = next;
  }
  if (p !== end) fail('E_ZIP', 'Central directory size is inconsistent.');
  return entries;
}

function checkMember(m, limits) {
  if (m.name.includes('\0')) fail('E_PATH', 'NUL or separator rewrite in member name.');
  if (!m.isAscii && !(m.flags & 0x800)) fail('E_PATH', 'Non-ASCII member name without the UTF-8 flag.');
  checkPath(m.name, limits);
  if (m.flags & 0x2061) fail('E_MEMBER', 'Encrypted or patched member: ' + m.name);
  if (m.method !== 0 && m.method !== 8) fail('E_MEMBER', 'Unsupported compression method: ' + m.name);
  const mode = (m.external >>> 16) & S_IFMT;
  if (m.name.endsWith('/')) {
    if (m.usize || (mode !== 0 && mode !== S_IFDIR)) fail('E_MEMBER', 'Directory entry with content or wrong type: ' + m.name);
    return false;
  }
  if (mode !== 0 && mode !== S_IFREG) fail('E_MEMBER', 'Non-regular member (symlink or device): ' + m.name);
  if (m.method === 0 && m.csize !== m.usize) fail('E_MEMBER', 'Stored member with mismatched sizes: ' + m.name);
  if (m.usize > 2 ** 20 && m.usize > m.csize * limits.ratio) fail('E_LIMIT', 'Compression ratio exceeds the limit: ' + m.name);
  return true;
}

function checkLayout(bytes, entries, cdOffset) {
  const spans = [];
  for (const m of entries) {
    const o = m.offset;
    if (o + 30 > bytes.length || !sig(bytes, o, LOCAL)) fail('E_ZIP', 'Missing local header: ' + m.name);
    const nameLen = u16(bytes, o + 26), extraLen = u16(bytes, o + 28);
    const raw = bytes.subarray(o + 30, o + 30 + nameLen);
    if (raw.length !== m.raw.length || raw.some((c, i) => c !== m.raw[i])) fail('E_ZIP', 'Local header name differs from the directory: ' + m.name);
    m.dataStart = o + 30 + nameLen + extraLen;
    spans.push([o, m.dataStart + m.csize, m.name]);
  }
  spans.sort((a, b) => a[0] - b[0]);
  spans.forEach(([, end, name], i) => {
    const limit = i + 1 < spans.length ? spans[i + 1][0] : cdOffset;
    if (end > limit) fail('E_ZIP', 'Member data overlaps the next member or the directory: ' + name);
  });
}

// ------------------------------------------------------------------ data

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(data) {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function defaultInflateRaw(data, maxOutput) {
  if (typeof process !== 'undefined' && process.versions?.node) {
    const zlib = await import('node:zlib');
    return new Uint8Array(zlib.inflateRawSync(data, { maxOutputLength: Math.max(1, maxOutput) }));
  }
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxOutput) {
      await reader.cancel();
      throw new RangeError('output exceeds the recorded size');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let p = 0;
  for (const c of chunks) { out.set(c, p); p += c.length; }
  return out;
}

async function memberData(bytes, m, inflateRaw) {
  const compressed = bytes.subarray(m.dataStart, m.dataStart + m.csize);
  if (compressed.length !== m.csize) throw new Error('member data is truncated');
  // Bound output at recorded size + 1 so a longer stream is detected, not trusted.
  const data = m.method === 0 ? compressed : await inflateRaw(compressed, m.usize + 1);
  if (data.length !== m.usize) throw new Error('length differs from the directory');
  if (crc32(data) !== m.crc) throw new Error('Bad CRC-32');
  return data;
}

async function sha256Hex(data) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ verify

export async function verifyBundle(input, { expectedSha256, limits: overrides, inflateRaw = defaultInflateRaw } = {}) {
  const limits = { ...LIMITS, ...(overrides || {}) };
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length > limits.archive_bytes) fail('E_SIZE', 'Archive exceeds its size limit.');
  const bounds = directoryBounds(bytes, limits);
  const bundleSha256 = await sha256Hex(bytes);
  if (expectedSha256 != null && expectedSha256 !== bundleSha256) fail('E_CHECKSUM', 'Bundle SHA-256 differs from the expected value.');
  const entries = readCentral(bytes, bounds);
  if (entries.length !== bounds.count) fail('E_ZIP', 'Central directory count differs from its end record.');
  const seen = new Set(), keys = new Set(), members = new Map();
  let total = 0;
  for (const m of entries) {
    if (seen.has(m.name)) fail('E_PATH', 'Duplicate member: ' + m.name);
    seen.add(m.name);
    const key = collisionKey(m.name);
    if (keys.has(key)) fail('E_PATH', 'Members differ only by case or normalization: ' + m.name);
    keys.add(key);
    if (checkMember(m, limits)) {
      members.set(m.name, m);
      total += m.usize;
    }
  }
  checkLayout(bytes, entries, bounds.cdOffset);
  if (total > limits.total_uncompressed) fail('E_LIMIT', 'Declared uncompressed size exceeds the limit.');
  if (!members.has(MANIFEST)) fail('E_MANIFEST', 'Missing ' + MANIFEST + '.');
  const mm = members.get(MANIFEST);
  if (mm.usize > limits.manifest_bytes) fail('E_LIMIT', 'Member exceeds its size limit: ' + MANIFEST);
  let manifestBytes;
  try {
    manifestBytes = await memberData(bytes, mm, inflateRaw);
  } catch (error) {
    fail('E_ZIP', 'Corrupt manifest member: ' + error.message);
  }
  const manifest = strictJson(manifestBytes);
  const files = checkManifest(manifest, limits);
  const listed = new Set(files.map((e) => e.path));
  const present = [...members.keys()].filter((n) => n !== MANIFEST);
  const extra = present.filter((n) => !listed.has(n)).sort();
  const absent = [...listed].filter((n) => !members.has(n)).sort();
  if (extra.length || absent.length) {
    fail('E_LIST', `Listed and present files differ. Unlisted: ${JSON.stringify(extra.slice(0, 5))}; missing: ${JSON.stringify(absent.slice(0, 5))}.`);
  }
  let payloadBytes = 0;
  for (const e of files) {
    const m = members.get(e.path);
    if (BigInt(m.usize) !== e.bytes.value) fail('E_HASH', 'Byte count differs: ' + e.path);
    let data;
    try {
      data = await memberData(bytes, m, inflateRaw);
    } catch (error) {
      fail('E_HASH', `Member failed its integrity check: ${e.path} (${error.message})`);
    }
    if ((await sha256Hex(data)) !== e.sha256) fail('E_HASH', 'SHA-256 or byte count differs: ' + e.path);
    payloadBytes += data.length;
  }
  const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (x instanceof JsonNumber ? Number(x.text) : x)));
  return {
    schema: REPORT_SCHEMA,
    status: 'verified',
    bundleSha256,
    producer: plain(manifest.producer),
    payloadSchema: manifest.payloadSchema,
    reality: manifest.reality,
    created: manifest.created,
    files: files.length,
    payloadBytes,
    omissions: plain(manifest.omissions),
    producerBoundary: manifest.boundary,
    boundary: VERIFIER_BOUNDARY,
  };
}

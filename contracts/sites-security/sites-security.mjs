// Reference helpers for the Sites security baseline (docs/sites-security-baseline.md).
//
// Each LighthouseRobotics Sites app (vinext Worker) can copy this file in. It
// collects the patterns network-atlas#18 and art-history-future#3 each built on
// 2026-10-13, so the next app doesn't have to rediscover them. No dependencies.

const IDENTITY_PREFIX = 'oai-authenticated-user-';

const list = (value) =>
  String(value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * Decide whether a request's dispatcher identity is allowed.
 *
 * Opt-in: when neither ALLOWED_USER_IDS nor CANONICAL_HOSTS is configured the
 * identity is accepted unchanged, so deploying this changes nothing until the
 * owner sets the variables. A rejected identity should be treated as signed out.
 *
 * @param {Headers} headers request headers
 * @param {{allowedUserIds?: string, canonicalHosts?: string}} env comma-separated lists
 * @returns {{userId: string|null, allowed: boolean, reason: string}}
 */
export function checkIdentity(headers, env = {}) {
  const userId = headers.get(IDENTITY_PREFIX + 'id');
  if (!userId) return { userId: null, allowed: false, reason: 'signed-out' };
  const hosts = list(env.canonicalHosts).map((h) => h.toLowerCase());
  const host = (headers.get('host') || '').toLowerCase().replace(/:\d+$/, '');
  if (hosts.length && !hosts.includes(host)) return { userId, allowed: false, reason: 'host-not-canonical' };
  const ids = list(env.allowedUserIds);
  if (ids.length && !ids.includes(userId)) return { userId, allowed: false, reason: 'user-not-allowed' };
  return { userId, allowed: true, reason: ids.length || hosts.length ? 'allowlisted' : 'no-allowlist-configured' };
}

/**
 * For dev servers with no dispatcher in front: drop every client-supplied
 * identity header so a LAN visitor cannot forge a signed-in user.
 * @param {Headers} headers
 * @returns {Headers} a copy without identity headers
 */
export function stripIdentityHeaders(headers) {
  const out = new Headers(headers);
  for (const name of [...out.keys()]) if (name.toLowerCase().startsWith(IDENTITY_PREFIX)) out.delete(name);
  return out;
}

/** Headers for every route: refuse framing, keep referrers short, no MIME sniffing. */
export function baselineHeaders() {
  return {
    'Content-Security-Policy': "frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

/**
 * Cross-origin reads of private data (attachments, exports). Allow same-origin
 * and direct navigation; refuse sibling Sites, which count as same-site.
 * @param {Headers} headers
 * @returns {boolean} true when the read must be refused with 403
 */
export function crossSiteReadBlocked(headers) {
  const site = headers.get('sec-fetch-site');
  return site !== null && site !== 'same-origin' && site !== 'none';
}

/** Header to add to private data responses alongside crossSiteReadBlocked. */
export const PRIVATE_DATA_HEADERS = { 'Cross-Origin-Resource-Policy': 'same-origin', 'Cache-Control': 'private, no-store' };

/** An error whose message was written for the owner and is safe to show. */
export class PublicError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'PublicError';
    this.status = status;
  }
}

/**
 * Turn any thrown value into a response body that never leaks internals.
 * PublicError keeps its message and status; everything else becomes a generic
 * 500 (or 503 for transient storage failures) and is logged server-side.
 * @param {unknown} error
 * @param {{log?: (e: unknown) => void, transient?: (e: unknown) => boolean}} options
 * @returns {{status: number, body: {error: string}}}
 */
export function publicError(error, { log = console.error, transient = defaultTransient } = {}) {
  if (error instanceof PublicError) return { status: error.status, body: { error: error.message } };
  log(error);
  if (transient(error)) return { status: 503, body: { error: 'The service is busy. Try again in a moment.' } };
  return { status: 500, body: { error: 'Something went wrong. Nothing was changed.' } };
}

function defaultTransient(error) {
  const text = String(error?.message || error || '');
  return /D1_|SQLITE_BUSY|database is locked|timed? ?out|network connection lost/i.test(text);
}

/**
 * Bound a request body before parsing it. Throws PublicError(413).
 * @param {Request} request
 * @param {number} limit bytes
 */
export async function readBounded(request, limit) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) throw new PublicError('Request is too large.', 413);
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      throw new PublicError('Request is too large.', 413);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let p = 0;
  for (const c of chunks) { out.set(c, p); p += c.length; }
  return out;
}

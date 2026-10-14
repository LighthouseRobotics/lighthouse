# Sites security baseline

One checklist for every LighthouseRobotics app hosted on Sites, Workers or static hosting.

On 2026-10-13, network-atlas#18 and art-history-future#3 each worked out most of this list separately. This page collects their patterns so the next app starts from them. Copy `contracts/sites-security/sites-security.mjs` into the app if useful; it has no dependencies and is tested.

## Checklist

| # | Control | Why | How |
| --- | --- | --- | --- |
| 1 | **Identity allowlist (opt-in)** | Sign-in establishes identity, not membership. If the platform ever passes a client-supplied identity header through, an allowlist limits the damage. | `checkIdentity(headers, {allowedUserIds, canonicalHosts})`. It changes nothing until the owner sets the variables. Check the real user ID first, or the owner locks themselves out. |
| 2 | **Dev servers can't be signed into from outside** | A dev server bound to `0.0.0.0` with mock sign-in lets anyone on the LAN forge identity. | Bind `127.0.0.1` by default. Run `stripIdentityHeaders` on dev servers that have no dispatcher in front. |
| 3 | **No framing** | Clickjacking on owner-only actions. | `baselineHeaders()` on every route (`frame-ancestors 'none'`, `X-Frame-Options: DENY`). In vinext, match `/(.*)`, because `/:path*` doesn't match `/` (found in network-atlas#18). |
| 4 | **Private data isn't readable cross-site** | Sibling Sites on the same parent domain count as *same-site*, so cookies alone don't protect attachments. | `crossSiteReadBlocked(headers)` → 403, plus `PRIVATE_DATA_HEADERS` (`CORP: same-origin`, `no-store`). |
| 5 | **Errors don't leak internals** | Raw `e.message` exposes table names, tokens and paths. | Throw `PublicError` for messages written for the owner. Everything else goes through `publicError()`, which logs server-side and returns a generic 500 or 503. |
| 6 | **Bounded request bodies** | Memory exhaustion, D1 row limits (2 MB). | `readBounded(request, limit)` before parsing. Check both the declared and the actual size. |
| 7 | **Write routes are idempotent and revision-checked** | Retries and two tabs. | Compare-and-swap revision plus an idempotency key, with the original receipt on replay. Summit's `app/api/state/route.ts` and OmniList already do this. |
| 8 | **Rate limits on unauthenticated routes** | Public webhooks (for example eBay's account-deletion notices) can be called by anyone. | Gate on shape first, then a relevance check that needs no database reads, then do bounded work (omnilist#66's pattern). |
| 9 | **No outbound fetch follows redirects blindly** | A redirect turns a trusted feed URL into an untrusted one. | `redirect: 'manual'`. Treat a 3xx as a failed source and keep the previous data (art-history-future#3). |
| 10 | **Static apps carry a CSP** | Imported files can carry scripts (destiny-callout-trainer#1 fixed a stored XSS). | `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'">`. `frame-ancestors` is ignored in a meta tag, so also set it as a header where the host allows. |

## Where each app stands (read from source on 2026-10-14)

| App | 1 | 2 | 3 | 4 | 5 | 6 | 10 | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Network Atlas | #18 | #18 | #18 | #18 | #18 | partly | n/a | Draft PR, not merged |
| Cabinet (art-history-future) | #3 | ? | – | – | #3 | #3 | n/a | Draft PR, not merged |
| Summit (elevate-and-peak) | – | – | branch | n/a | branch | – | n/a | Branch `claude/zen-brahmagupta-15jdby` (2026-10-14) adds the framing, nosniff and referrer headers and stops echoing an unexpected `TypeError` from `applyAction`. Checked on a local build: headers on `/` and `/api/state`; `tests/api.mjs` passes. Not merged. |
| Callout Trainer | n/a | n/a | – | n/a | n/a | n/a | branch | Static. #1 fixed the XSS. Branch `claude/zen-brahmagupta-15jdby` (2026-10-14) adds a CSP meta tag: scripts self-only, inline styles allowed, Google Fonts allowed. Checked in Chromium: the smoke test passes, there are no violations, and an injected handler is refused. Not merged. |
| KOTJ court | n/a | n/a | – | n/a | n/a | n/a | – | Static browser build |
| Crate Theory | ? | ? | ? | ? | ? | ? | ? | crate-theory#21 raised a CSP `data:` question. Needs its own pass. |
| OmniList | Access | – | ? | ? | partly | partly | n/a | Cloudflare Access plus workforce membership. #66 hardens the public webhook. |

`–` means not present, `?` means not checked, `n/a` means it doesn't apply, and `branch` means it's done on an unmerged branch. Update this table when an app adopts a line, and add a test per line.

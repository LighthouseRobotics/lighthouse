# lighthouse-bundle/v1

A bundle is one ZIP file that carries an app's export together with a small envelope manifest. Any project can hand one to any other: the vault, the second brain, OmniList, Manta, the Graphics Studio, Destiny Clips. They can all check it with the same verifier, without knowing the payload's format.

The envelope adds checking. It doesn't change the payload. An app's existing export goes under `payload/` byte for byte, so every existing import path keeps working.

## Layout

```
lighthouse-bundle.json        the envelope manifest (required, at the root)
payload/...                   the app's own export, unchanged
```

Nothing else may be in the archive. Directory entries under `payload/` are allowed but carry no content and are not listed.

## Manifest

UTF-8 JSON with no byte-order mark, no duplicate keys and no `NaN` or `Infinity`. Unknown top-level keys are rejected unless they start with `x-`.

| Key | Required | Meaning |
| --- | --- | --- |
| `schema` | yes | Exactly `lighthouse-bundle/v1` |
| `producer.app` | yes | Lowercase slug of the app that made the export, such as `omnilist` |
| `producer.version` | yes | The app's version or build ID |
| `producer.repository`, `producer.commit` | no | Source repository and 7–64 hex commit |
| `created` | yes | RFC 3339 UTC time ending in `Z` |
| `payloadSchema` | yes | The payload's own format ID, such as `manta.photo-package.v1` |
| `reality` | yes | `physical`, `simulated`, `synthetic` or `unknown`: where the payload's records came from. Use `unknown` rather than guess. |
| `files` | yes | Every payload file: `path`, `bytes`, `sha256` and optional `mediaType`. Non-empty, sorted by path (code-point order), no duplicates. |
| `omissions` | yes | What the producer knowingly left out: `[{ "what": ..., "why": ... }]`. Empty if nothing. |
| `boundary` | yes | The producer's own statement of what the payload does and doesn't establish |
| `source` | no | `{ "id": ..., "description": ... }`: the record or workspace the export came from |

The JSON Schema in `lighthouse-bundle-v1.schema.json` documents these fields. The verifiers below are the authority: they also enforce ordering, path rules and limits that JSON Schema can't express.

## Paths

A member path must be:

- relative, with `/` separators, NFC-normalized and at most 512 UTF-8 bytes;
- free of `\`, `:`, control characters, empty segments, `.` and `..`;
- free of segments ending in a space or dot, and of Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`9`, `LPT1`–`9`, with or without an extension);
- `lighthouse-bundle.json`, or under `payload/`.

Two members whose NFC lower-case forms are equal are rejected, because they would collide on case-insensitive filesystems. A non-ASCII name must set the ZIP UTF-8 flag (bit 11).

## Archive rules

- Single-disk ZIP. The first bytes are a local file header (no prepended data). The central directory ends exactly where the end record (or ZIP64 end record) begins. The only bytes allowed after the end record are its own comment, and the comment may not contain an end-record signature.
- Members use STORED (0) or DEFLATE (8). Members with encryption or patched-data flags (bits 0, 5, 6 and 13) are rejected.
- Regular files and directory entries only: no symlinks or devices.
- Each local header's name equals its central-directory name. No member's data overlaps the next member or the central directory.
- CRC-32 is checked as well as SHA-256.

## Limits

| Limit | Default |
| --- | --- |
| Archive size | 1 GiB |
| Declared uncompressed total | 2 GiB |
| Entries | 20,000 |
| Central directory | 8 MiB |
| Manifest | 16 MiB |
| Compression ratio (members over 1 MiB) | 200:1 |
| Path length | 512 UTF-8 bytes |

Entry count, directory size and archive size are checked from the end record **before** any ZIP library builds its index. A caller may pass lower limits.

## Verification order and codes

Both verifiers check in this order and stop at the first failure, so they return the same code for the same file.

1. Archive size → `E_SIZE`
2. End record, ZIP64 records and directory location → `E_ZIP`; entry and directory limits → `E_LIMIT`
3. Optional expected SHA-256 of the whole file → `E_CHECKSUM`
4. Central directory parse and entry count → `E_ZIP`
5. For each member in directory order:
   - duplicate name, case or normalization collision, NUL, missing UTF-8 flag, path rules → `E_PATH`;
   - encryption or patch flags, method, directory or symlink type, stored size mismatch → `E_MEMBER`;
   - compression ratio → `E_LIMIT`.
6. Local headers and overlap → `E_ZIP`
7. Declared uncompressed total → `E_LIMIT`
8. Manifest: present, within the size limit (`E_LIMIT`), readable (`E_ZIP`), strict JSON and valid fields → `E_MANIFEST`
9. Listed files equal present files → `E_LIST`
10. Each listed file, in manifest order: byte count, CRC and SHA-256 → `E_HASH`

A verified report (`lighthouse-bundle-verification/v1`) returns:
- the producer, `payloadSchema`, `reality`, `created`, file count and payload bytes;
- the omissions and the producer's boundary;
- the verifier's own boundary.

The verifier's boundary reads: *every listed file is present with the recorded byte count and SHA-256, and the archive holds nothing else. Sender authenticity, completeness beyond the listed files and the truth of the payload's own claims are not established.*

## Not in v1

- **Signatures.** v1 proves integrity, not authorship. A later version may add a detached signature, such as `ssh-keygen -Y sign` or minisign, over the manifest bytes.
- **Partial or streaming verification of archives over 1 GiB.**

## Implementations

| | File | Run |
| --- | --- | --- |
| Python 3.9+, standard library only | `lighthouse_bundle.py` | `python3 lighthouse_bundle.py verify FILE.zip` · `create --out B.zip --app A --version V --payload-schema S INPUT...` |
| JavaScript (browsers, Node 20+) | `js/bundle-verify.mjs` | `await verifyBundle(uint8array)` |

`tests/corpus.py` writes the shared conformance corpus of 55 cases. `tests/test_bundle.py` and `tests/bundle-verify.test.mjs` both require every case to return its expected code, so the two implementations can't drift apart silently.

# Lighthouse shared contracts

This repository holds what the LighthouseRobotics projects share. It isn't a product. Each product lives in its own repository: lighthouse-app, OmniList, Network Atlas, Manta, Crate Theory, King of the Jungle, Summit, the Reader, the Graphics Studio, Cabinet and the Destiny tools. This repository holds the formats and checks that let them trust each other's files and share security fixes.

| Path | What it is | Status |
| --- | --- | --- |
| [`formats/bundle/`](formats/bundle/SPEC.md) | **lighthouse-bundle/v1**: one ZIP envelope any app can wrap its export in, with a verifier in Python (standard library only) and JavaScript (browser and Node) | Spec and both verifiers; a 55-case shared conformance corpus passes in both |
| [`contracts/sites-security/`](contracts/sites-security/sites-security.mjs) | Reference helpers for the Sites security baseline: identity allowlist, framing, cross-site reads, safe errors, bounded bodies | Tested helpers; not yet adopted by any app |
| [`tools/ci-local/`](tools/ci-local/README.md) | **Local CI receipts** (`lighthouse-ci-receipt/v1`): runs a project's GitHub workflow at an exact commit on this machine and writes a receipt that `verify` can check | Tested; first receipt: Network Atlas `check.yml`, 2026-10-14 |
| [`docs/sites-security-baseline.md`](docs/sites-security-baseline.md) | The checklist and where each app stands | Written 2026-10-14 from source |
| [`STATUS.json`](STATUS.json) | Machine-readable status for the vault builder | |

## Check everything

```bash
bash scripts/check.sh
```

This runs the Python unit tests, the JS tests, the shared bundle corpus through both verifiers, and the local CI runner's tests. Nothing installs. It needs Python 3.9+, Node 20+, git and bash.

## Wrap an export

```bash
python3 formats/bundle/lighthouse_bundle.py create \
  --out omnilist-backup.bundle.zip --app omnilist --version 5f70f6a \
  --payload-schema omnilist.portable-backup --reality unknown \
  --omission "pending phone captures=still on the phones" \
  path/to/export/
python3 formats/bundle/lighthouse_bundle.py verify omnilist-backup.bundle.zip
```

In a page:

```js
import { verifyBundle } from './bundle-verify.mjs';
const report = await verifyBundle(new Uint8Array(await file.arrayBuffer()));
```

## Rules for this repository

- Shared contracts only. No product code, no private data, no credentials.
- Every contract has tests, and every format has a conformance corpus that every implementation runs.
- Changing a contract means a new version (`/v2`). Never change v1's meaning.

All rights reserved. Private repository. See [LICENSE](LICENSE).

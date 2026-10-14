# lighthouse-status/v1: one status line per repository

Each LighthouseRobotics repository keeps a small `STATUS.json` at its root. The vault builder reads them all and shows one line per product, so nobody has to open a repository's start-here document to learn where it stands. `STATUS.json` doesn't replace those documents; `startHere` points at them. Next-wave item XP-08 (`300-Builds/Next Wave/Cross-project.md` in LighthouseRobotics/lighthouse-vault).

```json
{
  "schema": "lighthouse-status/v1",
  "repository": "LighthouseRobotics/network-atlas",
  "status": "active",
  "summary": "Private people directory and outreach workspace on Sites (D1, R2).",
  "lastVerified": "2026-10-14",
  "verifiedBy": "check.yml run locally at bab8f72: docs/ci-local/2026-10-14-bab8f72/receipt.json (local CI, not hosted)",
  "nextAction": "Re-run the Android and authenticated-browser release checklist on the current head.",
  "blockers": ["Hosted CI is blocked by account billing; checks run locally."],
  "startHere": "README.md"
}
```

| Field | Rule |
| --- | --- |
| `schema` | `lighthouse-status/v1` |
| `repository` | `LighthouseRobotics/<name>` |
| `status` | `active`, `blocked` (then `blockers` can't be empty), `paused` or `archived` |
| `summary` | What the repository is, in one or two sentences, up to 400 characters |
| `lastVerified` | The date its checks last ran and passed, `YYYY-MM-DD`, or `null` if no run is recorded. Never a future date. |
| `verifiedBy` | How, and where the evidence is. Say "local" when it wasn't hosted CI, and cite a commit or receipt. |
| `nextAction` | The one next move |
| `blockers` | Up to ten sentences. What stops progress, not general limits. |
| `startHere` | The repository's own start-here file. It must exist. |

No other fields are allowed. Change the format by adding `/v2`, never by changing v1.

**Keep it honest.** Update `lastVerified` only when the checks actually ran, and don't copy a number into `summary` that will go stale. Treat the file like a commit message: it states what was true when it was written.

## Check a file

```bash
python3 formats/status/status_check.py path/to/STATUS.json --root path/to/repository
```

`lighthouse-status-v1.schema.json` is the same contract as a JSON Schema (draft 2020-12).

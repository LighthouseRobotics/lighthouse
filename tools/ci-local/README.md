# Local CI receipts

Hosted GitHub Actions runners are blocked by account billing, so the projects' workflows don't run on GitHub. `ci_local.py` runs a workflow on this machine at an exact commit and writes a **receipt**: which commit, which workflow bytes, which commands, which tool versions and which exit codes. A later audit can check the receipt with `verify`.

A receipt is local CI. It is never a GitHub check, and its label says so. Next-wave item XP-01 (`300-Builds/Next Wave` in LighthouseRobotics/lighthouse-vault).

Standard library only, Python 3.9+, plus `git` and `bash`.

## Run it

```bash
# Plan first: what would run, and what this runner cannot reproduce. Nothing executes.
python3 tools/ci-local/ci_local.py run --repo ../network-atlas --commit origin/my-branch --event workflow_dispatch --dry-run

# Run and write the receipt.
python3 tools/ci-local/ci_local.py run --repo ../network-atlas --commit origin/my-branch --event workflow_dispatch \
  --out receipts/atlas-my-branch

# Check a receipt, its logs, and the repository it describes.
python3 tools/ci-local/ci_local.py verify receipts/atlas-my-branch/receipt.json --repo ../network-atlas
```

Exit codes: 0 pass, 1 fail, 2 incomplete, 3 a bad request (unknown commit, workflow, job or input).

Useful options:

- `--workflow NAME`: a file in `.github/workflows`, repeatable. If the repository has one workflow it is chosen automatically.
- `--all`: every workflow. The receipt records which ones the event triggers and why the others don't.
- `--event push|pull_request|workflow_dispatch`, `--input NAME=VALUE`: the trigger to simulate. Branch filters are checked against `--ref` (by default the branch `--commit` names).
- `--base COMMIT`: checks `paths` and `paths-ignore` filters against the files changed since that commit. With `--all --event pull_request --base origin/main` it runs exactly the workflows a pull request would start.
- `--job NAME`, `--matrix NAME=VALUE`: run part of a workflow. A job brings the jobs it needs.
- `--tool-cache DIR` (or `$CI_LOCAL_TOOL_CACHE`): exact toolchains, see below.
- `--accept-version-drift`: see below.

## What counts as a pass

| Result | When |
| --- | --- |
| **pass** | Every selected job ran here, every step passed, at least one `run:` step executed, and nothing was substituted in a way that could change the outcome. |
| **fail** | A step failed (a non-zero exit, a timeout, or a missing `working-directory`) without `continue-on-error`. |
| **incomplete** | Anything else: an action this runner cannot reproduce, a secret or configuration variable the workflow reads, a tool version other than the one the workflow asks for, or a run that was interrupted. |

`verify` recomputes the result from the steps, so a hand-edited "pass" is caught. It also checks every log against its SHA-256 and, with `--repo`, the commit, tree, workflow file and lockfile hashes.

## How it runs a workflow

- **The commit, not the working tree.** Each job gets a fresh `git clone --shared` of the repository, checked out at the commit. Uncommitted changes are never included.
- **Workflow file.** It is read from that commit with `git show`. The parser accepts the YAML subset workflows use. It refuses anchors, aliases, tags, multi-document files and multi-line quoted values, and gives a line number. On 2026-10-14 it parsed all 32 workflow files in the LighthouseRobotics repositories identically to PyYAML, once PyYAML's YAML 1.1 reading of the `on` key as `true` is mapped back to `on`.
- **Expressions.** `${{ }}` and `if:` follow GitHub's rules: case-insensitive string comparison, number coercion, `||` and `&&` returning operands, the implicit `success() &&`, and the `contains`, `startsWith`, `endsWith`, `format`, `join`, `toJSON`, `fromJSON` and `hashFiles` functions. An unknown function makes the step incomplete.
- **Jobs** run one at a time in `needs` order, with matrix `include` and `exclude`, job outputs, `GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`, step and job timeouts, and `continue-on-error` on steps and jobs. Background processes a step starts are stopped when its job ends. If the runner itself is stopped (Ctrl-C or SIGTERM), it stops the running step's processes and still writes a receipt, marked `interrupted` and incomplete.
- **Environment.** Steps see GitHub's default variables (`CI`, `GITHUB_ACTIONS`, `GITHUB_WORKSPACE`, `GITHUB_SHA`, `RUNNER_TEMP` and the rest), plus `LIGHTHOUSE_CI_LOCAL=1`. From the host they get only an allowlist (`PATH`, `HOME`, locale, proxy and CA-bundle variables, `JAVA_HOME` and a few tool paths). `--pass-env NAME` adds one. Secrets and `vars` are empty; a workflow that reads one is incomplete.

Known actions are replaced like this:

| Action | Here | Effect on the result |
| --- | --- | --- |
| `actions/checkout` | Clean clone at the commit, or at `ref:` if that resolves locally | None. The note records that the full local history is present where GitHub fetches depth 1. Another repository, submodules or LFS make the step incomplete. |
| `actions/setup-node` | A matching Node from the tool cache, or else the local `node`, checked against `node-version` or `node-version-file` | A version that doesn't match makes the run incomplete |
| `actions/setup-python` | A fresh virtual environment from a matching cached Python, or else `pythonX.Y` if installed, or else `python3`. `pip install` stays inside the run. | As above |
| `actions/setup-java` | Checks the local `java` major version | As above; a different distribution is noted, not counted |
| `pnpm/action-setup` | Checks `pnpm --version` inside the checkout, so pnpm's own `packageManager` switching applies | As above |
| `actions/cache` | Skipped; `cache-hit` is `false` | None: caches change speed, not results |
| `actions/upload-artifact` | Copies the files into `artifacts/<name>/` beside the receipt, up to 200 MB | None. `if-no-files-found: error` fails the step as on GitHub. |
| Anything else, local actions, Docker actions, reusable workflows, job or service containers, Windows or macOS runners | Not run | The job stops there and the run is incomplete |

**Exact versions: the tool cache.** Workflows pin versions such as Node 22.23.2 that the machine may not have. Like a hosted runner's tool cache, `--tool-cache DIR` holds them as `DIR/node/<version>/bin/node` and `DIR/python/<version>/bin/python3`. `setup-node` and `setup-python` use the newest cached version that fits the workflow's spec, and only then fall back to the machine's own `node`, `pythonX.Y` or `python3`. To add a Node version:

```bash
python3 tools/ci-local/ci_local.py fetch-node 22.23.2 --tool-cache ~/.cache/ci-local
```

It downloads the official `node-v<version>-<os>-<arch>.tar.gz` from nodejs.org over HTTPS and refuses it unless its SHA-256 matches nodejs.org's `SHASUMS256.txt`. It doesn't check the GPG signature on that file. The archive is extracted only if no entry or link leaves the version's folder.

**Version drift.** `--accept-version-drift` lets a run whose only difference is a tool version pass. Each difference is still listed in the receipt as `material: false`. Use it when the owner has decided the drift doesn't matter, and say so where the receipt is cited.

**Pull requests.** GitHub runs `pull_request` workflows on a merge of head and base. This runner uses the head commit and records that difference.

## The receipt

`receipt.json`, schema `lighthouse-ci-receipt/v1`, with `logs/` (one file per `run:` step) and `artifacts/` beside it.

| Field | Contents |
| --- | --- |
| `label` | Always "Local CI on the owner's machine. Not a GitHub-hosted check." |
| `result` | `pass`, `fail` or `incomplete` |
| `repository` | `name` (owner/repo from the origin URL, no credentials), `commit`, `tree` |
| `event` | `name`, `ref`, `base`, `base_branch`, `inputs`, and the number of changed files when `--base` was given |
| `runner` | This tool's SHA-256; the host system and distribution; the versions of git, bash, node, npm, pnpm, python3 and java; and the **names** (never values) of the host variables passed to steps |
| `workflows[]` | `path`, `sha256` of the file at the commit, `name`, `triggered`, `trigger_note`, and `jobs[]` |
| `jobs[]` | `id`, `name`, `matrix`, `runs_on`, `result` (`success`, `failure`, `skipped`, `incomplete`), `note`, `outputs`, `steps[]` |
| `steps[]` | `name`, `kind` (`run` or `action`), `uses`, `result` (`pass`, `fail`, `skip`, `unsupported`, `not-run`), `note`, `duration_ms`. Run steps add `command` (after `${{ }}` substitution), `shell`, `working_directory`, `exit_code`, `log` and `log_sha256`. |
| `lockfiles` | SHA-256 of each lockfile at the commit (`package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `requirements.txt`, `gradle-wrapper.properties` and similar), up to two folders deep |
| `differences[]` | `kind` (`version`, `merge-commit`, `interrupted`), `detail`, `material` |
| `unavailable[]` | Secrets, configuration variables or `github.token` the workflow read |

Logs hold whatever the workflow's commands print. Read them before committing a receipt anywhere public.

## Before you run it

It runs the workflow's commands on this machine, with this user's permissions, much as a contributor would run them by hand. Read the workflow or the `--dry-run` plan first. Commands that install system packages (`playwright install --with-deps`, `apt-get`) will try to do so here.

## Tests

```bash
python3 -m unittest discover -s tools/ci-local -p 'test_*.py'
```

The tests build throwaway git repositories and cover:

- a pass, and a red run with `continue-on-error` and `if: always()`;
- an unknown action, version drift, a secret, and a fresh Python environment;
- dispatch inputs and triggers;
- a step timeout, and stopping the runner;
- the tool cache, with `fetch-node` refusing a wrong hash and archive entries that escape their folder;
- artifacts outside the job folder;
- `verify` catching an edited result and an edited log. When PyYAML is installed, they also compare the parser with it.

# Working in this repository

Shared contracts for the LighthouseRobotics projects. Read README.md first.

- Keep it dependency-free: Python standard library, plain ES modules.
- Every format change needs a new conformance case in `formats/bundle/tests/corpus.py`, and both verifiers must agree on it. Run `bash scripts/check.sh` before committing.
- Never change the meaning of a published version. Add `/v2` instead.
- No product code, private data or credentials.
- Hosted CI is blocked by account billing. Record local results in commit messages and say they are local.

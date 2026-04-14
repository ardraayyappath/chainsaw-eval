# Benchmarking Chainsaw vs. Incumbent Tools

## Goal
Empirically show that pip-audit, safety, socket, and snyk cannot detect
these novel supply-chain attacks — while chainsaw can, even post-cleanup.
This becomes the "what existing tools miss" table in the USENIX paper.

## Tools & detection modes

| Tool       | Mode            | Needs registry? | Needs pkg installed? |
|------------|-----------------|-----------------|----------------------|
| pip-audit  | Advisory DB     | Yes (OSV/PyPI)  | Yes (live env)       |
| safety     | Advisory DB     | Yes (safety DB) | Yes (live env)       |
| socket     | Static analysis | Yes (PyPI)      | No (wheel/manifest)  |
| snyk       | Advisory DB     | Yes (Snyk DB)   | No (manifest)        |
| **chainsaw** | Forensic artifacts | No          | No (S2/S3/S4 work)   |

## Expected results (paper hypothesis)
All four tools return 0 findings for all four packages — attacks were novel,
never listed in any advisory DB, and (except ultralytics) short-lived on PyPI.
Socket may flag *behavioral* signals (subprocess, network) but won't flag the
specific version as confirmed malicious.

## Implementation plan: eval/run_comparison.py

### pip-audit + safety (SSH into S1 container)
```
ssh -i keys/eval_key -p 220X eval@127.0.0.1 \
  "pip install pip-audit safety && \
   pip-audit --format json 2>&1; \
   safety scan --output json 2>&1"
```
Parse JSON output, record: vulnerability count, any package name matches.

### socket (REST API — file upload)
Auth: Basic auth with token as username, empty password.
Org: `chainsaw`  Token: stored in SOCKET_TOKEN env var.

Working endpoints confirmed:
- `GET  /v0/report/list`                        → 200 (lists GitHub-integrated scans)
- `GET  /v0/orgs/chainsaw/full-scans`           → 200
- `POST /v0/orgs/chainsaw/full-scans`           → to be confirmed (multipart form)

Upload flow:
1. Generate `requirements.txt` per scenario:
   `litellm==1.82.8` / `num2words==0.5.15` / `telnyx==4.87.1` / `ultralytics==8.3.41`
2. POST to `/v0/orgs/chainsaw/full-scans`:
   ```
   curl -u "$SOCKET_TOKEN:" -X POST \
     -F "package[]=@requirements.txt;filename=requirements.txt;type=text/plain" \
     https://api.socket.dev/v0/orgs/chainsaw/full-scans
   ```
3. Poll for scan completion, then fetch issues.

Socket org slug: `chainsaw`  (confirmed from /v0/report/list)
Socket token env var: `SOCKET_TOKEN`

### snyk (CLI subprocess)
Auth: `SNYK_TOKEN` env var.
Org ID: `e5956752-5a32-4a44-8832-af1f692d3ca4`

```
snyk test --package-manager=pip \
  --file=requirements.txt \
  --org=e5956752-5a32-4a44-8832-af1f692d3ca4 \
  --json
```
Parse JSON: `vulnerabilities[]`, `ok` field.

snyk CLI must be installed: `npm install -g snyk` or `brew install snyk`.
Check: `which snyk` (not installed yet as of 2026-04-13).

## Script structure: eval/run_comparison.py

```
PACKAGES = [
    ("litellm",     "1.82.8"),
    ("num2words",   "0.5.15"),
    ("telnyx",      "4.87.1"),
    ("ultralytics", "8.3.41"),
]

# S1 container ports for pip-audit/safety (live env)
S1_PORTS = {
    "litellm":     2201,
    "num2words":   2202,
    "telnyx":      2203,
    "ultralytics": 2204,
}
```

Output: `results/comparison.md` + `results/comparison.json`

Comparison table columns:
| Package | pip-audit | safety | socket | snyk | chainsaw (S1) | chainsaw (S4) |
|---------|-----------|--------|--------|------|---------------|---------------|

Row values: `DETECTED` / `not detected` / `ERROR` / `N/A`

## Credentials / config
Store in `.env` (already gitignored via `keys/` pattern — add `.env` too):
```
SOCKET_TOKEN=sktsec_frrLRfaygyZO6bzTvp80N6IoVFpz-8HC7vZiE45N-KD8_api
SNYK_TOKEN=<get from snyk account dashboard>
SNYK_ORG=e5956752-5a32-4a44-8832-af1f692d3ac4
```

## Status
- [ ] Confirm `POST /v0/orgs/chainsaw/full-scans` multipart body format
- [ ] Install snyk CLI and get SNYK_TOKEN
- [ ] Write run_comparison.py
- [ ] Run against all 4 S1 scenarios
- [ ] Add results to paper §5 evaluation table

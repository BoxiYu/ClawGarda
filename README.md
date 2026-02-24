# clawgarda

`clawgarda` is a lightweight MVP security scanner for OpenClaw workspaces.

## What it checks

- Gateway bind not loopback
- Missing gateway auth token/password
- Telegram bot token in config
- Workspace outside `/Users/ddq/openclaw`
- Exposed default gateway port (`3000`) based on local checks
- Plaintext secret patterns in workspace `.md` and `.json` files (first 200 files, max 1MB each)

## Install

```bash
cd /Users/ddq/openclaw/projects/clawgarda
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run

Default table output:

```bash
clawgarda scan --workspace /Users/ddq/openclaw
```

SAST scan (Phase 1):

```bash
clawgarda sast scan --workspace /Users/ddq/openclaw
clawgarda sast scan --workspace /Users/ddq/openclaw --format json

# reduce third-party noise
clawgarda sast scan --workspace /Users/ddq/openclaw --exclude-glob "projects/**"
```

SAST baseline workflow (Phase 1.1):

```bash
clawgarda sast baseline save --workspace /Users/ddq/openclaw --path /Users/ddq/openclaw/.clawgarda/sast-baseline.json
clawgarda sast baseline compare --workspace /Users/ddq/openclaw --path /Users/ddq/openclaw/.clawgarda/sast-baseline.json --fail-on-severity high
```

JSON output:

```bash
clawgarda scan --workspace /Users/ddq/openclaw --json
# or
clawgarda scan --workspace /Users/ddq/openclaw --format json
```

SARIF output (for code scanning / CI):

```bash
clawgarda scan --workspace /Users/ddq/openclaw --format sarif > clawgarda.sarif
```

Deep scan mode (logs/artifacts/deps):

```bash
clawgarda deep-scan --workspace /Users/ddq/openclaw
clawgarda deep-scan --workspace /Users/ddq/openclaw --format json

# Optional: add extra excludes to reduce noise
clawgarda deep-scan --workspace /Users/ddq/openclaw --exclude-glob "state/workspace/**"

# Optional RLM-assisted large-context analysis (best effort)
clawgarda deep-scan --workspace /Users/ddq/openclaw --use-rlm --rlm-model gpt-5-mini
```

Deep baseline workflow (v1.3):

```bash
# Save baseline snapshot for deep-scan
clawgarda deep-baseline save --workspace /Users/ddq/openclaw --path /Users/ddq/openclaw/.clawgarda/deep-baseline.json

# Compare and fail only on NEW high+ deep findings
clawgarda deep-baseline compare --workspace /Users/ddq/openclaw --path /Users/ddq/openclaw/.clawgarda/deep-baseline.json --fail-on-severity high
```

Use external rules file:

```bash
clawgarda scan --workspace /Users/ddq/openclaw --rules ./src/clawgarda/rules/default.json
```

Use policy file (ignore noisy paths / exceptions):

```bash
clawgarda scan --workspace /Users/ddq/openclaw --policy ./policy.example.json
```

Override allowed workspace root:

```bash
clawgarda scan --workspace /tmp/demo --allowed-root /Users/ddq/openclaw
```

## Baseline workflow (v0.3)

Save current baseline:

```bash
clawgarda baseline save --workspace /Users/ddq/openclaw --path .clawgarda/baseline.json
```

Compare current state against baseline:

```bash
clawgarda baseline compare --workspace /Users/ddq/openclaw --path .clawgarda/baseline.json
# JSON diff
clawgarda baseline compare --workspace /Users/ddq/openclaw --path .clawgarda/baseline.json --format json
# CI gate: fail only when NEW findings are high+
clawgarda baseline compare --workspace /Users/ddq/openclaw --path .clawgarda/baseline.json --fail-on-severity high
```

## GitHub Actions CI gate (v0.7)

A sample workflow is included at:

`projects/clawgarda/.github/workflows/clawgarda-ci.yml`

It runs tests, compares against baseline, and can fail PRs on new high+ findings.

## Safe fix scaffold (v0.6)

```bash
# preview only
clawgarda fix run --safe --dry-run --workspace /Users/ddq/openclaw

# emit patch preview
clawgarda fix run --safe --workspace /Users/ddq/openclaw --emit-patch --patch-path /Users/ddq/openclaw/.clawgarda/safe-fix.patch

# apply patch actions (policy-only, with backup)
clawgarda fix apply --workspace /Users/ddq/openclaw --patch /Users/ddq/openclaw/.clawgarda/safe-fix.patch
```

## Markdown report (v0.3)

```bash
# print to stdout
clawgarda report --workspace /Users/ddq/openclaw

# write to file
clawgarda report --workspace /Users/ddq/openclaw --output reports/clawgarda.md

# PR template markdown
clawgarda report --workspace /Users/ddq/openclaw --pr-template --output reports/PR_BODY.md
```

## Copilot plan (v1.1)

```bash
# Generate plan from current scan
clawgarda copilot plan --workspace /Users/ddq/openclaw --output reports/REMEDIATION_PLAN.md

# Or generate plan from existing findings JSON
clawgarda scan --workspace /Users/ddq/openclaw --format json > reports/findings.json
clawgarda copilot plan --workspace /Users/ddq/openclaw --from-json reports/findings.json --output reports/REMEDIATION_PLAN.md
```

Exit code is `0` when no findings, `1` when findings exist.

## Finding schema

Each finding includes:

- `id`
- `title`
- `severity`
- `confidence`
- `evidence`
- `fix`

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

Use external rules file:

```bash
clawgarda scan --workspace /Users/ddq/openclaw --rules ./src/clawgarda/rules/default.json
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
```

## Markdown report (v0.3)

```bash
# print to stdout
clawgarda report --workspace /Users/ddq/openclaw

# write to file
clawgarda report --workspace /Users/ddq/openclaw --output reports/clawgarda.md
```

Exit code is `0` when no findings, `1` when findings exist.

## Finding schema

Each finding includes:

- `id`
- `title`
- `severity`
- `evidence`
- `fix`

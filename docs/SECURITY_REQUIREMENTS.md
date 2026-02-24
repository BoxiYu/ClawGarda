# ClawGarda Security Requirements Mapping

## Requirement → Command Coverage

| Requirement | Current Coverage | Commands |
|---|---|---|
| Identity/authority checks | Partial | `scan`, `deep-scan` |
| Secret leakage (repo/runtime) | Good | `scan`, `deep-scan`, `hygiene secrets` |
| Tool/exposure posture | Good (basic) | `scan`, `dast smoke` |
| Baseline delta gating | Good | `baseline compare`, `deep-baseline compare`, `sast baseline compare`, `dast baseline compare` |
| Audit/reporting | Good | `report`, `--pr-template`, `sast summary`, `dast summary`, `copilot plan` |
| Safe remediation | Good (low risk) | `fix run --safe --emit-patch`, `fix apply` |

## Finding Families
- CGA-* : config/runtime posture
- CGD-* : deep runtime/log/artifact signals
- CGS-* : SAST code patterns
- CGDAS-* : DAST smoke checks
- CGH-* : hygiene pre-push secret checks

## Daily Operations (Recommended)
```bash
clawgarda hygiene secrets --workspace <repo>
clawgarda scan --workspace <repo> --policy policy.example.json
clawgarda sast baseline compare --workspace <repo> --path .clawgarda/sast-baseline.json --fail-on-severity high
clawgarda deep-baseline compare --workspace <repo> --path .clawgarda/deep-baseline.json --fail-on-severity high
```

## Gap Backlog
1. Authority graph checks (owner impersonation and delegated trust paths)
2. Loop/cost anomaly heuristics in deep logs
3. DAST auth-state differential checks (unauth vs auth)
4. Unified `dashboard` command for one-shot governance view

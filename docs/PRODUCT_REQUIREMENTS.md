# ClawGarda Product Requirements (vNext)

## Goal
Turn agent-security research findings into practical, testable product requirements for OpenClaw security governance.

## Product Scope
ClawGarda provides deterministic scanning, baseline gating, reporting, and safe remediation workflows across:
- config/runtime scan
- deep log/artifact scan
- SAST
- DAST smoke
- remediation planning

## Requirements

### PRD-1 Identity & Authority Boundaries
- Must detect missing/weak owner authorization settings.
- Must flag over-broad sender/mention/group access policies.
- Must support gating high-risk actions by policy (exec/external send/config mutation).

### PRD-2 Secrets & Data Exfiltration
- Must detect plaintext secrets in tracked files before commit/push.
- Must detect secret-like leakage in logs/artifacts/deep traces.
- Must support false-positive suppression via policy/exclude globs.

### PRD-3 Tool Risk & Execution Exposure
- Must detect unsafe gateway bind/auth combinations.
- Must detect risky exec policy posture and dangerous defaults.
- Must surface endpoint exposure risks (DAST smoke).

### PRD-4 Autonomy Runaway & Cost Governance
- Must identify likely loop/runaway patterns from logs.
- Must support baseline deltas and fail gates on newly introduced high+ findings.
- Should add cost/usage anomaly checks in deep mode.

### PRD-5 Verifiability, Auditability, Recovery
- Must produce machine-readable outputs (json/sarif) and human reports.
- Must support patch-first remediation with backups.
- Must maintain baseline/history for change accountability.

## Non-Goals (Current)
- Full internet-scale black-box scanning
- Full enterprise-grade SAST taint engine
- Full autonomous high-risk auto-remediation

## Acceptance Criteria
- Every requirement maps to at least one command and one finding family.
- CI can block on new high+ risk findings.
- Teams can run a daily command set and produce traceable reports.

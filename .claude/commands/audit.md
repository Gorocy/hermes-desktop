---
description: Run a full security audit of hermes-desktop using 5 specialist agents and an orchestrator
allowed-tools: Bash, Read, Write, Glob, Task
---

Run a full security audit of hermes-desktop. Follow these steps in order.

## Step 1 — prepare audit folder

Compute the audit directory once and reuse it across all subsequent steps:

```bash
AUDIT_DIR="docs/audits/$(date -u +%Y-%m-%d)"
mkdir -p "$AUDIT_DIR"
echo "$AUDIT_DIR"
```

If the folder already has prior reports for today, you will OVERWRITE them — that is intentional (idempotent re-runs).

Also capture the current commit hash so the auditors and SUMMARY can record it:

```bash
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
echo "$COMMIT"
```

## Step 2 — dispatch 5 specialists in parallel

In a SINGLE message, send 5 Task tool calls in parallel — one per specialist. Each Task prompt must include:

- The exact path it must Write its report to (under `$AUDIT_DIR`).
- Today's UTC date and the short commit hash from Step 1.
- A one-sentence reminder of its scope (no need to repeat the system prompt — that lives in the agent file).

Use these subagent types and target paths:

| `subagent_type` | output path |
|---|---|
| `electron-hardening-auditor` | `<AUDIT_DIR>/electron-hardening.md` |
| `shell-and-process-auditor` | `<AUDIT_DIR>/shell-and-process.md` |
| `secrets-and-credentials-auditor` | `<AUDIT_DIR>/secrets-and-credentials.md` |
| `supply-chain-auditor` | `<AUDIT_DIR>/supply-chain.md` |
| `network-and-storage-auditor` | `<AUDIT_DIR>/network-and-storage.md` |

## Step 3 — run orchestrator

After all 5 specialist Task calls return, dispatch a single Task call to `audit-orchestrator` with:

- The audit directory path.
- The 5 report paths (so it does not need to glob).

The orchestrator writes `<AUDIT_DIR>/SUMMARY.md`.

## Step 4 — present results

Read `<AUDIT_DIR>/SUMMARY.md` and show its contents to the user. Also list the 6 file paths so the user can drill into individual reports:

```
<AUDIT_DIR>/SUMMARY.md
<AUDIT_DIR>/electron-hardening.md
<AUDIT_DIR>/shell-and-process.md
<AUDIT_DIR>/secrets-and-credentials.md
<AUDIT_DIR>/supply-chain.md
<AUDIT_DIR>/network-and-storage.md
```

If any specialist failed (no report written), call it out explicitly and offer to retry just that specialist.

## Step 5 — sanity check

Run `git status --short` and confirm the only changes are under `docs/audits/`. The 6 agent files in `.claude/agents/` and this slash command must be untouched. If anything else changed, raise that immediately to the user.

## Notes

- All agents are read-only by design; they do NOT modify any project source file.
- Each report uses the same shape: header → severity matrix → findings → methodology.
- Re-running `/audit` on the same UTC day overwrites the existing reports.

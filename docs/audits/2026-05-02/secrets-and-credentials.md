# Secrets & Credentials Audit — hermes-desktop

| Field | Value |
|---|---|
| Date (UTC) | 2026-05-02 |
| Project | hermes-desktop |
| Commit | 72d7bcc |
| Auditor | secrets-and-credentials-auditor |
| Scope | `src/main/config.ts`, `src/main/index.ts` (IPC), `src/main/utils.ts` (`safeWriteFile`), `src/main/askpass.ts`, `src/main/installer.ts` (dump/log surfaces), `src/main/hermes.ts` (gateway env injection), `src/preload/index.ts`, `src/renderer/` (raw key handling, localStorage), `.gitignore`, git history (`-S 'sk-'`, `-S 'api_key'`, `--all -- .env auth.json`), tests fixtures |
| Method | Read-only static analysis. No source mutation. All suspected secret values redacted. Git history inspected with read-only `git log`/`git ls-files`. |

## Severity Matrix

| Severity | Count | Finding IDs |
|---|---|---|
| Critical | 0 | — |
| High     | 4 | SC-001, SC-002, SC-003, SC-004 |
| Medium   | 3 | SC-005, SC-006, SC-007 |
| Low      | 2 | SC-008, SC-009 |
| Info     | 3 | SC-010, SC-011, SC-012 |

---

## Findings

### SC-001 — `auth.json` (credential pool) written without explicit `mode 0o600`

- **Severity**: High
- **Category**: Credential storage / file permissions (CWE-732 Incorrect Permission Assignment for Critical Resource)
- **Location**:
  - `src/main/config.ts:377-379` (`writeAuthStore` calls `safeWriteFile`)
  - `src/main/utils.ts:40-44` (`safeWriteFile` uses `writeFileSync(filePath, content, "utf-8")` — no `mode` option, no `chmodSync` after, no atomic temp+rename)
- **Description**: The credential pool, which stores per-provider API keys keyed by `{ key, label }` entries inside `~/.hermes/auth.json`, is written through the shared helper `safeWriteFile`. That helper relies on the process umask to determine permissions (typically `0o644` — world-readable). The path `~/.hermes/` is in the user's home directory and may sit on a multi-user system, NFS share, or backup target where group/other-readable mode leaks every API key in the pool.
- **Impact**: Any local user (or process running under a different uid) can read the user's full provider credential set (OpenRouter, Anthropic, OpenAI, Google, xAI, Groq, etc.). On macOS with FileVault disabled or on shared Linux hosts this is directly exploitable.
- **Remediation**:
  1. In `safeWriteFile` (or in a dedicated credential-store helper), pass `{ mode: 0o600 }` to `writeFileSync` AND call `chmodSync(path, 0o600)` after write to also tighten existing files (the `mode` argument only applies on create).
  2. Use atomic write — write to `auth.json.tmp` then `renameSync` — to prevent torn writes during a crash.
  3. Also `chmodSync(HERMES_HOME, 0o700)` once on first write.
- **References**: CWE-732, OWASP ASVS V6.2.1, V8.3.7

---

### SC-002 — `.env` file (provider API keys) written without explicit `mode 0o600`

- **Severity**: High
- **Category**: Credential storage / file permissions (CWE-732)
- **Location**:
  - `src/main/config.ts:124-155` (`setEnvValue` → `safeWriteFile`)
  - `src/main/utils.ts:40-44` (no mode set on write)
- **Description**: The per-profile `.env` file at `~/.hermes/.env` (or `~/.hermes/profiles/<name>/.env`) holds plaintext provider keys: `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GROQ_API_KEY`, `GOOGLE_API_KEY`, `XAI_API_KEY`, `HF_TOKEN`, `MINIMAX_API_KEY`, `DEEPSEEK_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `MISTRAL_API_KEY`, `PERPLEXITY_API_KEY`, plus messaging tokens (`TELEGRAM_BOT_TOKEN`, `DISCORD_BOT_TOKEN`, `SLACK_BOT_TOKEN`, `TWILIO_AUTH_TOKEN`, etc.). Same `safeWriteFile` path → no `mode` enforcement, default umask permissions.
- **Impact**: World-/group-readable plaintext bag of >30 distinct provider/integration credentials. Compromise of any local user account or any process running under a sibling uid leaks the full provider key collection.
- **Remediation**: Same as SC-001 — set `{ mode: 0o600 }` on write, follow with `chmodSync` to handle pre-existing files, atomic temp+rename. Consider OS keychain (macOS Keychain via `keytar`/`safeStorage`, Windows DPAPI, libsecret) instead of plaintext on disk for the most sensitive provider keys.
- **References**: CWE-256, CWE-312, CWE-732, OWASP ASVS V6.2.1

---

### SC-003 — IPC `get-env` returns raw API keys to the renderer

- **Severity**: High
- **Category**: Information exposure across trust boundary (CWE-200)
- **Location**:
  - `src/main/index.ts:238` (`ipcMain.handle("get-env", … readEnv(profile))` returns the full `Record<string, string>` of raw values)
  - `src/main/config.ts:91-122` (`readEnv` returns plaintext values, including secrets)
  - `src/preload/index.ts:64-65` (`getEnv` exposed to renderer via `contextBridge`)
  - `src/renderer/src/screens/Providers/Providers.tsx:37,41,107` (renderer holds the raw map in React state and edits each value)
  - `src/renderer/src/screens/Gateway/Gateway.tsx:16`
  - `src/renderer/src/screens/Memory/Memory.tsx:117`
- **Description**: The renderer process receives every secret value verbatim. While the input fields render with `type: "password"`, the value still lives in renderer JS memory, in React DevTools, and in any Electron crash dumps generated by the renderer (`render-process-gone` is logged in `src/main/index.ts:147`). A renderer-side XSS (e.g., from a future markdown-render bug, embedded webview content, or a malicious skill rendered into the UI) reads `window.hermesAPI.getEnv()` directly.
- **Impact**: Any renderer compromise or memory disclosure (DevTools, crash dump, screen reader) exposes every provider key. The renderer never needs the full plaintext to display a "configured" indicator — main could mask all but the last 4 chars and accept new values without round-tripping the old.
- **Remediation**:
  1. Change `get-env` to return only metadata: `{ [key]: { configured: boolean, masked: "sk-…ABCD" } }`. Keep raw values in main only.
  2. For setters, do not require the renderer to send the existing value — only send the new value when changed.
  3. If a "Show key" UX must display the full key, gate it behind a separate `reveal-env-value` IPC that requires recent OS-prompt confirmation (e.g., `safeStorage` re-prompt or a touch-id check).
- **References**: CWE-200, CWE-522, OWASP ASVS V8.3.4

---

### SC-004 — IPC `get-credential-pool` returns raw key material to the renderer

- **Severity**: High
- **Category**: Information exposure across trust boundary (CWE-200)
- **Location**:
  - `src/main/index.ts:538` (`ipcMain.handle("get-credential-pool", () => getCredentialPool())`)
  - `src/main/config.ts:381-386` (returns the full pool incl. raw `entry.key` values)
  - `src/preload/index.ts:378-380`
  - `src/renderer/src/screens/Providers/Providers.tsx:39,45,118-128` (renderer state holds raw entries and re-sends them via `setCredentialPool`)
- **Description**: Same pattern as SC-003 — every entry's full secret string (`{ key: "<RAW_SECRET>", label: "..." }`) crosses the IPC boundary unmasked. The renderer also sends the full list back via `set-credential-pool`, which means any in-place edit forces every secret to make a round trip.
- **Impact**: Renderer-side compromise or DevTools opens the entire credential pool (potentially dozens of provider keys per profile). The reuse risk is amplified because `setCredentialPool` accepts an entire array — a partial-spoof attack only needs one bad entry to overwrite all the others.
- **Remediation**:
  1. Return masked entries: `{ id, label, masked: "sk-…ABCD" }` with a server-issued `id`.
  2. Implement granular IPC handlers: `add-credential`, `remove-credential-by-id`, `relabel-credential`. The renderer never holds raw values.
  3. If reveal is required, gate behind explicit per-entry IPC requiring user confirmation.
- **References**: CWE-200, CWE-522, OWASP ASVS V8.3.4

---

### SC-005 — Atomic write missing for credential and env files

- **Severity**: Medium
- **Category**: Data integrity / credential durability (CWE-362)
- **Location**:
  - `src/main/utils.ts:40-44` (`safeWriteFile` performs `writeFileSync` directly)
  - `src/main/config.ts:34, 154, 188, 266, 353, 378` (all credential/config writers funnel through `safeWriteFile` / `writeFileSync`)
- **Description**: A crash, panic, or power loss during write of `auth.json` or `.env` will leave a truncated file. With `JSON.parse` wrapped in `try/catch` in `readAuthStore` (`src/main/config.ts:367-375`), a corrupt file silently becomes `{}` — the user loses every credential without warning.
- **Impact**: Silent credential loss; user re-enters dozens of API keys with no recovery affordance.
- **Remediation**: Switch `safeWriteFile` to `writeFileSync(tmp, content, { mode: 0o600 })` then `renameSync(tmp, target)`. Optionally fsync via `fs.openSync` + `fs.fsyncSync` before rename.
- **References**: CWE-362, OWASP ASVS V8.3

---

### SC-006 — `~/.hermes` directory created without explicit restrictive mode

- **Severity**: Medium
- **Category**: File permissions (CWE-732)
- **Location**:
  - `src/main/config.ts:31-34` (`mkdirSync(HERMES_HOME, { recursive: true })` — uses default mode 0o777 & ~umask)
  - `src/main/utils.ts:42` (`safeWriteFile` `mkdirSync(dir, { recursive: true })` for parent dirs of credential files — also no mode)
- **Description**: When the credential directory is created, no explicit `mode: 0o700` is set, so directory bits default to umask-modified `0o777` (often `0o755`). On a multi-user host, anyone can `cd` into `~/.hermes/` and `cat auth.json` if the file mode also permits (see SC-001), or at minimum enumerate filenames.
- **Impact**: Reduces defense in depth around the credential files. Even if file modes are tightened, weak directory bits widen the blast radius.
- **Remediation**: Pass `{ recursive: true, mode: 0o700 }` to `mkdirSync` for `HERMES_HOME` and any profile-scoped subdirectory; follow with `chmodSync(HERMES_HOME, 0o700)` to harden pre-existing dirs.
- **References**: CWE-732, OWASP ASVS V6.2

---

### SC-007 — Remote-mode bearer token cached in `desktop.json` without mode 600

- **Severity**: Medium
- **Category**: Credential storage / file permissions (CWE-256, CWE-732)
- **Location**:
  - `src/main/config.ts:30-35` (`writeDesktopConfig` → `writeFileSync` plain)
  - `src/main/config.ts:46-52` (`setConnectionConfig` persists `remoteApiKey` field)
  - `src/main/index.ts:306-312` (`set-connection-config` IPC takes the bearer from renderer and stores it)
  - `src/main/hermes.ts:33-34` (the value is later sent as `Authorization: Bearer <token>` to the remote gateway — confirming it is a real credential, not a UUID room id)
- **Description**: When the user enables "remote" mode, their gateway bearer token is stored verbatim in `~/.hermes/desktop.json` via `writeFileSync` with no mode argument and no atomic write. Same exposure pattern as `auth.json`/`.env` but for the remote-deployment shared secret.
- **Impact**: A second sensitive file (gateway bearer) at world-/group-readable mode. Compromise of this token grants full remote-API access, including streaming chats and all backend tools.
- **Remediation**: Route `desktop.json` through the same hardened writer (mode 0o600 + atomic + chmod). Treat `remoteApiKey` as a credential equivalent to provider keys — mask before returning to renderer (currently `getConnectionConfig` returns it raw at `src/main/config.ts:42`).
- **References**: CWE-256, CWE-312, CWE-732

---

### SC-008 — `set-env`/`set-credential-pool` write paths do not validate key shape, allowing accidental log of secret-shaped values

- **Severity**: Low
- **Category**: Defense in depth / logging risk (CWE-532)
- **Location**:
  - `src/main/index.ts:240-254` (`set-env` accepts arbitrary `key: string, value: string`)
  - `src/main/index.ts:539-549` (`set-credential-pool` accepts arbitrary entries)
  - `src/main/index.ts:111-117` (`uncaughtException` / `unhandledRejection` print the entire `err`/`reason` to stderr — if a downstream handler ever throws with a secret in the message, it lands in the user's terminal/log)
- **Description**: Today no handler logs the secret value, but the global `console.error("[MAIN UNCAUGHT]", err)` and `console.error("[MAIN UNHANDLED REJECTION]", reason)` will dump arbitrary error payloads. If a future change throws `new Error(\`bad key: ${value}\`)` from inside `setEnvValue` or `setCredentialPool`, the secret leaks to stdout/log files. There is no scrubbing layer.
- **Impact**: Latent risk; not currently exploited, but no guardrail.
- **Remediation**: Add a redaction wrapper for the global error handlers — e.g., scrub strings matching `sk-`, `xai-`, `gsk_`, `AIza`, base64 ≥ 40 chars before logging. Centralize all credential writes through a helper that catches & rethrows with a redacted message.
- **References**: CWE-532

---

### SC-009 — Placeholder strings near real key shape can confuse downstream tooling

- **Severity**: Low
- **Category**: Auditor-confusion / pattern-pollution
- **Location**:
  - `src/renderer/src/constants.ts:51` (`placeholder: "sk-or-v1-..."`)
  - `src/renderer/src/constants.ts:64` (`placeholder: "sk-ant-..."`)
  - `src/renderer/src/constants.ts:75` (`placeholder: "sk-..."`)
  - `src/renderer/src/constants.ts:87` (`placeholder: "AIza..."`)
  - `src/renderer/src/constants.ts:99` (`placeholder: "xai-..."`)
  - `src/renderer/src/constants.ts:123` (`placeholder: "sk-..."` — local preset)
- **Description**: These are clearly truncated UI placeholders, not real keys. They will, however, false-positive a naive secret scanner (e.g., a CI gitleaks ruleset). Confirmed via line context — every match ends with `...` and they are stored in `placeholder` fields for `<input>` hints.
- **Impact**: Auditor confusion, CI noise. No real secret exposure.
- **Remediation**: Add `# pragma: allowlist secret` markers (or the equivalent for your scanner of choice) or rephrase to `e.g. sk-…` without the bare prefix, e.g. `[truncated]…`.
- **References**: N/A (informational)

---

### SC-010 — `.gitignore` correctly excludes credential files

- **Severity**: Info (positive observation)
- **Category**: Configuration hygiene
- **Location**: `.gitignore:21-23`
- **Description**:
  ```
  .env
  .env.*
  !.env.example
  ```
  Together with the absence of `.env*` and `auth.json` from `git ls-files | grep -E '(\.env|secret|credential|auth)'` (empty result), this confirms no env or credential file has ever been committed.
- **Note**: `auth.json` is NOT explicitly listed in `.gitignore`. It is currently ignored only because the project never creates it inside the repo — `~/.hermes/auth.json` lives outside. To prevent a future `cd repo && cp ~/.hermes/auth.json .` mistake, recommend adding `auth.json` and `desktop.json` lines to `.gitignore`.
- **References**: OWASP ASVS V14.3

---

### SC-011 — No live secrets found in git history within `src/`

- **Severity**: Info (positive observation)
- **Category**: Git history
- **Location**: Repository-wide
- **Description**: Commands run:
  - `git log --all --full-history -- '.env' '.env.*' '*auth.json*' 'src/**/secrets*'` → empty output (no matching history).
  - `git log -p -S 'sk-' -- src/` → only one commit (`e3b76b8`) matched, and the diff shows it adding/changing the literal placeholder strings `"sk-..."`, `"sk-ant-..."`, `"sk-or-v1-..."` in `src/renderer/src/constants.ts`. No real secret was ever committed.
  - `git log -p -S 'api_key' -- src/` → empty output.
  - `git log -p -S 'BEGIN PRIVATE KEY'` → empty output.
  - `git ls-files | grep -E '(\.env|secret|credential|auth)'` → empty output.
- **Impact**: None — clean history.
- **References**: N/A

---

### SC-012 — Renderer localStorage is used only for non-secret display caches

- **Severity**: Info (positive observation)
- **Category**: Browser storage
- **Location**:
  - `src/renderer/src/screens/Settings/Settings.tsx:10,18,52,118,125,130,173,265` (cached `hermes-version`, `hermes-openclaw-cache`, dismiss flag)
  - `src/renderer/src/screens/Office/Office.tsx:115` (claw3d onboarding flag)
  - `src/renderer/src/components/I18nProvider.tsx:18,41` (locale)
  - `src/renderer/src/components/ThemeProvider.tsx:36,45` (theme)
- **Description**: A grep for `localStorage|sessionStorage|indexedDB` across `src/renderer/` shows zero secret material is persisted in browser storage. Provider/credential keys live only in transient React state populated from the IPC `getEnv`/`getCredentialPool` calls (which is itself the SC-003/SC-004 finding). No leakage to disk via localStorage.
- **Impact**: None. The risk is upstream (renderer holding plaintext in JS heap), not in browser storage.
- **References**: N/A

---

## Methodology

### Files reviewed
- `src/main/config.ts` — credential pool + env reader/writer (full read)
- `src/main/utils.ts` — `safeWriteFile` helper (full read)
- `src/main/index.ts` — IPC handler registry (full read; focus on `set-env`, `get-env`, `set-credential-pool`, `get-credential-pool`, `set-connection-config`, `get-connection-config`)
- `src/main/askpass.ts` — sudo password dialog (full read)
- `src/main/installer.ts` — `runHermesDump`, `readLogs` (relevant excerpts)
- `src/main/hermes.ts` — gateway env preparation (`KNOWN_API_KEYS`, `Authorization: Bearer` header)
- `src/preload/index.ts` — context-bridge API surface (full read)
- `src/renderer/src/constants.ts` — settings sections / placeholders (full read)
- `src/renderer/src/screens/Providers/Providers.tsx` — renderer use of env + pool (relevant excerpt)
- `src/renderer/src/screens/Settings/Settings.tsx` — localStorage usage (grep)
- `tests/constants.test.ts` — confirmed no real secrets in fixtures
- `.gitignore`

### Grep patterns executed
1. `sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{10,}|Bearer[[:space:]]+[A-Za-z0-9._-]{20,}|api[_-]?key[[:space:]]*[:=][[:space:]]*['"][A-Za-z0-9]|xai-|gsk_|AIza` over `src/` — only placeholder hits in `src/renderer/src/constants.ts` (see SC-009).
2. `console.(log|error|warn|info|debug)|logger\.` over `src/main/` — 7 hits, all log error metadata or tags, none log secret values.
3. `[A-Za-z0-9+/]{40,}={0,2}` over `src/` excluding tests/svg/png/node_modules — empty.
4. `localStorage|sessionStorage|indexedDB` over `src/renderer/` — only display caches (see SC-012).
5. `API_KEY|TOKEN|apiKey|api_key` over `src/main/` — all matches are key-name constants (used as lookup keys), no embedded values.

### Bash git-history commands executed
1. `git log --all --full-history -- '.env' '.env.*' '*auth.json*' 'src/**/secrets*'` → empty.
2. `git log -p -S 'sk-' -- src/` → one commit `e3b76b8` adding placeholder strings only (redacted summary: `"sk-..."`, `"sk-ant-..."`, `"sk-or-v1-..."`).
3. `git log -p -S 'api_key' -- src/` → empty.
4. `git log -p -S 'BEGIN PRIVATE KEY'` → empty.
5. `git ls-files | grep -E '(\.env|secret|credential|auth)'` → empty.
6. `find . -maxdepth 4 -type f \( -name '.env' -o -name '.env.*' -o -name 'auth.json' \) ! -path '*/node_modules/*'` → empty.

### Out of scope / not investigated
- Behavior of the downstream `hermes-agent` Python tool (its own `dump`/log output reaches the renderer through `runHermesDump` and `readLogs` — what those processes actually print is governed by the upstream repo, not this Electron shell).
- Renderer XSS surface (would influence the actual exploitability of SC-003/SC-004 but is the remit of a separate Electron-renderer-security review).
- `src/main/askpass.ts` sudo dialog uses `nodeIntegration: true, contextIsolation: false` — the OS password is exchanged over a unix socket with mode `0o600`, so the credential never lands on disk; the BrowserWindow security posture is left to the Electron-security audit.
- Code signing, auto-updater channel integrity (`electron-updater`).
- Operating-system keychain integration alternatives (suggested in SC-001/SC-002 but not implemented today).

---

## Summary

No live secrets are committed to the repository or its history (SC-011), and the `.gitignore` correctly blocks `.env`/`.env.*` (SC-010). The principal concerns are runtime: provider keys and the credential pool are written to disk under default umask (SC-001, SC-002, SC-006, SC-007), and the renderer process receives raw key material across IPC where masked metadata would suffice (SC-003, SC-004). Closing the SC-001…SC-004 cluster — set `mode 0o600`, atomic writes, mask IPC payloads — eliminates the highest-impact exposure paths.

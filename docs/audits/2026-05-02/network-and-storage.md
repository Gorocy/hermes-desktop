# Network & Storage Audit — hermes-desktop

- **Date (UTC):** 2026-05-02
- **Project:** hermes-desktop
- **Commit:** 72d7bcc
- **Auditor:** network-and-storage-auditor
- **Scope:** HTTP/HTTPS calls, SSE streaming, Authorization Bearer handling, TLS validation, URL construction, better-sqlite3 prepared statements, FTS5 MATCH parameterization, internal bind addresses (127.0.0.1 vs 0.0.0.0), electron-updater feed configuration, log surface for tokens/URLs.
- **Method:** Read-only static analysis. Grep for `fetch\(`, `https?\.request`, `Bearer`, `Authorization`, `rejectUnauthorized`, `tls\.`, `db\.prepare\(`, `db\.exec\(`, `MATCH`, bind-address literals, `console\.(log|error|warn)`. Manual review of `src/main/hermes.ts`, `src/main/sessions.ts`, `src/main/session-cache.ts`, `src/main/memory.ts`, `src/main/index.ts`, `src/main/installer.ts`, `src/main/claw3d.ts`, `src/main/askpass.ts`, `src/main/config.ts`, `dev-app-update.yml`, `electron-builder.yml`, `package.json`. No network requests or source modifications were performed.

## Severity Matrix

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 1 |
| Medium   | 4 |
| Low      | 3 |
| Info     | 4 |

---

## Findings

### NS-001 — Remote API URL accepts plaintext `http://` schemes; Bearer token can be sent in cleartext

- **Severity:** High
- **Category:** Cleartext transmission of credentials (CWE-319)
- **Location:** `src/main/hermes.ts:17-25`, `src/main/hermes.ts:31-37`, `src/main/hermes.ts:303-304`, `src/main/hermes.ts:765-789`

**Description**
The remote-mode connection URL is taken verbatim from the user-supplied value in `desktop.json` (`getConnectionConfig().remoteUrl`) and never validated to require HTTPS. The scheme is dispatched purely on a `startsWith("https")` test — anything else (including `http://`) silently falls back to plain HTTP. The `Authorization: Bearer ${conn.apiKey}` header is appended to every outbound request, including the `/v1/chat/completions` POST, the `/health` probe, and `testRemoteConnection`.

```ts
// src/main/hermes.ts:17-25
const LOCAL_API_URL = "http://127.0.0.1:8642";

function getApiUrl(): string {
  const conn = getConnectionConfig();
  if (conn.mode === "remote" && conn.remoteUrl) {
    return conn.remoteUrl.replace(/\/+$/, "");
  }
  return LOCAL_API_URL;
}
```

```ts
// src/main/hermes.ts:31-37
function getRemoteAuthHeader(): Record<string, string> {
  const conn = getConnectionConfig();
  if (conn.mode === "remote" && conn.apiKey) {
    return { Authorization: `Bearer ${conn.apiKey}` };
  }
  return {};
}
```

```ts
// src/main/hermes.ts:303-304
const chatUrl = `${getApiUrl()}/v1/chat/completions`;
const requester = chatUrl.startsWith("https") ? https.request : http.request;
```

The renderer-facing setter at `src/main/index.ts:306-312` accepts any string; the i18n strings explicitly tell users they may leave the key empty when "tunneling to localhost" but say nothing about the scheme requirement.

**Impact**
A user who pastes a remote URL beginning with `http://` (typo, copy/paste from documentation, or hostile MITM redirect) will transmit the long-lived `API_SERVER_KEY` Bearer token in the clear over every chat request, every 15-second `/health` poll, and every full-conversation streaming POST.

**Remediation**
- In `setConnectionConfig`, reject any `remote` URL that does not start with `https://` (allow only `http://127.0.0.1`/`http://localhost` for SSH-tunnel use). Surface the error to the renderer.
- Strengthen the dispatch: `new URL(chatUrl).protocol === "https:"` and require it for remote mode regardless of input.
- Keep one explicit allowlist for `localhost`/`127.0.0.1` and warn in the UI when the loopback exception is used.

---

### NS-002 — Streaming chat POST has no socket timeout; abort relies solely on user/IPC-driven cancellation

- **Severity:** Medium
- **Category:** Resource exhaustion / token-in-memory exposure (CWE-400)
- **Location:** `src/main/hermes.ts:303-311`, `src/main/hermes.ts:312-381`

**Description**
The streaming SSE POST request omits the `timeout:` option that the health probes set. Only the `/health` GET (`timeout: 1500`) and `testRemoteConnection` GET (`timeout: 5000`) attach `req.on("timeout", …)`. The chat request is governed only by `controller.signal` (an `AbortController` plumbed through IPC).

```ts
// src/main/hermes.ts:303-311
const chatUrl = `${getApiUrl()}/v1/chat/completions`;
const requester = chatUrl.startsWith("https") ? https.request : http.request;
const req = requester(
  chatUrl,
  {
    method: "POST",
    headers,            // contains Authorization: Bearer …
    signal: controller.signal,
  },
```

**Impact**
A silent half-open TCP connection (server stops emitting bytes but never closes) leaves the request and `headers` object — which includes the live Bearer token — pinned in memory indefinitely, and the renderer never sees `chat-done`/`chat-error`. There is no socket-idle bound and `keep-alive` failures will not free the connection. SSE keep-alives are not enforced.

**Remediation**
- Pass `{ method: "POST", headers, signal: controller.signal, timeout: 60_000 }` and add `req.on("timeout", () => { req.destroy(); finish("Request timed out"); });`.
- Consider an idle-byte timer on `res` so a stalled stream after the first chunk also terminates.

---

### NS-003 — Remote URL is accepted from the renderer without scheme/host validation; loopback-vs-public determination is case-sensitive substring

- **Severity:** Medium
- **Category:** Improper input validation / SSRF surface (CWE-20, CWE-918)
- **Location:** `src/main/index.ts:306-312`, `src/main/config.ts:46-52`, `src/main/hermes.ts:486-489`

**Description**
The IPC handler trusts whatever string the renderer hands in. There is no scheme check, no host validation, and no rejection of obviously dangerous values (e.g. `file://`, `javascript:`, embedded credentials in URL `https://user:pass@host/`).

```ts
// src/main/index.ts:306-312
ipcMain.handle(
  "set-connection-config",
  (_event, mode: "local" | "remote", remoteUrl: string, apiKey?: string) => {
    setConnectionConfig({ mode, remoteUrl, apiKey: apiKey || "" });
    return true;
  },
);
```

```ts
// src/main/hermes.ts:486-489
// Local servers (localhost/127.0.0.1) don't need a real key
if (!resolvedKey && /localhost|127\.0\.0\.1/i.test(mc.baseUrl)) {
  resolvedKey = "no-key-required";
}
```

The substring check `localhost|127\.0\.0\.1` matches anywhere in the URL — `https://attacker.com/?h=localhost` would qualify the URL as "local". This is currently used only to skip API-key requirement (so the impact here is a UX/key-handling issue rather than direct exploitation), but the same loose pattern recurs as a security primitive.

**Impact**
Compromised renderer (XSS via markdown, malicious skill) can persist any URL into `desktop.json` and cause every subsequent request to leak the Bearer token to attacker-controlled hosts. The loose `localhost|127.0.0.1` regex enables a "looks local but isn't" bypass that may be exploitable in future loopback-only branches.

**Remediation**
- Validate via `new URL(remoteUrl)` and require `protocol === "https:"` (with a documented exception for `hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1"`).
- Replace the substring regex with `new URL(mc.baseUrl).hostname` exact-match against the loopback set.
- Reject embedded user-info (`url.username || url.password`).

---

### NS-004 — `getSessionMessages` / `searchSessions` / `syncSessionCache` open the SQLite DB without setting a busy timeout or `fileMustExist`

- **Severity:** Medium
- **Category:** Resource exhaustion / locking
- **Location:** `src/main/sessions.ts:36-39`, `src/main/session-cache.ts:75-78`, `src/main/memory.ts:87`

**Description**
Every read-only query opens a fresh `Database(DB_PATH, { readonly: true })` and closes it. There is no `timeout:` option and no `fileMustExist: true` — the `existsSync` check that precedes it is racy.

```ts
// src/main/sessions.ts:36-39
function getDb(): Database.Database | null {
  if (!existsSync(DB_PATH)) return null;
  return new Database(DB_PATH, { readonly: true });
}
```

If the Hermes Python gateway holds an exclusive write lock at the moment the desktop app issues a query (e.g. during heavy ingest), the call blocks indefinitely on the main process, freezing the IPC handler.

**Impact**
A long-running gateway transaction can hang the desktop UI's session list. Combined with the lack of timeout in network probes, this can produce a fully wedged main process with no user feedback.

**Remediation**
- Pass `{ readonly: true, fileMustExist: true, timeout: 2000 }` to `new Database(...)`.
- Consider a singleton open-once handle for the session of the renderer rather than open/close per query.

---

### NS-005 — FTS5 `MATCH` sanitizer strips literal `"` but does not strip column-prefix or operator tokens

- **Severity:** Medium
- **Category:** FTS5 query injection / DoS surface (CWE-89, CWE-1287)
- **Location:** `src/main/sessions.ts:100-126`

**Description**
The sanitizer wraps every whitespace-split token in double quotes and appends `*`, after stripping internal `"`:

```ts
// src/main/sessions.ts:100-126
// Sanitize query for FTS5: wrap each word with quotes for safety, add * for prefix
const sanitized = query
  .trim()
  .split(/\s+/)
  .filter((w) => w.length > 0)
  .map((w) => `"${w.replace(/"/g, "")}"*`)
  .join(" ");

if (!sanitized) return [];

const rows = db
  .prepare(
    `SELECT DISTINCT
      m.session_id,
      …
      snippet(messages_fts, 0, '<<', '>>', '...', 40) as snippet
    FROM messages_fts
    JOIN messages m ON m.id = messages_fts.rowid
    JOIN sessions s ON s.id = m.session_id
    WHERE messages_fts MATCH ?
    ORDER BY rank
    LIMIT ?`,
  )
  .all(sanitized, limit) as Array<{…}>;
```

The bound parameter (`?`) makes this safe from classic SQL injection, but FTS5 has its own grammar: a token like `col:term` is interpreted as a column-restricted phrase, and inside the wrapping quotes the `*` is appended outside (`"col:term"*`). Tokens like `NEAR(`, `+`, `-`, `^` are *defanged* by the surrounding `"…"`, so the practical injection surface is small. However, an adversarial query of many short tokens (e.g. `a a a a … *200`) becomes `"a"* "a"* "a"* …*` and lets an attacker (or accidentally, a paste of Markdown) construct an expensive disjunction. The sanitizer also leaves carriage returns, NULs, and FTS5 `\` escape semantics unaddressed because of the surrounding quotes — but an unmatched closing quote at end-of-input is impossible because the function strips `"`.

**Impact**
Low practical injection risk thanks to the prepared parameter, but an unbounded number of `OR`-joined tokens can still produce slow scans on the FTS5 index. Treat as DoS / resource exhaustion rather than exfiltration.

**Remediation**
- Cap the number of tokens (e.g. first 8) and the per-token length (e.g. 64 chars).
- Whitelist allowed characters (`/[A-Za-z0-9_]/`) before the wrap, so `:` cannot become an FTS5 column-prefix.
- Add a row LIMIT-driven `EXPLAIN QUERY PLAN` regression test for malformed input.

---

### NS-006 — `dev-app-update.yml` and the production `electron-builder.yml` publish target are bound to a personal fork (`fathah/hermes-desktop`)

- **Severity:** Low
- **Category:** Supply-chain / update integrity (CWE-345)
- **Location:** `dev-app-update.yml:1-4`, `electron-builder.yml:54-57`

**Description**
Both the dev update channel and the release channel point to the same GitHub repo:

```yaml
# dev-app-update.yml
provider: github
owner: fathah
repo: hermes-desktop
updaterCacheDirName: hermes-desktop-updater
```

```yaml
# electron-builder.yml:54-57
publish:
  provider: github
  owner: fathah
  repo: hermes-desktop
```

`dev-app-update.yml` is excluded from the packaged build by the `files:` block (`"!{…,dev-app-update.yml,…}"`), so it cannot leak into a release artifact directly. However, electron-builder uses HTTPS + Ed25519/SHA-512 signature verification of the release feed only when `publisherName` (Windows) or notarization (mac) is configured. `mac.notarize: false` is set in `electron-builder.yml:32`, which means macOS users get an unsigned/unnotarized binary; the auto-update path still validates HTTPS but Apple's gatekeeper will not enforce code-signing integrity.

**Impact**
- Dev: unsigned dev builds use the same feed as production — typo or env-var leak could install a dev artifact on a production user.
- Release: macOS users do not get gatekeeper validation; if the fork's GitHub releases credentials are compromised, an unsigned update can replace the app.

**Remediation**
- Set `mac.notarize: true` (or migrate to Apple's `notarytool` flow) for any signed release.
- Confirm `provider: github` is paired with HTTPS-only feed (default — verified) and enforce minimum-version bump checks.
- Document that `dev-app-update.yml` must never ship in a release artifact (the current `files:` exclusion does enforce this — keep in CI).

---

### NS-007 — Desktop notification body and renderer chat-error IPC channel echo the upstream error string verbatim

- **Severity:** Low
- **Category:** Information exposure through error messages (CWE-209, CWE-532)
- **Location:** `src/main/index.ts:375-385`, `src/main/hermes.ts:316-330`, `src/main/hermes.ts:560-566`

**Description**
When a remote/local upstream returns a non-200 status, the body is sliced and forwarded to the renderer (and to a desktop `Notification` if the window is unfocused).

```ts
// src/main/hermes.ts:316-330
if (res.statusCode !== 200) {
  let errBody = "";
  res.on("data", (d) => { errBody += d.toString(); });
  res.on("end", () => {
    try {
      const err = JSON.parse(errBody);
      finish(err.error?.message || `API error ${res.statusCode}`);
    } catch {
      finish(
        `API server returned ${res.statusCode}: ${errBody.slice(0, 200)}`,
      );
    }
  });
  return;
}
```

```ts
// src/main/index.ts:380-385
new Notification({
  title: "Hermes Agent — Error",
  body: error.slice(0, 100),
}).show();
```

A misconfigured proxy or a CLI fallback path that includes the spawned process's full env in stderr (`/Users/gorac/Desktop/hermes-desktop/src/main/hermes.ts:534-554`) could push diagnostic strings — including provider URLs and partial keys leaked by upstream — to a system-level notification surface. The CLI fallback explicitly forwards lines matching `error|denied|unauthorized|invalid` to `cb.onChunk` (`src/main/hermes.ts:544-550`), and many providers (OpenAI, Anthropic) have echoed the request URL or key prefix in their 401 responses historically.

**Impact**
Bounded (200/300 chars), but a Bearer-token prefix or full provider URL embedded in an upstream error could appear in a desktop notification, in a renderer chat bubble, or in a Hermes log.

**Remediation**
- Run errors through a redactor that masks `Bearer …`, `sk-…`, and `apikey=…` patterns before forwarding.
- For desktop notifications, emit a generic body and put the full text only in the chat panel.

---

### NS-008 — Unconditional process logging of renderer console at level ≥ warn writes raw renderer output to main-process stdout

- **Severity:** Low
- **Category:** Information exposure through log files (CWE-532)
- **Location:** `src/main/index.ts:154-161`

**Description**

```ts
mainWindow.webContents.on(
  "console-message",
  (_event, level, message, line, sourceId) => {
    if (level >= 2) {
      console.error(`[RENDERER ERROR] ${message} (${sourceId}:${line})`);
    }
  },
);
```

If the renderer ever logs a request body, URL, or token (the React code today does not appear to, but third-party libraries may), it is mirrored to the packaged Electron's `stderr`, which on macOS is captured by the system log (`Console.app` → `hermes`) and on Linux by the systemd journal.

**Impact**
A future renderer change or markdown-rendering library that logs payloads would emit them to the OS-level log surface.

**Remediation**
- Gate this forwarding behind `is.dev`, or scrub `Bearer`, `sk-`, `Authorization:` substrings before the `console.error`.

---

### NS-009 (Info) — All `db.prepare(...)` call sites use bound parameters (`?`); no string-concatenated SQL was found

- **Severity:** Info
- **Category:** Confirmed positive observation (CWE-89 not present)
- **Location:** `src/main/sessions.ts:48-60`, `src/main/sessions.ts:111-126`, `src/main/sessions.ts:159-164`, `src/main/session-cache.ts:88-94`, `src/main/session-cache.ts:122-126`, `src/main/memory.ts:88-94`

Every prepared statement uses `?` placeholders or (in the table-existence probe) is a literal string with no user input:

```ts
// src/main/sessions.ts:159-164
db.prepare(
  `SELECT id, role, content, timestamp
   FROM messages
   WHERE session_id = ? AND role IN ('user', 'assistant') AND content IS NOT NULL
   ORDER BY timestamp, id`,
).all(sessionId)
```

No template-literal SQL with renderer-derived input was found. The DB is opened `readonly: true` from the desktop process, so even an injection bug would not be able to perform DDL. There are no migrations executed by hermes-desktop itself — schema and DDL live in the Hermes CLI.

---

### NS-010 (Info) — Hermes local API is bound to `127.0.0.1:8642`, not `0.0.0.0`

- **Severity:** Info
- **Category:** Confirmed positive observation
- **Location:** `src/main/hermes.ts:17`, `src/main/hermes.ts:101-114`, `src/main/claw3d.ts:108-110`, `src/main/claw3d.ts:127`

```ts
// src/main/hermes.ts:101-114
const addition = `
# Desktop app API server (auto-configured)
platforms:
  api_server:
    enabled: true
    extra:
      port: 8642
      host: "127.0.0.1"
`;
```

`claw3d.ts` similarly writes `HOST=127.0.0.1` into the office `.env` and probes ports via `createConnection({ port, host: "127.0.0.1" })`. No `0.0.0.0` bind was found in any spawned-process configuration.

---

### NS-011 (Info) — TLS validation is left at Node defaults; no `rejectUnauthorized: false`, no `tls.createSecureContext` overrides

- **Severity:** Info
- **Category:** Confirmed positive observation (CWE-295 not present)
- **Location:** `src/main/hermes.ts` (entire file)

A grep for `rejectUnauthorized`, `tls.`, `NODE_TLS_REJECT_UNAUTHORIZED`, and certificate-bypass APIs returned no matches. All `https.request` calls inherit Node.js's stock CA bundle and full cert validation. No custom HTTPS agents, no insecure HTTPS-Proxy setup, no `setSecureProtocol` calls.

---

### NS-012 (Info) — Only mandatory log file names are accepted in the `read-logs` IPC handler

- **Severity:** Info
- **Category:** Confirmed positive observation (path-traversal mitigated)
- **Location:** `src/main/installer.ts:857-879`

```ts
const allowed = ["agent.log", "errors.log", "gateway.log"];
const file = allowed.includes(logFile) ? logFile : "agent.log";
const fullPath = join(logsDir, file);
```

No path-traversal vector here — the user-supplied `logFile` is constrained to a 3-element allowlist before `join`. Note that the contents of those log files may contain Hermes Agent (Python) logs with provider keys; that is out of scope for this audit and belongs to the upstream Hermes repo.

---

## Methodology

### Files reviewed in full
- `src/main/hermes.ts`
- `src/main/sessions.ts`
- `src/main/session-cache.ts`
- `src/main/memory.ts`
- `src/main/index.ts`
- `src/main/installer.ts`
- `src/main/config.ts`
- `src/main/claw3d.ts`
- `src/main/askpass.ts`
- `src/main/cronjobs.ts`
- `src/main/skills.ts`
- `src/main/sse-parser.ts`
- `dev-app-update.yml`
- `electron-builder.yml`
- `package.json`

### Grep patterns executed
- `fetch\(`
- `https?\.request`
- `Bearer`, `Authorization`
- `rejectUnauthorized`, `tls\.`
- `db\.prepare\(`, `db\.exec\(`, `MATCH`
- `127\.0\.0\.1|localhost|0\.0\.0\.0`
- `console\.(log|error|warn)`
- `encodeURIComponent`, `encodeURI\b`
- `chmod|0o600|0o700|umask`
- `User-Agent`
- `apiKey|api_key|API_KEY|TOKEN|token`
- `createServer|listen\(`

### Out-of-scope notes
- Hermes Agent (Python, `~/.hermes/hermes-agent/`) is not audited here; FTS5 indexing, the `state.db` schema, and the API server's own request logging belong to the upstream repo.
- Renderer-side token storage in React state and the preload API surface (`src/preload/index.ts`) were not deeply audited — see the IPC/preload audit.
- Skills and cron CLI fall-through to spawned Python processes; their argument-injection surface is the responsibility of the process-spawn auditor.
- macOS Keychain integration is not present; the remote API key is stored in `~/.hermes/desktop.json` as plaintext (out of scope for "network and storage" but flagged here for triage).

### Severity legend
- **Critical** — `rejectUnauthorized: false` in remote production fetch; classic SQLi via string concatenation.
- **High** — Token logged to stdout/file; FTS5 operator-injection in `MATCH`; bind to `0.0.0.0` for an internal API; missing TLS on update feed.
- **Medium** — URL with raw user input not URL-encoded; missing fetch timeout; SSE keep-alive failures leak token in memory.
- **Low** — Verbose logging of non-sensitive fields; missing User-Agent; supply-chain dev-channel notes.
- **Info** — Confirmed positive observations.

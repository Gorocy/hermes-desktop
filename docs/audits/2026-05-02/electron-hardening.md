# Electron Hardening Audit -- hermes-desktop

| Field      | Value                                                           |
| ---------- | --------------------------------------------------------------- |
| Date (UTC) | 2026-05-02                                                      |
| Project    | hermes-desktop (Electron 39.2.6 + React 19 + TypeScript 5.9)    |
| Auditor    | electron-hardening-auditor                                      |
| Commit     | 72d7bcc                                                         |
| Scope      | BrowserWindow webPreferences, preload bridge, IPC, CSP, navigation guards, electron-updater, electron-builder packaging hardening |
| Method     | Read-only static analysis. No source files modified. Findings cite `file:line`. Code excerpts quote the project verbatim. |

---

## Severity matrix

| Severity | Count |
| -------- | ----- |
| Critical | 2     |
| High     | 4     |
| Medium   | 5     |
| Low      | 4     |
| Info     | 2     |
| **Total**| **17**|

---

## Findings

### EH-001 -- `sandbox: false` on the only BrowserWindow

- **Severity**: Critical
- **Category**: BrowserWindow / process model
- **Location**: `src/main/index.ts:135-139`

```ts
    webPreferences: {
      preload: join(__dirname, "../preload/index.js"),
      sandbox: false,
      webviewTag: true,
    },
```

- **Description**: The single application window is created with `sandbox: false` explicitly, disabling Chromium's renderer sandbox. With `contextIsolation` left at default (true) and `nodeIntegration` left at default (false), the renderer cannot directly call `require`, but `sandbox: false` still grants the preload script (and any code that escapes the v8 context boundary, e.g. via a Chromium RCE) full Node.js runtime access -- `require`, `process`, OS-process spawning primitives, `fs`, etc. The Electron security checklist lists "Enable Process Sandboxing" as Checklist Item #4 and considers it mandatory hardening for any window that loads untrusted or remote-influenced HTML. Because the renderer also enables `webviewTag: true` (see EH-002) and renders Markdown/code blocks from arbitrary AI tool outputs and remote chat partners, the absence of the sandbox materially raises the blast radius of any Chromium 0-day.
- **Impact**: A renderer-side memory-corruption or v8 type-confusion bug becomes an immediate code-execution-on-host primitive. Combined with the broad IPC surface (60+ handlers, several of which spawn shell commands and Python CLIs -- see EH-005, EH-008), an attacker who lands a single renderer exploit can pivot to arbitrary command execution on the user's machine.
- **Remediation**: Set `sandbox: true` and `contextIsolation: true` explicitly in `webPreferences`. Convert the preload to use only `ipcRenderer.invoke`/`on` and `contextBridge` (already the case here). Confirm the sandboxed preload still has access to the `electron` module subset it needs (`contextBridge`, `ipcRenderer`).
- **References**:
  - Electron Security Checklist #4 -- Enable Process Sandboxing
  - Electron Security Checklist #2 -- Do Not Enable Node.js Integration for Remote Content
  - CWE-693 (Protection Mechanism Failure)

---

### EH-002 -- `webviewTag: true` enabled with no `will-attach-webview` guard

- **Severity**: Critical
- **Category**: BrowserWindow / embedded content
- **Location**: `src/main/index.ts:135-139` (option) and `src/main/index.ts:122-180` (no `will-attach-webview` listener anywhere in the file)

```ts
    webPreferences: {
      preload: join(__dirname, "../preload/index.js"),
      sandbox: false,
      webviewTag: true,
    },
```

- **Description**: `webviewTag: true` re-enables the legacy `<webview>` element in the renderer. Electron's documentation and security checklist both flag this as a high-risk feature: a `<webview>` can be embedded by any HTML the renderer loads, and unless the main process intercepts the `will-attach-webview` event, the embedder controls the child's `webPreferences` (including `nodeIntegration` and `preload`), enabling sandbox-escape. Searching the entire `src/main/` tree confirms there is no `will-attach-webview`, `setWebviewTag(false)`, or `webContents.on('will-attach-webview', ...)` handler. The renderer also injects untrusted Markdown via `react-markdown` (see `src/renderer/index.html:13` referencing `/src/main.tsx`), which expands the HTML attack surface that could plant a malicious `<webview src="...">` if any sanitiser regression occurs.
- **Impact**: Any HTML-injection vector (Markdown content rendered verbatim, MCP-server output, model-generated text inserted into the DOM as raw HTML) can spawn `<webview>` with attacker-controlled `webpreferences`/`preload`, escaping into Node-integrated execution and bypassing the existing `setWindowOpenHandler` (which only constrains `window.open`). Combined with EH-001 (`sandbox: false`), the impact is full host RCE.
- **Remediation**: Remove `webviewTag: true` unless a specific, documented feature requires it. If it is needed, register a `web-contents-created` listener that calls `event.preventDefault()` for any `will-attach-webview` whose `webPreferences` do not match a strict allow-list (`nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, no custom `preload`), and a strict source-URL allow-list. Prefer a `BrowserView` or sandboxed `iframe` over `<webview>`.
- **References**:
  - Electron Security Checklist #11 -- Verify WebView Options Before Creation
  - Electron docs -- `<webview>` Tag, "Manually Enabling..."
  - CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

---

### EH-003 -- `setWindowOpenHandler` opens every URL via `shell.openExternal` with no allow-list

- **Severity**: High
- **Category**: Navigation / external launching
- **Location**: `src/main/index.ts:170-173`

```ts
  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url);
    return { action: "deny" };
  });
```

- **Description**: The handler correctly denies the new-window action, but it unconditionally forwards `details.url` to `shell.openExternal`. `shell.openExternal` resolves the URL through the OS's URL-scheme registrar, which on macOS/Windows/Linux can launch arbitrary local handlers (`file://`, `smb://`, custom schemes such as `ms-settings:`, `vbscript:`, custom protocol handlers shipped by other installed apps that take parameters). A renderer compromise -- or even just an attacker-controlled chat message that resolves to a renderer-side `window.open(...)` via Markdown link expansion -- can dispatch arbitrary URI schemes against the user's machine. This is a known Electron pitfall ("URL handler abuse"). The same uncritical pattern is also present in the `open-external` IPC handler (`src/main/index.ts:640-642`), which accepts any string from the renderer:

```ts
  ipcMain.handle("open-external", (_event, url: string) => {
    shell.openExternal(url);
  });
```

- **Impact**: Renderer-controlled invocation of arbitrary OS URL handlers. Possible vectors include `file:` paths to attacker-staged binaries on a network share, `vbscript:` (older Windows), `ms-cxh-full:` and similar Windows protocol abuse, custom `slack://`, `zoommtg://`, `mailto:` payloads with crafted parameters, and on macOS, `x-apple-prefspane:` or Sourcetree-style protocol handlers that can take command arguments. Some custom schemes have known argument-injection bugs.
- **Remediation**: Validate `details.url` and the `open-external` argument with `new URL(url)` and explicitly allow only `https:` (and optionally `http:`/`mailto:`) before calling `shell.openExternal`. Reject any other scheme. Apply the same policy in both call sites -- they are the only places the app calls `shell.openExternal` on dynamic input.
- **References**:
  - Electron Security Checklist #14 -- Disable or Limit Navigation
  - Electron docs -- "shell.openExternal" security note
  - CWE-601 (URL Redirection to Untrusted Site / "Open Redirect"); CWE-88 (Argument Injection)

---

### EH-004 -- Missing `will-navigate` and `will-redirect` guards

- **Severity**: High
- **Category**: Navigation
- **Location**: `src/main/index.ts:122-180` (no `will-navigate` or `will-redirect` listener anywhere; also no `app.on('web-contents-created', ...)` navigation hardening)

```ts
  // Only navigation-related listener present:
  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url);
    return { action: "deny" };
  });
```

- **Description**: Electron Security Checklist #13 ("Disable or Limit Navigation") requires intercepting `will-navigate` and `will-redirect` so that a compromised renderer (or an unfortunate `<a target="_top" href="https://evil/">` click) cannot load arbitrary remote origins inside the privileged main window -- a "remote takeover" of the application origin. The only navigation hook present is `setWindowOpenHandler` (popups), and even the global `app.on('web-contents-created', ...)` block (at `src/main/index.ts:848`) only attaches `optimizer.watchWindowShortcuts(window)` -- no security wiring.
- **Impact**: Any code in the renderer (including a poorly-handled link inside Markdown content rendered from chat / tool output) can navigate the entire window to a remote attacker page. Once the renderer points at a remote origin, the existing CSP `default-src 'self'` (see EH-009) does NOT protect against the navigation itself -- it only protects subresource loads -- and the renderer is now rendering attacker HTML inside a window with an exposed `hermesAPI` preload bridge. Combined with EH-001 (no sandbox) and EH-002 (`webviewTag: true`), full RCE is plausible.
- **Remediation**: In `app.on('web-contents-created', (_, contents) => { ... })`, register `contents.on('will-navigate', (event, navigationUrl) => { ... })` and `contents.on('will-redirect', ...)`. Compute the allowed origin once (the dev `ELECTRON_RENDERER_URL` in dev, the `file://` scheme of the loaded `index.html` in prod) and call `event.preventDefault()` for any other origin. Optionally route allowed external links through `shell.openExternal` after scheme validation (see EH-003).
- **References**:
  - Electron Security Checklist #13 -- Disable or Limit Navigation
  - Electron Security Checklist #14 -- Verify WebView Options
  - CWE-601 (URL Redirection to Untrusted Site)

---

### EH-005 -- IPC handlers spawn child processes with renderer-supplied arguments

- **Severity**: High
- **Category**: IPC / argument handling
- **Location**: `src/main/index.ts:648-652` (handler) plus `src/main/installer.ts:592-630` (`runHermesImport`)

```ts
  // src/main/index.ts:648
  ipcMain.handle(
    "run-hermes-import",
    (_event, archivePath: string, profile?: string) =>
      runHermesImport(archivePath, profile),
  );
```

```ts
  // src/main/installer.ts:601
  const args = [HERMES_SCRIPT, "import", archivePath];
  if (profile && profile !== "default") args.push("-p", profile);
  ...
  // execFile invocation (see installer.ts:605-630)
```

- **Description**: The renderer can pass any string as `archivePath`, and the main process passes it directly into the underlying CLI as an argument to the Hermes Python import command. While `execFile` (vs the shell-string variant) avoids shell-metacharacter injection (good), the `archivePath` is not validated as: (a) absolute, (b) inside a user-data directory, (c) ending in an expected extension, or (d) free of `--`-prefixed flag-injection (a value beginning with `-` would be interpreted as a flag by the Python CLI). The same pattern recurs in:
  - `claw3d-set-port` -> `setClaw3dPort(port: number)` -- port is not validated as `1024 <= port <= 65535`.
  - `claw3d-set-ws-url` -> `setClaw3dWsUrl(url: string)` -- URL is not validated; written verbatim into a settings file consumed by `npm run dev` env (`src/main/claw3d.ts:451`).
  - `set-env` (`src/main/index.ts:241-254`) and `set-config` (`:260-265`) accept arbitrary `key`/`value` strings from the renderer and write them into the user's `.env` and `config.yaml` -- keys are not validated against `^[A-Z_][A-Z0-9_]*$`, so an attacker could inject newline characters, comment tokens, or YAML-breaking syntax (`!!python/object/...`) -- see EH-006.
  - `add-memory-entry`, `update-memory-entry` (`:461-475`) and `write-soul` (`:484`) write renderer-controlled content to disk inside `HERMES_HOME` with no length cap.
  - `create-cron-job` (`:614-624`) -> `createCronJob(schedule, prompt, name, deliver, profile)` forwards every value into the underlying process spawn as CLI arguments to `hermes cron create` (see `src/main/cronjobs.ts:117-135`).
- **Impact**: Renderer compromise (or a future bug that causes the renderer to forward content from a remote API directly into one of these IPC channels) yields: arbitrary file overwrite via `archivePath`, environment-variable injection via `set-env`, YAML-parser confusion via `set-config`, and CLI flag-injection if `archivePath`/`prompt`/`name` start with `-`/`--`.
- **Remediation**: For every handler, validate inputs with explicit guards:
  - Strings: enforce maximum length (e.g. 4 KB), forbid `\0`, and reject leading `-`/`--`.
  - Paths: require absolute, canonicalise via `path.resolve`, then assert the result is inside an allow-listed root (e.g. `app.getPath('home')` or `HERMES_HOME`).
  - Identifiers (`key`, `provider`, `profile`, `jobId`): match `^[A-Za-z0-9_-]{1,64}$`.
  - Ports: `Number.isInteger(port) && 1024 <= port <= 65535`.
  - URLs: `new URL(url)` plus scheme allow-list (`https:` only for `wsUrl`; `ws:`/`wss:` if applicable).
  Wrap validation in a small helper and invoke it at the top of each handler before any side effect.
- **References**:
  - Electron Security Checklist #16 -- Validate the Sender of All IPC Messages
  - OWASP -- Argument Injection
  - CWE-88 (Argument Injection); CWE-22 (Path Traversal); CWE-20 (Improper Input Validation)

---

### EH-006 -- `set-env` / `set-config` write renderer input to disk without sanitisation

- **Severity**: High
- **Category**: IPC / persistence
- **Location**: `src/main/index.ts:240-266`

```ts
  ipcMain.handle(
    "set-env",
    (_event, key: string, value: string, profile?: string) => {
      setEnvValue(key, value, profile);
      // Restart gateway so it picks up the new API key
      if (
        (isGatewayRunning() && key.endsWith("_API_KEY")) ||
        key.endsWith("_TOKEN") ||
        key === "HF_TOKEN"
      ) {
        restartGateway(profile);
      }
      return true;
    },
  );

  ipcMain.handle("get-config", (_event, key: string, profile?: string) =>
    getConfigValue(key, profile),
  );

  ipcMain.handle(
    "set-config",
    (_event, key: string, value: string, profile?: string) => {
      setConfigValue(key, value, profile);
      return true;
    },
  );
```

- **Description**: A renderer-controlled `key` and `value` are written into the user's profile `.env` and YAML config files. Neither is validated. For `.env`, an attacker who lands a single XSS in any future renderer view could inject newline-separated extra variables (e.g. set `NODE_OPTIONS=--require=/tmp/payload.js` if the gateway is later started in an environment that respects it; or set `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` on Linux/macOS). For YAML, an attacker could write keys/values that break the parser invariant or, if any future code path uses `yaml.load` (not `safeLoad`), that triggers gadget chains.
- **Impact**: Persistent local privilege amplification: malicious renderer content survives across restarts, can poison the gateway environment, and (because `restartGateway` is auto-invoked when the key ends in `_API_KEY`/`_TOKEN`) is applied immediately.
- **Remediation**: Validate `key` against `^[A-Z][A-Z0-9_]{0,63}$` for `.env` and `^[a-z][a-z0-9_.-]{0,63}$` for YAML config. Forbid `\n`, `\r`, and `\0` in `value`. Cap `value` length at e.g. 4 KB. Maintain an allow-list of writable keys if practical. Use a YAML serializer that escapes values rather than concatenating.
- **References**:
  - Electron Security Checklist #16 -- Validate IPC senders/payloads
  - CWE-78 (OS Command Injection -- env-var-mediated); CWE-20 (Improper Input Validation)

---

### EH-007 -- IPC handlers do not authenticate the sender frame

- **Severity**: Medium
- **Category**: IPC / sender validation
- **Location**: `src/main/index.ts:182-671` (every `ipcMain.handle`/`ipcMain.on`)

```ts
  ipcMain.handle("start-install", async (event) => {
    try {
      await runInstall((progress: InstallProgress) => {
        event.sender.send("install-progress", progress);
      }, mainWindow);
      ...
```

- **Description**: None of the ~60 IPC handlers verify `event.senderFrame` against the expected app origin. With `webviewTag: true` (EH-002), if a `<webview>` is ever attached, its renderer also gets the `hermesAPI` preload (because it inherits the same preload path unless explicitly overridden) -- meaning a compromised or attacker-loaded `<webview>` could call privileged channels like `start-install`, `claw3d-setup`, `run-claw-migrate`, `run-hermes-import`. Even without a `<webview>`, the Electron 28+ guidance is to defensively check `event.senderFrame.url` so that a future architectural change (adding a frame, opening a `BrowserView`, etc.) does not silently expand the privileged surface.
- **Impact**: Defence-in-depth gap. Becomes exploitable if EH-002 is leveraged or if a future feature adds frames.
- **Remediation**: Centralise an `assertTrustedSender(event)` helper that checks `event.senderFrame === mainWindow.webContents.mainFrame` (or matches the expected `file://`/dev URL) and call it at the top of every handler. Electron 28 introduced `event.senderFrame` precisely for this purpose.
- **References**:
  - Electron Security Checklist #16 -- Validate Sender of All IPC Messages
  - Electron docs -- `WebFrameMain` / `event.senderFrame`
  - CWE-346 (Origin Validation Error)

---

### EH-008 -- `installer.ts` shells out via `bash -c` with a constructed command string and runs `curl | bash` for install

- **Severity**: Medium
- **Category**: Command construction / supply chain (defence-in-depth)
- **Location**: `src/main/installer.ts:486-502`

```ts
      const installCmd = [
        shellProfile ? `source "${shellProfile}" 2>/dev/null;` : "",
        "curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash -s -- --skip-setup",
      ].join(" ");

      const basePath = getEnhancedPath();
      const proc = spawn("bash", ["-c", installCmd], {
        cwd: home,
        env: {
          ...process.env,
          PATH: askpass ? `${askpass.pathPrepend}:${basePath}` : basePath,
          ...
```

- **Description**: The install path concatenates a shell-profile path into a `bash -c` string and pipes a remote script directly into `bash`. `shellProfile` is derived from `homedir()` and a fixed list of profile filenames (`~/.zshrc`, `~/.bash_profile`, etc.) inside `getShellProfile`, so it is not directly user-controlled -- but the pattern of building shell strings is fragile and appears once more time as a synchronous shell call: `("which npm 2>/dev/null || where npm 2>/dev/null", ...)` (`src/main/claw3d.ts:276`). More importantly, the install path executes a remote shell script (`curl | bash`) over HTTPS without checksum or signature verification of the downloaded script -- so a CDN compromise, MITM via a misconfigured corporate proxy, or a GitHub-account compromise of `NousResearch/hermes-agent` results in arbitrary code execution on the user's host the next time they reinstall. This is a classic supply-chain risk.
- **Impact**: Trust-on-first-use weakness during install/repair; one-time RCE if the upstream script is tampered with.
- **Remediation**: (a) Replace the `bash -c` shell-string pattern with an array-based spawn only when sourcing the shell profile is unavoidable, or skip sourcing entirely (let the user surface their PATH via the Electron-toolkit utilities). (b) Pin a SHA-256 hash of the install script in the desktop binary, download it to a tempfile, verify the hash, then run it. (c) Replace the synchronous `which npm 2>/dev/null || where npm 2>/dev/null` shell call with platform-conditioned argv-array calls.
- **References**:
  - Electron Security Checklist (general) -- minimise shell usage
  - SLSA / supply-chain best practices for `curl | bash` patterns
  - CWE-494 (Download of Code Without Integrity Check); CWE-78 (OS Command Injection)

---

### EH-009 -- CSP allows `'unsafe-inline'` styles and lacks `connect-src`/`frame-ancestors`/`object-src`

- **Severity**: Medium
- **Category**: Content Security Policy
- **Location**: `src/renderer/index.html:6-9`

```html
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    />
```

- **Description**: The CSP is good in that it does NOT enable `'unsafe-inline'` or `'unsafe-eval'` for scripts, which is the primary defence the checklist mandates. However:
  1. `style-src 'unsafe-inline'` is broader than needed. Tailwind CSS in the build emits a static stylesheet -- inline-style allowance is required only for component-level `style="..."` attributes injected by React. Modern CSP allows `'unsafe-hashes'` plus per-attribute hashes, or a nonce-based approach, to keep this surface small.
  2. There is no explicit `connect-src` directive. With `default-src 'self'`, fetch/`WebSocket`/`EventSource` falls back to `'self'` -- but the renderer connects to the local Hermes gateway (an HTTP API on a localhost port -- see `src/main/hermes.ts:118`) and to Claw3D's WS URL (renderer-configurable, see `claw3dGetWsUrl`/`claw3dSetWsUrl`). When the renderer talks to a non-`'self'` origin (likely `http://127.0.0.1:<port>`), CSP will block it -- so either the policy is being inadvertently violated (and any WebSocket open call is blocked) or there is a runtime CSP relaxation elsewhere (none was found via `onHeadersReceived` -- see EH-010). This needs verification and explicit `connect-src` such as `connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*`.
  3. `object-src 'none'` and `base-uri 'self'` are not present. `base-uri` is the recommended hardening to prevent `<base href=...>` injection from rewriting all relative URLs.
  4. `frame-ancestors 'none'` is absent, so the page is embeddable in a remote frame if the navigation guard (EH-004) is also bypassed.
- **Impact**: Smaller-than-ideal defence-in-depth; the inline-style allowance is the highest-priority concern because it silently expands the XSS attack surface.
- **Remediation**: Tighten CSP to (rough draft, validate with build):
  ```
  default-src 'none';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self' data:;
  connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*;
  base-uri 'none';
  object-src 'none';
  frame-ancestors 'none';
  form-action 'none';
  ```
  Move enforcement to a `session.defaultSession.webRequest.onHeadersReceived` callback in the main process so it cannot be relaxed by a compromised renderer (see EH-010).
- **References**:
  - Electron Security Checklist #6 -- Define a Content Security Policy
  - MDN CSP -- `connect-src`, `base-uri`, `object-src`
  - CWE-1021 (Improper Restriction of Rendered UI Layers); CWE-79 (XSS)

---

### EH-010 -- CSP enforced only via `<meta>` tag; no main-process `onHeadersReceived` policy

- **Severity**: Medium
- **Category**: Content Security Policy / enforcement layer
- **Location**: `src/main/index.ts` (search for `onHeadersReceived` returns no match) and `src/renderer/index.html:6-9`

```ts
// no occurrence of onHeadersReceived anywhere in src/main/
```

- **Description**: The only CSP is the `<meta http-equiv="Content-Security-Policy">` tag in `src/renderer/index.html`. Electron documentation and the security checklist explicitly recommend setting CSP via the HTTP `Content-Security-Policy` header through `session.defaultSession.webRequest.onHeadersReceived(...)`, because: (a) a `<meta>` tag is parsed only after the document begins loading, so any `<script>` declared above it is not covered; (b) an injection attacker who can control any HTML before the `<meta>` tag (e.g. in a future bundled or fetched template) can elide it; (c) `<meta>` CSP cannot enforce `frame-ancestors` or `report-uri/report-to`. For a `file://`-loaded production build (line 178), the response header method is the only way to enforce CSP across all sub-resources.
- **Impact**: Defence-in-depth gap; CSP is more bypassable than necessary.
- **Remediation**: In the `app.whenReady()` block, register:
  ```ts
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"],
      },
    });
  });
  ```
  Then keep the `<meta>` tag as belt-and-braces.
- **References**:
  - Electron Security Checklist #6 -- Define and Enforce a Content Security Policy
  - Electron docs -- `session.webRequest.onHeadersReceived`
  - CWE-693 (Protection Mechanism Failure)

---

### EH-011 -- Hardened-runtime entitlements weaken codesigning protections

- **Severity**: Medium
- **Category**: Packaging / macOS code signing
- **Location**: `build/entitlements.mac.plist:1-15` and `build/entitlements.mac.inherit.plist:1-15`

```xml
  <dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
  </dict>
```

- **Description**: All four entitlements weaken macOS hardened-runtime protections:
  - `com.apple.security.cs.allow-jit` -- required by V8 (acceptable, but should be paired with `com.apple.security.cs.allow-unsigned-executable-memory: false`).
  - `com.apple.security.cs.allow-unsigned-executable-memory` -- broader than `allow-jit`; allows arbitrary `mprotect(PROT_EXEC)` of unsigned pages. Modern Electron builds typically do NOT need this.
  - `com.apple.security.cs.allow-dyld-environment-variables` -- re-enables `DYLD_INSERT_LIBRARIES` (the macOS equivalent of `LD_PRELOAD`). With EH-006 (`set-env` writing arbitrary env vars), an attacker who controls the .env file can inject arbitrary dylibs into the main process at next launch.
  - `com.apple.security.cs.disable-library-validation` -- disables Apple's signed-library check, allowing any unsigned dylib to load. With `afterPack.js` doing only an ad-hoc `codesign --sign -` (no Developer ID, no notarization), dylib substitution is trivial.
- **Impact**: Together with `notarize: false` (`electron-builder.yml:32`) and `mac.identity` not configured, the macOS build provides minimal tamper resistance. A local attacker (or installer for unrelated software) can swap dylibs into the `.app` bundle without invalidating its (ad-hoc) signature.
- **Remediation**: (a) Drop `allow-unsigned-executable-memory`, `allow-dyld-environment-variables`, and `disable-library-validation` unless a specific dependency requires them -- most Electron 39 apps do not. (b) Acquire an Apple Developer ID, set `mac.identity` and `mac.notarize: true` in `electron-builder.yml`. (c) Sign with proper entitlements only for the JIT helper, not the main app.
- **References**:
  - Apple -- Hardened Runtime exception entitlements
  - Electron docs -- macOS code-signing & notarization
  - CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

---

### EH-012 -- Auto-updater publishes via GitHub on an unsigned, unnotarized binary

- **Severity**: Medium
- **Category**: electron-updater / supply chain
- **Location**: `electron-builder.yml:32, 53-58` and `src/main/index.ts:792-841`

```yaml
  notarize: false
...
publish:
  provider: github
  owner: fathah
  repo: hermes-desktop
```

```ts
  const { autoUpdater } = require("electron-updater") as {
    autoUpdater: AppUpdater;
  };

  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on("update-available", (info) => { ... });
```

- **Description**: The feed itself is HTTPS (GitHub Releases), which is the minimum requirement. However:
  1. macOS notarization is disabled (`notarize: false`), and the build uses an ad-hoc signature (`codesign --sign -` in `build/afterPack.js`). electron-updater on macOS uses Apple's `LSPlist` mechanism that requires a valid Developer ID signature -- without it, the update will install but Gatekeeper will refuse to launch the new build on first run for users who downloaded the original from the web (quarantine bit set). For users who downloaded via "homebrew tap" or similar, ad-hoc signatures generally allow updates but provide zero tamper-resistance.
  2. There is no Windows Authenticode certificate configured (`win.certificateFile`/`win.certificateSubjectName` absent in `electron-builder.yml`). Without it, the update payload is unsigned on Windows. electron-updater verifies the SHA-512 from `latest.yml`, which is a partial mitigation, but `latest.yml` is fetched over HTTPS from GitHub and a GitHub-account compromise would issue a valid attacker-controlled `latest.yml`.
  3. `dev-app-update.yml:1-4` mirrors the same provider/repo with no public-key pinning. electron-updater supports `electronUpdaterCompatibility` but not native public-key pinning out of the box for GitHub releases.
- **Impact**: A GitHub-account compromise of `fathah/hermes-desktop` would let the attacker push a malicious release that auto-updates onto every user's machine. Without code signing (especially on Windows), there is no second-factor verification.
- **Remediation**: (a) Acquire a code-signing certificate (Apple Developer ID + notarization for macOS, Authenticode for Windows) and configure both in `electron-builder.yml`. (b) Set `notarize: true` and configure `mac.identity`. (c) Consider switching to a self-hosted feed where the SHA-512 is pinned and signed with a separate key. (d) Enforce 2FA on the GitHub publishing account.
- **References**:
  - electron-updater -- Code Signing requirement
  - Electron Security Checklist -- Auto-update over HTTPS with valid signature
  - CWE-494 (Download of Code Without Integrity Check); CWE-345 (Insufficient Verification of Data Authenticity)

---

### EH-013 -- `@electron/fuses` not used; runtime hardening fuses are unset

- **Severity**: Medium
- **Category**: Packaging / electron-fuses
- **Location**: `package.json:27-67` (no `@electron/fuses` dep; transitive only via `package-lock.json:639`); `electron-builder.yml` (no `electronFuses` block); no `forge.config` or fuses script

```json
"dependencies": {
  ...
  "electron-updater": "^6.3.9",
  ...
},
"devDependencies": {
  ...
  "electron": "^39.2.6",
  "electron-builder": "^26.0.12",
  ...
}
```

- **Description**: `@electron/fuses` is present only as a transitive dependency of `app-builder-lib` and is not invoked by the build. Electron-fuses are compile-time toggles burned into the final binary that defang the most common abuse vectors:
  - `RunAsNode` -- when off, removes `ELECTRON_RUN_AS_NODE` so the binary cannot be reused as a generic Node interpreter for arbitrary scripts.
  - `EnableNodeOptionsEnvironmentVariable` -- when off, ignores `NODE_OPTIONS=--require=...` etc.
  - `OnlyLoadAppFromAsar` -- when on, refuses to load app from any path other than the bundled `app.asar`.
  - `LoadBrowserProcessSpecificV8Snapshot` -- defence-in-depth.
  - `EnableEmbeddedAsarIntegrityValidation` -- verifies ASAR integrity headers at runtime.
  - `EnableCookieEncryption` -- encrypts the renderer's cookie store at rest.
  Combined with EH-006 (renderer can write env vars to the user's `.env`) and EH-011 (hardened-runtime exemptions), `RunAsNode` and `EnableNodeOptionsEnvironmentVariable` being unblown is a high-value attacker primitive: a benign-looking `.env` modification can re-execute arbitrary JS inside the trusted Hermes binary.
- **Impact**: Persistence and code-execution amplification. Even if every other layer holds, a single environment-variable injection in the user's profile elevates to RCE on next launch.
- **Remediation**: Add `@electron/fuses` as a direct devDep, write a small post-build script (or `afterPack` extension) that calls `flipFuses(...)` with `RunAsNode: false`, `EnableNodeOptionsEnvironmentVariable: false`, `EnableNodeCliInspectArguments: false`, `OnlyLoadAppFromAsar: true`, `EnableEmbeddedAsarIntegrityValidation: true`, `LoadBrowserProcessSpecificV8Snapshot: false`, `EnableCookieEncryption: true`. Verify with `npx electron-fuses read`.
- **References**:
  - electron/fuses repo -- README and recommended fuses
  - Electron Security Checklist -- Defence in depth
  - CWE-693 (Protection Mechanism Failure)

---

### EH-014 -- ASAR integrity not enforced

- **Severity**: Low
- **Category**: Packaging / ASAR
- **Location**: `electron-builder.yml:1-58` (no `asarIntegrity` or `electronUpdaterCompatibility` keys) -- ASAR is on by default in electron-builder 26, but integrity checking requires the fuse + post-build step

- **Description**: ASAR packaging is on by default (good), but without the `EnableEmbeddedAsarIntegrityValidation` fuse blown (see EH-013), and without `asarIntegrity` content provided, the binary will not refuse to load a tampered `app.asar`. macOS in particular uses `asarIntegrity` headers in the bundle's `Info.plist` to validate; if the entitlements (EH-011) allow library validation to be skipped, the trust chain is only as strong as the OS-level `codesign` check, which is ad-hoc here.
- **Impact**: Static tamper-resistance is weaker than the Electron defaults intend.
- **Remediation**: Combine the fuses-based fix from EH-013 with an electron-builder configuration that emits ASAR integrity hashes (see `asarIntegrity` in electron-builder docs). Test by mutating the packed `.asar` and verifying the binary refuses to launch.
- **References**:
  - Electron docs -- ASAR Integrity
  - CWE-353 (Missing Support for Integrity Check)

---

### EH-015 -- `chat-error` notification body shows untrusted gateway error string verbatim

- **Severity**: Low
- **Category**: Notification / output handling
- **Location**: `src/main/index.ts:375-385`

```ts
          onError: (error) => {
            currentChatAbort = null;
            event.sender.send("chat-error", error);
            rejectChat(new Error(error));
            // Notify on error too if window not focused
            if (mainWindow && !mainWindow.isFocused()) {
              new Notification({
                title: "Hermes Agent -- Error",
                body: error.slice(0, 100),
              }).show();
            }
          },
```

- **Description**: `error` is whatever the gateway emits -- potentially attacker-influenced text from a remote LLM provider or MCP server. It is sliced to 100 chars and displayed via the OS Notification API. The Notification API on macOS/Windows does not interpret HTML, so this is not XSS, but error content commonly includes unsanitised provider URLs or tokens; it can also be used for low-effort phishing ("Click here to renew your subscription: https://attacker"). Combined with the `mailto:`/scheme-permissive `shell.openExternal` (EH-003), a clickable notification body could be steered to dangerous targets on systems where notification clicks are routed via the app.
- **Impact**: Phishing surface; minor information disclosure if errors include credentials.
- **Remediation**: Replace `body: error.slice(0, 100)` with a static string (e.g. `"An error occurred. Open the app for details."`). Display the full error only inside the in-app UI where it is rendered as text by React.
- **References**:
  - OWASP -- Output Encoding & Phishing Defence
  - CWE-451 (User Interface Misrepresentation)

---

### EH-016 -- `console-message` dev hook left in production build

- **Severity**: Low
- **Category**: Logging / information disclosure
- **Location**: `src/main/index.ts:154-161`

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

- **Description**: All renderer warnings/errors flow into the main process's stdout/stderr. In a packaged build, that stream is typically captured to a log file (or to the system console on macOS). Renderer error messages can leak file paths, tokens captured by error stack traces, and user-input fragments. This is normal in dev but should be gated behind `is.dev`.
- **Impact**: Mild information disclosure into local log files; aids attacker reconnaissance.
- **Remediation**: Wrap the listener in `if (is.dev) { ... }` (the same pattern used at line 175 for the dev-server load) so that production builds do not capture renderer console output.
- **References**:
  - CWE-532 (Insertion of Sensitive Information into Log File)

---

### EH-017 -- Dev menu "reload" / "toggleDevTools" gated by `is.dev`, but `webPreferences.devTools` not explicitly disabled in prod

- **Severity**: Low
- **Category**: Hardening
- **Location**: `src/main/index.ts:735-741, 848-850`

```ts
        ...(is.dev
          ? [
              { type: "separator" as const },
              { role: "reload" as const },
              { role: "toggleDevTools" as const },
            ]
          : []),
```

```ts
  app.on("browser-window-created", (_, window) => {
    optimizer.watchWindowShortcuts(window);
  });
```

- **Description**: The visible menu correctly hides "Toggle Developer Tools" in production. However, `@electron-toolkit/utils`' `optimizer.watchWindowShortcuts(window)` keeps the **F12 / Ctrl+Shift+I** shortcuts wired in development but disables them in production by default. This is the intended defence -- but it is brittle: a future toolkit update could change the default, and there is no explicit `mainWindow.webContents.closeDevTools()` or `webPreferences.devTools: false` to belt-and-brace it. Setting `devTools: false` in `webPreferences` removes this entire surface for production builds.
- **Impact**: Defence-in-depth; minimal direct exploit value, but DevTools open in a malicious-link scenario allows arbitrary `eval` in the renderer.
- **Remediation**: Set `webPreferences.devTools: !app.isPackaged` (or simply `is.dev`). Continue to rely on `optimizer.watchWindowShortcuts` only as the secondary control.
- **References**:
  - Electron docs -- `BrowserWindow.webPreferences.devTools`
  - CWE-489 (Active Debug Code)

---

### EH-018 -- Info: `contextIsolation` is at default (true), `nodeIntegration` at default (false)

- **Severity**: Info
- **Category**: BrowserWindow defaults (positive observation)
- **Location**: `src/main/index.ts:135-139`

```ts
    webPreferences: {
      preload: join(__dirname, "../preload/index.js"),
      sandbox: false,
      webviewTag: true,
    },
```

- **Description**: Although the `webPreferences` block is sparse, the keys NOT mentioned inherit Electron 39 defaults, which are: `contextIsolation: true`, `nodeIntegration: false`, `nodeIntegrationInWorker: false`, `nodeIntegrationInSubFrames: false`, `webSecurity: true`, `allowRunningInsecureContent: false`, `experimentalFeatures: false`, `enableRemoteModule` removed in Electron 14. The preload itself uses `contextBridge.exposeInMainWorld(...)` and gates the call on `process.contextIsolated` (`src/preload/index.ts:637`), confirming context isolation is the intended posture. This is the correct default; document it explicitly in the source for clarity (e.g. add `contextIsolation: true` to the literal so a future dev does not accidentally remove it via a refactor).
- **Impact**: Positive -- but the defaults are implicit, and the call-out is to make them explicit.
- **Remediation**: Make the security-relevant defaults explicit in `webPreferences`:
  ```ts
  contextIsolation: true,
  nodeIntegration: false,
  webSecurity: true,
  allowRunningInsecureContent: false,
  ```
- **References**: Electron 39 changelog & default values.

---

### EH-019 -- Info: preload bridge does not leak Node primitives

- **Severity**: Info
- **Category**: Preload bridge surface (positive observation)
- **Location**: `src/preload/index.ts:1-650`

```ts
import { contextBridge, ipcRenderer } from "electron";
import { electronAPI } from "@electron-toolkit/preload";

const hermesAPI = {
  // ... 60+ methods, every one is a thin wrapper that does:
  //   ipcRenderer.invoke("<fixed-channel-string>", ...args)
  // or
  //   ipcRenderer.on("<fixed-channel-string>", handler) + return removeListener.
};

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld("electron", electronAPI);
    contextBridge.exposeInMainWorld("hermesAPI", hermesAPI);
  } ...
```

- **Description**: I read the entire 650-line preload. Every exposed method:
  - Calls `ipcRenderer.invoke` (or `ipcRenderer.on`) with a hard-coded channel string. No channel name is constructed from arguments. This is the correct pattern.
  - Does not expose `require`, `process`, `Buffer`, raw `fs`, or process-spawning primitives to the renderer.
  - Wraps event listeners to return a `removeListener` cleanup, avoiding leaks.
  The only potential concern is the `electronAPI` from `@electron-toolkit/preload`, which exposes a curated subset of Electron APIs to the renderer (e.g. `process.platform`, `process.versions`); review that subset out-of-band. Within this file, there is nothing to remediate.
- **Impact**: Positive observation; the bridge surface is appropriately narrow.
- **Remediation**: None.
- **References**: Electron Security Checklist #3 -- Use ContextBridge.

---

## Methodology

### Files reviewed (full read)

| Path                                                                       | Why                                  |
| -------------------------------------------------------------------------- | ------------------------------------ |
| `/Users/gorac/Desktop/hermes-desktop/src/main/index.ts` (879 lines)        | All `BrowserWindow`, IPC, navigation |
| `/Users/gorac/Desktop/hermes-desktop/src/preload/index.ts` (650 lines)     | Bridge surface                       |
| `/Users/gorac/Desktop/hermes-desktop/src/renderer/index.html`              | CSP `<meta>` tag                     |
| `/Users/gorac/Desktop/hermes-desktop/package.json`                         | Auto-updater dep, Electron version   |
| `/Users/gorac/Desktop/hermes-desktop/electron-builder.yml`                 | Packaging, ASAR, fuses, signing      |
| `/Users/gorac/Desktop/hermes-desktop/electron.vite.config.ts`              | Build-time CSP / nonce config        |
| `/Users/gorac/Desktop/hermes-desktop/dev-app-update.yml`                   | Auto-updater feed                    |
| `/Users/gorac/Desktop/hermes-desktop/build/entitlements.mac.plist`         | macOS hardened-runtime exceptions    |
| `/Users/gorac/Desktop/hermes-desktop/build/entitlements.mac.inherit.plist` | macOS hardened-runtime exceptions    |
| `/Users/gorac/Desktop/hermes-desktop/build/afterPack.js`                   | macOS post-pack ad-hoc codesign      |

### Files spot-checked (relevant excerpts)

| Path                                                                       | Reason                                          |
| -------------------------------------------------------------------------- | ----------------------------------------------- |
| `/Users/gorac/Desktop/hermes-desktop/src/main/installer.ts:486-630, 855-879` | Shell command paths, argv patterns, `readLogs` allow-list |
| `/Users/gorac/Desktop/hermes-desktop/src/main/skills.ts:120-296`             | Argv handling around bundled-skill operations  |
| `/Users/gorac/Desktop/hermes-desktop/src/main/cronjobs.ts:80-150`            | Argv handling around cron CLI                  |
| `/Users/gorac/Desktop/hermes-desktop/src/main/claw3d.ts:270-460`             | git/npm spawns, and the `which/where` shell call |
| `/Users/gorac/Desktop/hermes-desktop/src/main/config.ts:1-80`                | How `set-env`/`set-config` persist input        |

### Search patterns used

- Grep for `BrowserWindow(` in `src/main/index.ts`
- Grep for `webPreferences` in `src/main/index.ts`
- Grep for `ipcMain.handle` and `ipcMain.on` in `src/main/index.ts`
- Recursive grep for `onHeadersReceived`, `Content-Security-Policy`, `web-contents-created`, `will-navigate`, `will-redirect`, `will-attach-webview`, `setWindowOpenHandler` in `src/`
- Recursive grep for `asarIntegrity`, `@electron/fuses`, `RunAsNode`, `OnlyLoadAppFromAsar` excluding `node_modules`
- Grep for child-process imports in every `src/main/*.ts`
- Grep for `contextBridge`/`exposeInMainWorld` in `src/preload/index.ts`
- Grep for `require`, `process`, `Buffer`, `fs` leaks in `src/preload/index.ts`

### Out of scope

- **Runtime / dynamic analysis** -- This audit is read-only static analysis. The auditor's tool budget is `Read | Grep | Glob | Write`, so the app was not run, network traffic was not observed, and IPC payloads were not fuzzed.
- **Renderer code (`src/renderer/src/**`)** -- Per the task scope, only `src/renderer/index.html` was inspected. Findings about Markdown sanitisation, route-handler logic, or React component leakage of secrets are out of scope and would belong to a separate renderer/UX audit.
- **Third-party dependency vulnerabilities** -- No SCA was performed; only `package.json` was read for the Electron, electron-updater, and toolkit versions. SBOM-level review belongs to a supply-chain audit.
- **Cryptographic review of stored credentials** -- `set-env` / `setEnvValue` writes API keys to a `.env` file under `HERMES_HOME`. The on-disk encryption posture (e.g. macOS Keychain integration, OS-level disk encryption) is not assessed here.
- **Hermes Python gateway / `hermes.py`** -- The desktop's IPC handlers shell out to `hermes` Python CLIs. The CLI's own argument-handling is upstream and not in scope.
- **Network egress allow-listing** -- Beyond CSP `connect-src`, no network-layer policy (e.g. via `session.webRequest.onBeforeRequest` filters) is reviewed; the CSP recommendation in EH-009 covers the renderer side only.

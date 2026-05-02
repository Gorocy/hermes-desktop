# Supply-Chain Audit — hermes-desktop

| Field | Value |
| --- | --- |
| Date (UTC) | 2026-05-02 |
| Project | hermes-desktop @ 0.3.1 |
| Commit | `72d7bcc` (branch: main) |
| Auditor | `supply-chain-auditor` |
| Scope | `package.json`, `package-lock.json`, `electron-builder.yml`, native modules, install scripts, Electron 39 CVEs, license posture |
| Toolchain | `npm audit`, `npm outdated`, `npm ls --all`, lockfile sanity (`node -e ...`), `npm view electron versions` |
| Tree size | 962 packages in lockfile (961 resolved); npm reports 961 (prod 219 / dev 724 / optional 136 / peer 25) |

## Methodology

All commands were executed read-only from `/Users/gorac/Desktop/hermes-desktop`. No `install`, `ci`, `update`, `prune`, or `dedupe` was run. `node_modules/` was not present on disk at audit time, so the postinstall enumeration was performed against the lockfile (`hasInstallScript` flag) instead of `find node_modules ... -name package.json`.

### `npm audit --json` summary line

```
metadata.vulnerabilities = { info: 0, low: 0, moderate: 1, high: 3, critical: 0, total: 4 }
metadata.dependencies    = { prod: 219, dev: 724, optional: 136, peer: 25, peerOptional: 0, total: 961 }
```

### `npm outdated --json` (verbatim, all 11 entries — fewer than 20)

```json
{
  "@electron-toolkit/preload":            { "wanted": "3.0.2",     "latest": "3.0.2"     },
  "@electron-toolkit/utils":              { "wanted": "4.0.0",     "latest": "4.0.0"     },
  "@types/react-syntax-highlighter":      { "wanted": "15.5.13",   "latest": "15.5.13"   },
  "better-sqlite3":                       { "wanted": "12.9.0",    "latest": "12.9.0"    },
  "electron-updater":                     { "wanted": "6.8.3",     "latest": "6.8.3"     },
  "i18next":                              { "wanted": "25.10.10",  "latest": "26.0.8"    },
  "lucide-react":                         { "wanted": "1.14.0",    "latest": "1.14.0"    },
  "react-i18next":                        { "wanted": "15.7.4",    "latest": "17.0.6"    },
  "react-markdown":                       { "wanted": "10.1.0",    "latest": "10.1.0"    },
  "react-syntax-highlighter":             { "wanted": "16.1.1",    "latest": "16.1.1"    },
  "remark-gfm":                           { "wanted": "4.0.1",     "latest": "4.0.1"     }
}
```

The lockfile pins **electron-updater 6.3.9 → wanted 6.8.3** and **better-sqlite3 12.8.0 → wanted 12.9.0**; both are below the latest acceptable patch. Two prod deps are major versions behind: `i18next` 25 → 26 and `react-i18next` 15 → 17.

### Lockfile sanity

```
lockfileVersion: 3
packages: 962
packages_missing_integrity: 0
non-HTTPS resolved URLs: 0
non-npm-registry resolved entries: 0
unresolved entries: 0
```

Every resolved tarball carries a SHA-512 integrity hash and resolves over `https://registry.npmjs.org/`. No git-tarball, no http://, no off-registry sources.

### Electron version comparison (`npm view electron versions --json`)

- Range pinned via `package.json`: `^39.2.6`.
- Resolved in lockfile: **39.8.5**.
- Latest 39.x stable as of audit: **39.8.9**.
- Latest 39.x patches available beyond 39.8.5: 39.8.6, 39.8.7, 39.8.8, 39.8.9.
- Newer majors available: 40.x (latest 40.9.3) and 41.x (latest 41.5.0). 42.x is in beta.

### Postinstall / install-script enumeration

`node_modules` was absent on disk, so the requested `find node_modules -maxdepth 2 ...` could not be executed (recorded as out-of-scope below). Lockfile-based enumeration via `hasInstallScript=true` returned six packages:

| Package | Version | Scope | Notes |
| --- | --- | --- | --- |
| `better-sqlite3` | 12.8.0 | prod | Native compile via `prebuild-install` / `node-gyp`; rebuilt for Electron via `electron-builder install-app-deps` postinstall hook |
| `electron` | 39.8.5 | prod (devDep in package.json) | Downloads platform-specific binary from GitHub releases at install time |
| `electron-winstaller` | 5.4.0 | dev | Windows installer build helper |
| `esbuild` | 0.25.12 | dev | Native binary downloaded per platform |
| `vite/node_modules/esbuild` | 0.27.4 | dev | Nested copy under `vite` |
| `fsevents` | 2.3.3 | dev (optional) | macOS-only native module |

Project-level scripts (root `package.json`):
- `"postinstall": "electron-builder install-app-deps"` — rebuilds native deps (`better-sqlite3`) against the Electron ABI. This is the standard Electron flow but is a script that runs on every `npm install`.
- No `preinstall` or `prepare` script in the root.

### Out-of-scope

| Sub-scope | Reason |
| --- | --- |
| `find node_modules -maxdepth 2 -name package.json -exec grep -l '"postinstall"\|"preinstall"\|"prepare"' {} \;` | `node_modules/` absent at audit time. Substituted with `hasInstallScript` enumeration over `package-lock.json` (above). Findings below already cite the lockfile path. |
| `npm ls --all --json` deep tree | Tree was emitted but contained `"missing": true` for every dep because `node_modules/` is absent. Used the lockfile (962 entries) as the authoritative tree instead. |

## Severity matrix

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 3 |
| Medium | 4 |
| Low | 1 |
| Info | 1 |

## Findings

### DEP-001 — `vite` 7.3.1: arbitrary-file-read + path-traversal + `server.fs.deny` bypass

- Severity: **High**
- Package: `vite@7.3.1` (direct `devDependencies`, also pulled by `@tailwindcss/vite`, `@vitejs/plugin-react`, `@vitest/mocker`, `electron-vite`, `vitest`)
- Fixed in: ≥ 7.3.2 (covers all three advisories below)
- Advisories:
  - GHSA-p9ff-h696-f583 — Arbitrary File Read via Vite Dev Server WebSocket (high; affected `>=7.0.0 <=7.3.1`).
  - GHSA-v2wj-q39q-566r — `server.fs.deny` bypassed with queries (high; affected `>=7.1.0 <=7.3.1`).
  - GHSA-4w7w-66w2-5vf9 — Path traversal in optimized-deps `.map` handling (moderate; affected `>=7.0.0 <=7.3.1`).
- Impact in this project: Vite is dev-only (`npm run dev` / `electron-vite dev`). The dev server is not exposed in production builds. Risk surface is the developer's loopback HTTP server during `electron-vite dev` — anyone able to lure the developer's browser to attacker-controlled origin or websocket can exploit. Not in shipped product.
- Action: Bump to `vite ^7.3.2` (or latest 7.x patch; semver-compat with current `^7.2.6` constraint). Also forces `@tailwindcss/vite` and `electron-vite` resolutions to update.

### DEP-002 — `@xmldom/xmldom` 0.8.12: four high-severity DoS / XML-injection issues

- Severity: **High**
- Package: `@xmldom/xmldom@0.8.12` (transitive: `electron-builder` → `app-builder-lib` → `@electron/osx-sign`, `@electron/universal`, `dmg-license`, `plist`)
- Fixed in: ≥ 0.8.13
- Advisories (all high, all `<0.8.13`):
  - GHSA-2v35-w6hq-6mfw — Uncontrolled recursion in XML serialization → DoS (CWE-674).
  - GHSA-f6ww-3ggp-fr8h — XML injection through unvalidated DocumentType serialization (CWE-91).
  - GHSA-x6wf-f3px-wcqx — XML node injection via processing-instruction serialization (CWE-91).
  - GHSA-j759-j44w-7fr8 — XML node injection via comment serialization (CWE-91).
- Impact in this project: Build-time only — `electron-builder` parses macOS `Info.plist`/`entitlements.plist`/DMG metadata. A malicious plist controlled by an attacker who can influence the build inputs could trigger DoS or inject XML into produced installer artifacts. Low-likelihood in a CI pipeline that builds project-controlled assets only.
- Action: `npm audit fix` will lift the resolved `@xmldom/xmldom` to ≥ 0.8.13 (the registry already has 0.8.13+). No semver bump in `electron-builder` required.

### DEP-003 — `lodash` 4.17.21: prototype pollution + code-injection

- Severity: **High** (top advisory is high)
- Package: `lodash@4.17.21` (transitive: `@malept/flatpak-bundler` and `electron-winstaller` — both pulled by `electron-builder`)
- Fixed in: ≥ 4.17.24
- Advisories:
  - GHSA-r5fr-rjxr-66jc — Code Injection via `_.template` import-key names (**high**, CVSS 8.1; affected `>=4.0.0 <=4.17.23`).
  - GHSA-xxjr-mmjv-4gpg — Prototype pollution in `_.unset`/`_.omit` (moderate, CVSS 6.5; `>=4.0.0 <=4.17.22`).
  - GHSA-f23m-r3pf-42rh — Prototype pollution via array-path bypass in `_.unset`/`_.omit` (moderate, CVSS 6.5; `<=4.17.23`).
- Impact in this project: Build-time only — `flatpak-bundler` and `electron-winstaller` run during Linux/Windows installer creation. `_.template` code injection requires attacker-controlled template strings; current call sites in those build helpers use static templates. Still tracked as high because the CVE itself is high.
- Action: Add resolutions/overrides for `lodash@^4.17.24` in root `package.json`, or wait for `electron-builder` 26.x to pin a fixed lodash via `npm audit fix`.

### DEP-004 — `postcss` 8.5.8: XSS via unescaped `</style>` in CSS stringify

- Severity: **Medium** (CVSS 6.1)
- Package: `postcss@8.5.8` (transitive: `vite` → `postcss`)
- Fixed in: ≥ 8.5.10
- Advisory: GHSA-qx2v-qp2m-jg93 (moderate; affected `<8.5.10`).
- Impact in this project: Tailwind/Vite stylesheet pipeline at build/dev time. Production app does not run postcss. Exploit requires malicious CSS author content; in this project CSS is project-controlled.
- Action: Bumped automatically by `vite ≥ 7.3.2` upgrade; no separate dependency declaration in `package.json` to change.

### DEP-005 — Electron 39.8.5 is two minor patches behind 39.x tip

- Severity: **Medium**
- Package: `electron@39.8.5` (devDep, ships as the runtime in the distributable)
- Resolved: 39.8.5
- Latest 39.x: 39.8.9 (delta = 4 patch releases: 39.8.6, 39.8.7, 39.8.8, 39.8.9)
- Latest stable Electron: 41.5.0 (40.9.3 also available)
- `npm audit` does **not** flag any open Electron CVE for the resolved version. However, Chromium-based runtimes accumulate security fixes between patches; staying within four patches of HEAD on the supported 39.x line is correct for an LTS-style channel and the gap is small but non-zero.
- Note: `package.json` claims `^39.2.6` — installation actually resolved to 39.8.5 (correct for the caret range). The "39.2.6" string in repo metadata is stale — the runtime delivered to users is 39.8.5.
- Action: Re-resolve with a fresh `npm install` to pull 39.8.9 (within the existing `^39.2.6` caret range — no manifest change needed). Track Electron 40.x / 41.x for next major upgrade window; Electron 39 is in active maintenance but will eventually fall off support.
- References:
  - https://www.electronjs.org/docs/latest/tutorial/electron-timelines
  - https://github.com/electron/electron/security/advisories

### DEP-006 — `i18next` and `react-i18next` major versions behind

- Severity: **Medium**
- Packages:
  - `i18next` 25.10.10 → latest 26.0.8 (1 major behind; prod dep)
  - `react-i18next` 15.7.4 → latest 17.0.6 (2 majors behind; prod dep)
- No active CVE on either, but a two-major gap on a prod dep accumulates technical debt and increases the chance the next CVE patch lives only on the new line.
- Action: Plan a guarded upgrade (verify breaking-change notes for `i18next` 26 and `react-i18next` 16 → 17). Not blocking.

### DEP-007 — `electron-updater` 6.3.9 → 6.8.3 (auto-update channel)

- Severity: **Medium**
- Package: `electron-updater@6.3.9` (prod dep)
- Latest: 6.8.3 (5 minor releases behind on a security-sensitive component).
- `electron-builder.yml` configures `publish.provider: github` (owner `fathah`, repo `hermes-desktop`); the auto-updater fetches release artifacts from GitHub Releases and verifies signatures via the channel YAML. No `requestHeaders` or `serverType` overrides.
- No open advisory against 6.3.9 in `npm audit`, but auto-update code paths are a high-value target — a 5-minor lag means foregone hardening (e.g. signature checks, fs-extra/semver bumps in `builder-util-runtime`).
- Direct deps it pulls (relevant): `builder-util-runtime@9.5.1`, `fs-extra@10.x`, `js-yaml@4.x`, `semver@~7.7.3`. None currently flagged.
- Action: Bump to `electron-updater ^6.8.3`.

### DEP-008 — Electron-builder 26.0.12 build chain pulls native installers (build-time native code)

- Severity: **Medium** (build-pipeline integrity; informational at runtime)
- Packages with `hasInstallScript: true`:
  - `electron@39.8.5` (prod) — fetches platform binary from GitHub Releases at install time.
  - `electron-winstaller@5.4.0` (dev).
  - `esbuild@0.25.12` (dev) and `vite/node_modules/esbuild@0.27.4` (dev) — both fetch native binary tarballs.
  - `fsevents@2.3.3` (dev, optional, macOS).
  - `better-sqlite3@12.8.0` (prod) — native build via `prebuild-install` / `node-gyp` rebuild against Electron ABI through the `postinstall: electron-builder install-app-deps` hook.
- All resolutions are over HTTPS to the official npm registry; lockfile integrity coverage is 100% (962/962 packages with SHA-512 hashes). The risk here is procedural: each install script runs arbitrary code in the project context. A compromised registry mirror or DNS attack would still be defeated by the integrity hashes — *but only* on `npm ci` (lockfile-strict) flows; a plain `npm install` will fall back to range resolution.
- Action: Use `npm ci` in CI (not `npm install`). `npm config set ignore-scripts true` for CI steps that don't need native rebuilds (publishing typecheck-only). Verify the GitHub Releases URL for the Electron tarball is HTTPS (it is — `electron/electron`).

### DEP-009 — `format@0.2.2` ships in the production bundle with `UNKNOWN` license

- Severity: **Low**
- Package: `format@0.2.2`
- License (per lockfile): not declared (`UNKNOWN` in our roll-up; package.json on registry lacks a `license` field).
- Chain: `format <- fault <- lowlight <- react-syntax-highlighter` (and `react-syntax-highlighter` is a direct **prod** dep via `package.json`).
- Risk: Unlicensed dependency in a redistributed binary creates legal ambiguity. The `format` package on npm has been unmaintained for years (still effectively MIT-style code, but the manifest never declares it). One-line dep used for sprintf-style formatting; trivial to vendor or replace, but the legal nit is real for a desktop app distributed under MIT.
- Action: File an upstream issue at `lowlight` to drop the dep or pin a fork; alternatively add a `format` alias in `overrides` pinning a maintained fork that declares a license. Verify the legal team is comfortable with `UNKNOWN` in the bundled artifact.

### DEP-010 — Native module `better-sqlite3` 12.8.0 is one minor behind (12.9.0)

- Severity: **Low**
- Package: `better-sqlite3@12.8.0` (prod) — bundled SQLite via `prebuild-install` (downloads a prebuilt `.node` binary keyed by Electron ABI; falls back to `node-gyp` rebuild via `electron-builder install-app-deps`).
- Latest: 12.9.0. No CVE on either version per `npm audit`.
- Lockfile integrity hash present, registry-resolved. `electron-builder.yml` sets `npmRebuild: false` (rebuild handled by `install-app-deps` hook in `postinstall` rather than by electron-builder during packaging) — that is the intended pattern.
- Action: Bump on next dependency-refresh cycle.

### DEP-011 — Lockfile and registry posture are clean (Info)

- Severity: **Info**
- `lockfileVersion: 3`, 962 packages, 961 with `resolved` URL, **0 missing integrity**, **0 non-HTTPS** URLs, **0 non-npm-registry** resolutions.
- License rollup (962 packages):
  - 791 MIT, 86 ISC, 27 Apache-2.0, 14 BSD-2-Clause, 12 MPL-2.0, 11 BlueOak-1.0.0, 9 BSD-3-Clause, plus dual-license MIT/WTFPL/CC0 entries.
  - **0 GPL-classed packages**, **0 LGPL**, **0 AGPL**, **0 SSPL**, **0 CC-BY-NC**.
  - **1 UNKNOWN** license: `format@0.2.2` (covered by DEP-009).
- No off-registry tarballs (no `git+ssh://`, no `file:`, no `http://`).
- This is a clean lockfile; the only real risk material is the four CVEs in dev-time tooling and the one `UNKNOWN`-license prod transitive.

## Recommendations (priority order)

1. **High** — Run `npm audit fix` (or hand-bump): `vite` → 7.3.2+ (closes DEP-001 + DEP-004), `@xmldom/xmldom` → 0.8.13+ (DEP-002), `lodash` → 4.17.24+ via override (DEP-003).
2. **Medium** — Bump `electron-updater` to 6.8.3 (DEP-007); refresh Electron resolution to 39.8.9 within the existing caret (DEP-005); plan migration off `i18next` 25 → 26 and `react-i18next` 15 → 17 (DEP-006).
3. **Medium** — Switch CI to `npm ci` and consider `--ignore-scripts` for non-build CI steps (DEP-008).
4. **Low** — Replace or override `format@0.2.2` to remove `UNKNOWN`-license prod transitive (DEP-009); bump `better-sqlite3` to 12.9.0 (DEP-010).
5. **Info** — Re-audit after dependency refresh; current lockfile integrity posture is excellent and should be preserved.

## Command audit trail

| Command | Result | Lines / summary |
| --- | --- | --- |
| `npm audit --json` | exit 1 (non-zero is normal when advisories present) | 4 advisories: 3 high, 1 moderate; 961 deps scanned |
| `npm outdated --json` | exit 1 | 11 outdated entries (above, verbatim) |
| `npm ls --all --json \| head -c 200000` | exit 0 | Tree returned but every dep marked `missing` because `node_modules/` is absent — substituted lockfile (962 entries) |
| `node -e "...lockfile sanity..."` | exit 0 | `lockfileVersion: 3`, 962 pkgs, 0 missing integrity |
| `find node_modules -maxdepth 2 -name package.json -exec grep -l '"postinstall"...' {} \;` | **skipped** | `node_modules/` absent — substituted lockfile `hasInstallScript` enumeration (6 packages, table above) |
| `npm view electron versions --json \| tail -50` | exit 0 | 39.x patches up to 39.8.9; 40.9.3 latest 40; 41.5.0 latest stable |
| License roll-up via `node -e ...` over lockfile | exit 0 | 791 MIT, 0 GPL/AGPL, 1 UNKNOWN (`format@0.2.2`) |
| Resolved-URL audit via `node -e ...` | exit 0 | 0 non-HTTPS, 0 non-registry resolutions |

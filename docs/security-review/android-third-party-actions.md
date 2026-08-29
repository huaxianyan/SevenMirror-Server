# Android third-party GitHub Action review

Status: **internal readiness review; not an independent security approval**

Reviewed: 2026-08-29

## Scope and method

This review covers the two non-`actions/*` Actions used by the Android CI
baseline before this review:

| Action | Pinned commit | Upstream tag | GitHub commit verification |
| --- | --- | --- | --- |
| `android-actions/setup-android` | `40fd30fb8d7440372e1316f5d1809ec01dcd3699` | `v4.0.1` | unsigned |
| `reactivecircus/android-emulator-runner` | `a421e43855164a8197daf9d8d40fe71c6996bb0d` | `v2.38.0` | unsigned |

The review cloned each repository, checked out the exact commit, inspected the
Action metadata, TypeScript source, committed JavaScript, production dependency
lock, network and command-execution calls, and rebuilt the executable JavaScript
with the locked dependencies. It also ran `npm audit --omit=dev` against the
public npm advisory service. An unsigned commit is not treated as provenance;
the exact pin only prevents a mutable tag from silently changing the selected
tree.

## `android-actions/setup-android`

The Action downloads Google Android command-line tools when the requested
version is absent, accepts SDK licenses, installs caller-selected SDK packages,
exports `ANDROID_HOME` and `ANDROID_SDK_ROOT`, and extends `PATH`. Its source does
not deliberately read GitHub tokens or repository secrets. The executable
`dist/index.js` rebuilt to the exact tracked Git blob from the pinned source and
lockfile.

The locked production graph contains `undici 6.24.1`. The 2026-08-29
`npm audit --omit=dev` result reports one High aggregate finding, including
`GHSA-vxpw-j846-p89q`; fixed versions are available. SevenMirror did not need
this Action because the GitHub-hosted Ubuntu image already exposes the Android
SDK used by Gradle, while the emulator job independently prepares its required
SDK packages.

**Disposition:** remove the Action instead of accepting or suppressing the
finding. Android CI must prove both the normal build and API 29 instrumentation
without it. A future reintroduction requires a new exact-commit review and a
clean applicable production-dependency assessment.

## `reactivecircus/android-emulator-runner`

### Executed behavior

At the pinned commit, the Action:

- runs with Node.js 24 from committed `lib/*.js` and production
  `node_modules/`;
- downloads Android command-line tools from fixed `dl.google.com` URLs only when
  they are absent;
- invokes `sdkmanager` to install licenses, build tools, platform tools, the
  emulator, the selected platform and system image;
- creates and starts an AVD, waits for boot, runs the caller-provided script,
  and terminates the emulator;
- optionally supports direct emulator ZIP, NDK and CMake installation, but the
  SevenMirror workflow does not enable those inputs;
- does not deliberately read or transmit `GITHUB_TOKEN`, OIDC variables,
  signing secrets, or notification data.

The Action constructs several shell commands from inputs. SevenMirror supplies
fixed literals for API level, architecture, target, profile and test script; it
does not interpolate issue text, branch names, commit messages, workflow
payloads, or other attacker-controlled metadata. Executing repository Gradle
code is intentional for an instrumentation-test job and does not grant that job
release-signing secrets.

The pinned TypeScript build reproduced all six tracked `lib/*.js` Git blobs
exactly. The lockfile includes registry integrity hashes. The executable tree is
still larger than a bundled Action because it commits production
`node_modules/`; exact rebuild evidence reduces, but does not remove, the need
to review dependency updates.

### Vulnerability applicability

The 2026-08-29 `npm audit --omit=dev` result reports three Moderate dependency
records rooted in `uuid` through `@actions/core 1.10.0` and
`@actions/tool-cache 2.0.1` (`GHSA-w5hq-g745-h8pq`). The advisory concerns the
v3/v5/v6 APIs when a caller supplies an output buffer with unsafe bounds.

The reviewed execution paths call UUID v4 without an output buffer to create a
file-command delimiter or temporary download path. SevenMirror does not supply
UUID arguments. The vulnerable condition is therefore not reachable in the
reviewed use, but the outdated dependency remains a supply-chain maintenance
risk and must stay visible.

**Temporary usage decision:** retain the exact commit for API 29 instrumentation
with `contents: read` as the job's only repository permission. This is internal
applicability evidence, not an independent `ACCEPTED RISK` decision. Recheck by
2026-09-29, before selecting a release baseline, or immediately when upstream
publishes a compatible dependency update, whichever comes first.

### Residual risks

- The selected upstream commit is unsigned and has no GitHub-verified signature.
- Android SDK and system-image bytes are obtained at CI runtime. This Action
  does not independently pin their content digest; Android repository metadata
  and the hosted runner boundary remain trusted.
- Fixed inputs are safe only while the workflow keeps them independent of
  untrusted event data.
- A compromised GitHub-hosted runner, Google Android package source, Action
  repository before commit selection, or npm dependency before lock selection
  remains outside what an exact commit pin alone can prevent.

## SevenMirror verification evidence

Android commit `a96fa6002a1d6c65c2e19589fa3c74feb585d0da` removes
`setup-android` and limits the API 29 job to `contents: read`; the build job keeps
only `actions: read` and `contents: read`. GitHub Actions run `33234738489`
completed successfully with all four jobs green: normal build and inventory
verification, blocking release-runtime OSV scan, complete supply-chain audit,
and API 29 secure-runtime instrumentation. This proves the selected hosted
runner baseline does not require the removed setup Action.

## Update policy

For every retained third-party Action:

1. keep a full 40-character commit pin and preserve the CI pin check;
2. inspect the exact source-to-executable diff and upstream commit verification;
3. rebuild committed JavaScript from the lockfile and require no unexplained
   executable diff;
4. run a production-dependency vulnerability scan and record applicability for
   every finding;
5. review network destinations, command construction, environment and secret
   access, file writes, and required GitHub permissions;
6. run the complete Android CI before merging the new pin;
7. review monthly and again before every release baseline, even if Dependabot or
   upstream has not proposed an update.

High or Critical applicable production-dependency findings block use. Moderate
findings require documented reachability, an owner, and a review deadline;
they may not be hidden with a broad advisory ignore.

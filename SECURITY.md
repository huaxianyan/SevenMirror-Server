# Security policy

## Current support status

SevenMirror has no production release or stable compatibility line. The current
`0.1.x-dev` code and protocol are provisional and may change before the first
reviewed release.

| Version or artifact | Security reports | Production support |
| --- | --- | --- |
| Current unreleased development code | Accepted | No |
| Older commits, local test builds, and experimental artifacts | Accepted when still relevant to current code | No |

A report being accepted does not mean the affected build is supported for
production use. Real third-party notification transport remains disabled until
the documented release gates and independent security review are complete.
When a supported release exists, this table will name its exact maintained
version range and security-update window.

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected
vulnerability. Use GitHub Private Vulnerability Reporting in the affected
repository:

- [Server private report](https://github.com/huaxianyan/SevenMirror-Server/security/advisories/new)
- [Android private report](https://github.com/huaxianyan/SevenMirror-Android/security/advisories/new)
- [Chrome Extension private report](https://github.com/huaxianyan/SevenMirror-Extension/security/advisories/new)

If the affected component is unclear or the issue crosses repositories, use the
Server private-report link and identify every component you tested. These
private reports are the canonical confidential contact; project members will
not ask you to move secrets or exploit details into a public channel.

Include as much of the following as is safely available:

- affected repository, exact commit, build, platform, and deployment topology;
- vulnerability class and realistic impact;
- minimal reproduction steps or a proof of concept using synthetic data;
- whether authentication, local access, user interaction, or a compromised
  endpoint is required;
- relevant redacted logs, stack traces, or packet structure;
- any known active exploitation or disclosure deadline;
- how you would like to be credited.

Do not send private keys, signing keystores, live transport credentials,
pairing or rotation codes, real notification content, or full private device
identifiers. Revoke an exposed live credential first, then provide a sanitized
reproduction and describe the exposure through the private report.

## Response targets

The project aims to:

- acknowledge a private report within 3 business days;
- provide an initial severity and applicability assessment within 7 calendar
  days;
- provide a status update at least every 14 calendar days while remediation is
  active;
- coordinate a disclosure date after a fix and affected release path are known.

These are response targets, not a service-level agreement. Complex protocol,
cryptographic, multi-device, or upstream dependency findings may require more
time. The report will remain open with a stated next step rather than being
silently treated as resolved.

## Disclosure and remediation

Please allow a reasonable remediation window before public disclosure, unless
users face active exploitation or another urgent safety need. The project will
coordinate scope, severity, credit, advisory text, remediation commits, and a
public disclosure date with the reporter when practical.

A security fix is complete only when it identifies the affected boundary,
includes reproducible verification, and is available through the relevant
repository or release channel. A GitHub Security Advisory and CVE will be used
when warranted. Dependency findings are not suppressed solely because the
vulnerable code is transitive; applicability and accepted residual risk must be
documented. The canonical cross-repository exception, owner, approver, expiry and
scan-time evidence rules are in
[`docs/vulnerability-management.md`](docs/vulnerability-management.md).

Reports may be closed as not applicable when the behavior is outside the stated
threat model or supported deployment, but the explanation must identify the
failed security claim or boundary. Self-hosting or end-to-end encryption alone
is not a disposition.

## Research boundaries

Good-faith testing should use systems, workspaces, devices, browser profiles,
and notification data that you own or are explicitly authorized to test. Do
not access another person's data, degrade shared services, perform destructive
or persistent actions, publish working exploit details before coordination, or
use real third-party notification content where a synthetic reproduction is
sufficient.

The project does not authorize testing against infrastructure or accounts owned
by GitHub, Google, browser vendors, mobile carriers, cloud providers, or other
third parties. Follow their policies separately.

## Security updates and trust

There are currently no production release artifacts. Source commits, local test
APKs, unpacked extensions, and CI artifacts are development evidence, not a
stable update channel or a production-support promise.

For a future supported release:

- the advisory will identify exact affected and fixed versions or commits;
- Server, Android, Chrome, protocol, and cryptographic changes will be
  coordinated when a fix crosses repository boundaries;
- protocol or cryptographic changes will update canonical specifications and
  interoperability vectors before release;
- release artifacts must use the documented signing identity and provenance
  process;
- rollback or key-transition instructions will be explicit when an old artifact
  can no longer be trusted.

Do not trust keys, binaries, APKs, extension packages, checksums, or update
instructions sent only through unsolicited direct messages. Verify security
updates against the repositories and release channels named in the published
advisory.

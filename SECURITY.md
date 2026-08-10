# Security Policy

Security is a core property of microtun. The project implements WireGuard-compatible protocol machinery and handles cryptographic key material, authenticated peer state, replay protection, routing, relaying, and tunnel access control across both host and embedded targets.

If you believe you have found a security vulnerability, please report it privately so it can be investigated and fixed before public disclosure.

## Supported versions

microtun is currently pre-1.0 and under active development.

| Version | Security support |
| --- | --- |
| Current development branch | Yes |
| Latest published release | Yes, where practical |
| Older releases or snapshots | No |

Security fixes may require upgrading to the latest release or development revision. If you are unsure whether a version is affected, include the exact version, commit, or `Cargo.lock` revision in your report.

## Reporting a vulnerability

**Do not open a public issue, discussion, pull request, or other public report for an undisclosed vulnerability.**

Send reports to **`owner@microtun.dev`** with a subject such as:

```text
[SECURITY] Brief description of the issue
```

Please include as much of the following as is reasonably available:

- the affected crate, component, version, or commit;
- the target/runtime involved, such as Linux, `microtun-std`, Embassy, or a specific embedded target;
- a description of the vulnerability and its security impact;
- the prerequisites and attacker capabilities required to exploit it;
- clear reproduction steps or a minimal proof of concept;
- relevant logs, packet traces, or stack traces, with secrets removed;
- whether the issue appears remotely exploitable or can cause key disclosure, authentication bypass, plaintext exposure, denial of service, or persistent compromise;
- for protocol or cryptographic issues, the expected behavior and any relevant WireGuard specification/reference behavior;
- any proposed mitigation or patch, if you have one.

Do **not** send real production private keys, credentials, peer registries, or other secrets. Use generated test material and redact unrelated data.

If ordinary email is not appropriate for the sensitivity of the report, contact `owner@microtun.dev` first with only enough information to establish a safer communication method.

## What we consider security-sensitive

Examples include, but are not limited to:

- cryptographic implementation errors or misuse of cryptographic primitives;
- private-key, session-key, cookie-secret, or other sensitive-state disclosure;
- nonce, counter, replay-window, rekey, or session-lifecycle flaws;
- authentication or peer-identity bypasses;
- acceptance of unauthenticated or incorrectly attributed traffic;
- routing, AllowedIPs, firewall, or peer-resolution behavior that lets one peer access traffic or state belonging to another;
- relay behavior that breaks the intended end-to-end confidentiality or integrity of inner WireGuard traffic;
- Peers API admission, authorization, framing, or state-consistency flaws with security impact;
- parsing or state-machine bugs reachable from untrusted network input that cause memory unsafety, persistent corruption, or exploitable panics;
- remotely triggerable resource exhaustion or denial of service that bypasses intended bounds or rate limits;
- leakage of plaintext packets, keys, credentials, or sensitive configuration through logs or error paths;
- privilege-boundary problems in the Linux daemon, including unsafe handling around TUN setup or required capabilities;
- security-relevant differences between allocator-backed and allocation-free builds;
- dependency vulnerabilities that are actually exploitable through microtun.

A protocol interoperability bug, ordinary crash caused only by invalid local configuration, documented capacity limit, or dependency advisory with no reachable impact in microtun is not automatically a security vulnerability. We still welcome ordinary bug reports for those cases through the project's normal contribution channels.

## Testing guidelines

Please test only against systems, devices, keys, and networks that you own or are explicitly authorized to test.

When investigating a suspected vulnerability:

- prefer local test networks, generated keys, and isolated devices;
- minimize collection or retention of other users' data;
- avoid destructive testing against production systems;
- do not intentionally degrade third-party networks or services;
- stop testing if you obtain unintended access to real secrets or unrelated data, and report what occurred without exploring further;
- avoid publishing exploit details until a fix or mitigation has been coordinated.

The example firmware and configuration files are intended for development and demonstration. Publicly documented placeholder/example keys or intentionally exposed demo services are not vulnerabilities unless they lead to an unintended security impact outside the documented example behavior.

## Response and disclosure process

We aim to acknowledge a complete security report within **7 days** and provide an initial assessment within **14 days**. These are targets, not guaranteed service-level commitments.

After confirming an issue, we will work with the reporter to:

1. determine affected versions and realistic impact;
2. develop and test a fix or mitigation;
3. decide whether coordinated release notes, an advisory, or a CVE are appropriate; and
4. agree on a reasonable public-disclosure date.

Please allow time for affected users to obtain a fix before publishing technical details that would materially enable exploitation. If an issue is already being actively exploited or has otherwise become public, the disclosure timeline may be shortened so users can protect themselves quickly.

Security reports will be shared only with people needed to investigate and remediate the issue, subject to practical and legal requirements.

## Security updates

Security fixes will be published through the project's normal source and release channels. Reports affecting an upstream dependency may also be coordinated with the relevant upstream maintainers.

When a fix is available, users should upgrade promptly and rotate any private keys, credentials, or other secrets that may have been exposed by the vulnerability.

Thank you for helping keep microtun and its users secure.

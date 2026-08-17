# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.16.x   | Yes       |
| < 0.16   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them privately using one of the following methods:

### 1. GitHub Private Vulnerability Reporting (preferred)

Use GitHub's built-in private reporting:

**[Report a vulnerability](https://github.com/I4cTime/q-ring/security/advisories/new)**

### 2. Email

Send details to the maintainer directly. You can find contact information on the [@I4cTime GitHub profile](https://github.com/I4cTime).

## What to Include

When reporting, please provide:

- **Description** of the vulnerability and its potential impact.
- **Steps to reproduce** or a proof of concept.
- **Affected version(s)** of q-ring.
- **Environment** details (OS, Node.js version, keyring backend).
- **Suggested fix**, if you have one.

## Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix or mitigation | Varies by severity |
| Public disclosure | After a fix is released |

## Scope

The following areas are in scope for security reports:

- **Secret storage and retrieval** — any bypass of OS keyring isolation.
- **Tunneling** — leaks of ephemeral in-memory secrets to disk or logs.
- **Teleportation** — weaknesses in the encrypted sharing protocol.
- **Entanglement** — unintended exposure during linked secret rotation.
- **MCP server** — unauthorized access to secrets via the MCP transport, including bypasses of the approval gate, governance policy, or per-key restrictions.
- **Governance & approvals** — escaping `.q-ring.json` policy, forging/bypassing approval tokens, or reading protected secrets via bulk operations (`export_secrets`, `teleport_pack`).
- **Outbound requests** — SSRF via hook/validation URLs (including DNS-rebinding) to private/loopback ranges.
- **Status dashboard** — unauthorized access to the local dashboard, its `/api/status` snapshot, or SSE stream.
- **CLI** — command injection, argument parsing flaws, or privilege escalation.

## Out of Scope

- Vulnerabilities in upstream dependencies (report those to the respective project).
- Issues requiring physical access to an already-unlocked machine.
- Social engineering attacks.

The full picture of what q-ring defends against — trust boundaries,
attackers considered, and known residual risks — is documented in
[docs/threat-model.md](docs/threat-model.md). Anything listed there as a
mitigation is in scope if you can bypass it.

## Recognition

We're happy to credit security researchers in the release notes and CHANGELOG unless you prefer to remain anonymous. Let us know your preference when reporting.

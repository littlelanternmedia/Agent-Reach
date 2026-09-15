---
name: potato-security-gate
description: Defensive repository adoption gate combining a deterministic honeypot/supply-chain preflight with Cloudflare's pinned security-audit skill. Use before cloning, forking, installing, executing, or adopting unfamiliar repositories, and for re-checking already adopted repos.
---
# Potato Security Gate

## Mandatory order
1. **DISCOVER — source identity only.** Record canonical repository, owner, license, source ref, age/activity, maintainers/contributors, releases/issues/PRs, security policy/advisories when available.
2. **🍯 PRE-FLIGHT — no target execution.** Run `bin/potato-audit <target>`. This stage is read-only and must not install dependencies or access real credentials.
3. **STOP gate.** RED blocks installs/builds/execution. YELLOW requires isolation and explicit review. GREEN permits the Cloudflare stage but is not an adoption verdict.
4. **🔐 CLOUDFLARE STAGE.** Use `cloudflare/security-audit-skill` pinned to commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`. Default profile: QUICK for green preflight on low-stakes/small repos; STANDARD for yellow/security-sensitive repos; DEEP for credential/session/wallet/browser/MCP/agent/release tooling or high-stakes targets.
5. **Independent validation.** A hunter must never validate its own candidate. Preserve Cloudflare's confirmed / needs_validation / rejected distinction.
6. **FINAL POTATO VERDICT.** Merge both layers:
   - 🟢 ADOPT / TEST: no unresolved high-risk preflight finding; no confirmed high/critical boundary failure; target can be run inside the Potato sandbox.
   - 🟡 QUARANTINE / ISOLATE: unresolved trust questions, needs_validation findings, sensitive capability, or material medium findings requiring mitigation.
   - 🔴 REJECT: malicious/suspicious behavior, secret theft/exfiltration, destructive host behavior, or confirmed severe vulnerability that makes experimentation unjustifiable.

## Non-negotiable execution envelope
- Empty/sanitized environment; never inherit real API keys, OAuth tokens, browser sessions, cookies, wallets, SSH keys, cloud credentials, or ChatGPT credentials.
- No external network for target-controlled code unless a specific test requires loopback only.
- Read-only target/toolchain; scratch-only writes.
- CPU/memory/process/file/disk/time limits.
- No dependency installation during the audit. If dependencies are absent, record the dynamic check as blocked/needs_validation.
- Never probe live endpoints, production accounts, or other users' data.

## Cloudflare pin policy
Read `config/cloudflare-pin.json`. Never track `main` implicitly. Upgrades are separate security changes: inspect the upstream diff, run the Potato preflight on the upstream revision, then deliberately update the pin.

## Report contract
Always return: canonical repo + reviewed ref; preflight verdict/findings; Cloudflare profile/status; confirmed/needs_validation summary; final 🟢/🟡/🔴 verdict; sandbox restrictions; exact blockers/mitigations; whether coverage is partial.

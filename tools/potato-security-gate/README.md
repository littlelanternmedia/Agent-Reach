# 🥔 Potato Security Gate

A defensive repo-adoption gate that combines:

1. **Potato 🍯 Preflight** — deterministic, read-only honeypot/supply-chain checks before target code is allowed to execute.
2. **Cloudflare Security Audit** — pinned agent workflow for reconnaissance, coverage-led vulnerability hunting, independent candidate validation, structured findings, independent record verification, and reporting.

## One command for stage 1

```sh
./bin/potato-audit /path/to/repo
```

Exit codes: `0` green, `1` yellow/review, `2` red/reject. A JSON result is written to `potato-preflight.json` unless `POTATO_AUDIT_OUT` is set.

**Important:** the Cloudflare component is an agent skill, not a scanner binary. Stage 1 decides whether the target is allowed to proceed. Stage 2 must be run by a coding agent that supports tool use/sub-agents and the required sandbox. The upstream source is deliberately pinned in `config/cloudflare-pin.json` rather than silently tracking `main`.

## Final verdicts

- 🟢 **ADOPT / TEST** — acceptable for isolated Potato testing.
- 🟡 **QUARANTINE / ISOLATE** — genuine-looking or useful, but sensitive/unresolved.
- 🔴 **REJECT** — suspicious, malicious, destructive, or unjustifiably risky.

## Safety properties

The preflight does not execute repository code, install dependencies, or use network access. It bounds file scanning, ignores dependency/build caches, disables Git hooks for metadata reads, and treats secret/session/wallet access as high-risk.

The Cloudflare stage retains its stricter execution contract: external network off for target-controlled code, sanitized allowlisted environment, read-only target/toolchain, scratch-only writes, resource limits, dummy identities/secrets, no live systems, and independent verifiers.

## Upstream

Cloudflare Security Audit Skill: `cloudflare/security-audit-skill` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (MIT). See `config/cloudflare-pin.json`.

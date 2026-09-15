# 🥔 Potato Customs — Repository Security Gate

Security comes before convenience. This repository must pass this gate before new upstream code or dependencies are trusted.

## Mandatory rules

1. **Provenance first** — record the real upstream repository, license, and the exact commit being adopted.
2. **No moving dependency refs** — reject `#main`, `#master`, `latest`, unpinned Git branches, or equivalent moving refs. Pin Git dependencies to immutable commit SHAs and prefer lockfiles/checksums.
3. **Inspect before install** — review package manifests, lockfiles, lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`), shell scripts, GitHub Actions, Dockerfiles, and downloaded binaries before executing them.
4. **No blind remote execution** — never use `curl | sh`, `wget | bash`, remote `eval`, or equivalent patterns without first retrieving and auditing the exact artifact.
5. **Secrets stay out** — do not commit API keys, cookies, session tokens, OAuth codes, private keys, `.env` secrets, browser profiles, or credential-bearing logs.
6. **Credential boundaries are privileged** — code that reads browser cookies, keychains, SSH config, cloud credentials, wallets, or authenticated sessions is isolated and opt-in only.
7. **Network surface is explicit** — identify runtime/build-time outbound domains. Vendor executable browser assets where practical; otherwise pin versions/integrity and allowlist endpoints.
8. **Least privilege** — workflows, apps, tokens, filesystem access, and network access receive only the permissions required for the bounded task.
9. **Unknown binaries are quarantined** — do not execute opaque prebuilt binaries until provenance, checksum/signature, and necessity are understood.
10. **Upstream updates re-enter Customs** — a previously approved repo is not permanently trusted. Re-run the gate when the upstream commit, dependencies, install scripts, auth behavior, or workflow permissions change.

## Verdicts

- 🟢 **CLEAR TO TEST** — no material red flags found; normal sandbox precautions still apply.
- 🟡 **ISOLATE / HARDEN FIRST** — legitimate project with meaningful supply-chain, credential, network, or install-time risk that requires controls.
- 🔴 **DO NOT RUN** — malicious/suspicious behavior, unverifiable provenance, unacceptable credential access, or unresolved critical supply-chain risk.

A green verdict is permission to test in a sandbox, not a lifetime trust certificate.

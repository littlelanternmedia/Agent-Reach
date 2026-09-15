# Potato Lab Security Hardening

This fork is treated as a **credential-sensitive tool** because it can interact with authenticated social platforms and optionally read browser cookie stores.

## Default policy

Browser-cookie extraction is **disabled by default** in this fork. Importing `agent_reach` installs blockers for the optional `rookiepy` and `browser_cookie3` backends unless this exact environment variable is set:

```bash
AGENT_REACH_ALLOW_BROWSER_COOKIE_READ=1
```

Do not persist that variable globally. Set it only for the single isolated session that needs browser-cookie access.

## Potato Social Read-Only Gate

Social-media mutation is also **disabled by policy**. This fork ships PATH-shadowing wrappers for the social command entry points used by Agent Reach:

- `twitter`
- `rdt`
- `bili`
- `xhs`
- social `opencli` platform commands
- social `mcporter call` tool invocations

Install the wrappers after installing this fork:

```bash
potato-social-guard install
```

Then activate them for the current bounded shell/session:

```bash
export PATH="$HOME/.agent-reach/readonly-bin:$PATH"
```

The install command intentionally does **not** edit `.bashrc`, `.zshrc`, shell profiles, or other persistent startup files.

The gate is fail-closed for known social CLIs: only explicit read/search/browse actions are allowed. Posting, replying, commenting, liking, voting, retweeting, bookmarking mutations, following/unfollowing, deleting, publishing, direct messaging, uploads, and unknown future social verbs are blocked. There is no runtime `--force` or environment-variable bypass for social writes.

A Potato social session is considered protected only when `~/.agent-reach/readonly-bin` is ahead of the real social CLI directories on `PATH`. Calling an upstream binary by absolute path or invoking its Python module directly bypasses PATH wrappers and is therefore outside the approved Potato Lab operating procedure.

Useful checks:

```bash
potato-social-guard status
potato-social-guard check -- twitter search "AI"
potato-social-guard check -- twitter post "blocked"
potato-social-guard check -- opencli instagram follow someone
```

## Isolation requirements

If browser-cookie extraction is ever enabled:

1. Use a dedicated browser profile created only for Agent Reach.
2. Do not use a primary personal/work browser profile.
3. Prefer test, read-only, or otherwise least-privilege social accounts where possible.
4. Run Agent Reach with an isolated `HOME`/configuration directory when practical.
5. Never commit exported cookies, session files, tokens, `.env` files, or generated credential files.
6. Disable the opt-in immediately after the bounded task finishes.

For any authenticated social-media experiment:

1. Activate the Potato Social Read-Only Gate first.
2. Verify `command -v twitter`, `command -v rdt`, `command -v bili`, `command -v xhs`, `command -v opencli`, and `command -v mcporter` resolve to `~/.agent-reach/readonly-bin/...` when those binaries are present.
3. Use dedicated/secondary accounts rather than primary personal or work accounts.
4. Keep request volume low and respect platform rate limits and terms.
5. Stop if a required operation is not on the read-only allowlist; review and update policy rather than bypassing the gate.

Manual per-platform credential configuration does not require browser-cookie extraction and is preferred when it gives narrower access.

## Why the guards exist

Upstream intentionally supports local browser-cookie extraction for selected platforms and some upstream social CLIs also expose write operations. Those are legitimate capabilities, but they cross high-value credential and account-mutation boundaries. Potato Lab therefore treats browser-profile access and social writes as privileged operations rather than convenience defaults.

## Upstream updates

Before merging or syncing any future upstream change:

- review changes touching cookie/session/auth/config code;
- review social CLI command surfaces for new or renamed actions;
- review new dependencies and install hooks;
- confirm the default-deny browser-cookie guard still works;
- confirm the Potato Social Read-Only test matrix still passes;
- re-run the Potato Customs supply-chain checklist.

# Potato Lab Security Hardening

This fork is treated as a **credential-sensitive tool** because it can interact with authenticated social platforms and optionally read browser cookie stores.

## Default policy

Browser-cookie extraction is **disabled by default** in this fork. Importing `agent_reach` installs blockers for the optional `rookiepy` and `browser_cookie3` backends unless this exact environment variable is set:

```bash
AGENT_REACH_ALLOW_BROWSER_COOKIE_READ=1
```

Do not persist that variable globally. Set it only for the single isolated session that needs browser-cookie access.

## Isolation requirements

If browser-cookie extraction is ever enabled:

1. Use a dedicated browser profile created only for Agent Reach.
2. Do not use a primary personal/work browser profile.
3. Prefer test, read-only, or otherwise least-privilege social accounts where possible.
4. Run Agent Reach with an isolated `HOME`/configuration directory when practical.
5. Never commit exported cookies, session files, tokens, `.env` files, or generated credential files.
6. Disable the opt-in immediately after the bounded task finishes.

Manual per-platform credential configuration does not require browser-cookie extraction and is preferred when it gives narrower access.

## Why the guard exists

Upstream intentionally supports local browser-cookie extraction for selected platforms. That is legitimate functionality, but it crosses a high-value credential boundary. Potato Lab therefore treats browser-profile access as an explicit privileged operation rather than a convenience default.

## Upstream updates

Before merging or syncing any future upstream change:

- review changes touching cookie/session/auth/config code;
- review new dependencies and install hooks;
- confirm the default-deny browser-cookie guard still works;
- re-run the Potato Customs supply-chain checklist.

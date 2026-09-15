# -*- coding: utf-8 -*-
"""Potato Social Read-Only Gate.

This module enforces a fail-closed command policy for social-media CLIs used by
Agent Reach. It is intentionally separate from upstream tools: the wrappers
inspect the requested command, reject mutations, then delegate only allowed
read/search actions to the real executable found later on PATH.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


WRAPPER_BINARIES = ("twitter", "rdt", "bili", "xhs", "opencli", "mcporter")
SOCIAL_OPENCLI_PLATFORMS = {
    "twitter",
    "x",
    "reddit",
    "xiaohongshu",
    "xhs",
    "facebook",
    "instagram",
    "bilibili",
    "linkedin",
}

# Explicit allowlists are deliberate. Unknown verbs fail closed for social CLIs.
_READ_ONLY_ACTIONS = {
    "twitter": {
        "feed",
        "bookmarks",
        "search",
        "user",
        "user-posts",
        "likes",
        "tweet",
        "article",
        "list",
        "followers",
        "following",
        "whoami",
        "status",
    },
    "rdt": {
        "login",
        "logout",
        "status",
        "whoami",
        "feed",
        "popular",
        "all",
        "sub",
        "sub-info",
        "user",
        "user-posts",
        "user-comments",
        "saved",
        "upvoted",
        "open",
        "read",
        "show",
        "search",
        "export",
    },
    "bili": {
        "login",
        "logout",
        "status",
        "whoami",
        "video",
        "user",
        "user-videos",
        "search",
        "favorites",
        "following",
        "history",
        "watch-later",
        "feed",
        "my-dynamics",
        "hot",
        "rank",
        "audio",
    },
    "xhs": {
        "login",
        "logout",
        "status",
        "whoami",
        "search",
        "read",
        "comments",
        "hot",
        "feed",
        "user",
        "user-posts",
        "favorites",
    },
}

_OPENCLI_READ_ONLY_ACTIONS = {
    "twitter": {"search", "article", "user-posts", "feed", "user", "tweet"},
    "x": {"search", "article", "user-posts", "feed", "user", "tweet"},
    "reddit": {"search", "read", "subreddit", "hot", "popular", "subreddit-info"},
    "xiaohongshu": {"search", "note", "comments", "feed", "user"},
    "xhs": {"search", "note", "comments", "feed", "user"},
    "facebook": {"search", "profile", "feed", "groups"},
    "instagram": {"search", "profile", "user", "explore", "saved"},
    "bilibili": {"subtitle", "search", "video", "user"},
    # LinkedIn uses MCP in Agent Reach today. Unknown OpenCLI LinkedIn verbs fail closed.
    "linkedin": set(),
}

# MCP tool names are matched exactly or by a conservative read-only prefix.
_MCP_SOCIAL_SERVERS = {
    "xiaohongshu",
    "xhs",
    "linkedin",
    "linkedin-scraper",
    "linkedin-scraper-mcp",
    "mcp-server-linkedin",
}
_MCP_READ_ONLY_EXACT = {
    "xiaohongshu.check_login_status",
    "xiaohongshu.search_feeds",
    "xiaohongshu.get_feed_detail",
    "xhs.check_login_status",
    "xhs.search_feeds",
    "xhs.get_feed_detail",
}
_MCP_READ_ONLY_VERBS = (
    "get_",
    "read_",
    "search_",
    "list_",
    "find_",
    "fetch_",
    "lookup_",
    "check_",
    "status",
    "profile",
)

_HELP_TOKENS = {"-h", "--help", "--version"}


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str
    binary: str
    platform: str | None = None
    action: str | None = None


class SocialWriteBlocked(PermissionError):
    """Raised when a social command is outside the read-only policy."""


def _basename(value: str) -> str:
    return os.path.basename(value).lower()


def _first_non_option(tokens: Sequence[str]) -> tuple[str | None, int | None]:
    for index, token in enumerate(tokens):
        if token == "--":
            continue
        if token.startswith("-"):
            continue
        return token.lower(), index
    return None, None


def _allow_help(binary: str, args: Sequence[str]) -> GuardDecision | None:
    if not args or any(token in _HELP_TOKENS for token in args):
        return GuardDecision(True, "help/version is non-mutating", binary)
    return None


def _check_simple_cli(binary: str, args: Sequence[str]) -> GuardDecision:
    help_decision = _allow_help(binary, args)
    if help_decision:
        return help_decision

    action, _ = _first_non_option(args)
    if action is None:
        return GuardDecision(False, "no explicit read-only action was found", binary)

    allowed = _READ_ONLY_ACTIONS.get(binary, set())
    if action in allowed:
        return GuardDecision(True, "explicit read-only allowlist match", binary, action=action)

    return GuardDecision(
        False,
        f"'{action}' is not on the Potato read-only allowlist",
        binary,
        action=action,
    )


def _check_opencli(args: Sequence[str]) -> GuardDecision:
    help_decision = _allow_help("opencli", args)
    if help_decision:
        return help_decision

    platform, platform_index = _first_non_option(args)
    if platform is None or platform_index is None:
        return GuardDecision(False, "OpenCLI command has no platform", "opencli")

    if platform not in SOCIAL_OPENCLI_PLATFORMS:
        # The social gate should not break unrelated OpenCLI integrations.
        return GuardDecision(True, "non-social OpenCLI platform; social gate not applicable", "opencli")

    action, _ = _first_non_option(args[platform_index + 1 :])
    if action is None:
        return GuardDecision(False, "social OpenCLI command has no explicit action", "opencli", platform)

    if action in _OPENCLI_READ_ONLY_ACTIONS.get(platform, set()):
        return GuardDecision(True, "explicit social read-only allowlist match", "opencli", platform, action)

    return GuardDecision(
        False,
        f"OpenCLI {platform}.{action} is not on the Potato read-only allowlist",
        "opencli",
        platform,
        action,
    )


def _split_mcp_tool(tool: str) -> tuple[str | None, str | None]:
    if "." not in tool:
        return None, None
    server, action = tool.split(".", 1)
    return server.lower(), action.lower()


def _mcp_action_is_read_only(tool: str, action: str) -> bool:
    lowered = tool.lower()
    if lowered in _MCP_READ_ONLY_EXACT:
        return True
    return action.startswith(_MCP_READ_ONLY_VERBS)


def _check_mcporter(args: Sequence[str]) -> GuardDecision:
    help_decision = _allow_help("mcporter", args)
    if help_decision:
        return help_decision

    command, command_index = _first_non_option(args)
    if command != "call" or command_index is None:
        # config/inspect/etc are outside the social-content mutation boundary.
        return GuardDecision(True, "mcporter command is not a social tool call", "mcporter")

    tool, _ = _first_non_option(args[command_index + 1 :])
    if tool is None:
        return GuardDecision(False, "mcporter call has no tool name", "mcporter")

    server, action = _split_mcp_tool(tool)
    if server is None or action is None:
        return GuardDecision(False, "mcporter social tool name is not server.action", "mcporter")

    if server not in _MCP_SOCIAL_SERVERS:
        return GuardDecision(True, "non-social MCP server; social gate not applicable", "mcporter")

    if _mcp_action_is_read_only(tool, action):
        return GuardDecision(True, "MCP tool name is read-only", "mcporter", server, action)

    return GuardDecision(
        False,
        f"MCP social tool '{tool}' is not provably read-only",
        "mcporter",
        server,
        action,
    )


def check_social_command(argv: Sequence[str]) -> GuardDecision:
    """Return a fail-closed read-only decision for a social command argv."""
    if not argv:
        return GuardDecision(False, "empty command", "")

    binary = _basename(argv[0])
    args = list(argv[1:])

    if binary in _READ_ONLY_ACTIONS:
        return _check_simple_cli(binary, args)
    if binary == "opencli":
        return _check_opencli(args)
    if binary == "mcporter":
        return _check_mcporter(args)

    return GuardDecision(True, "command is outside the social gate", binary)


def require_read_only(argv: Sequence[str]) -> GuardDecision:
    decision = check_social_command(argv)
    if not decision.allowed:
        command = " ".join(argv)
        raise SocialWriteBlocked(
            "Potato Social Read-Only Gate blocked this command: "
            f"{command!r}. Reason: {decision.reason}. "
            "Social write actions require an explicit future policy change; "
            "there is no runtime bypass flag."
        )
    return decision


def _filtered_path(excluded_dir: Path) -> str:
    kept: list[str] = []
    excluded = excluded_dir.resolve()
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw:
            continue
        try:
            if Path(raw).expanduser().resolve() == excluded:
                continue
        except OSError:
            pass
        kept.append(raw)
    return os.pathsep.join(kept)


def find_real_executable(binary: str, wrapper_dir: Path) -> str:
    path = _filtered_path(wrapper_dir)
    found = shutil.which(binary, path=path)
    if not found:
        raise FileNotFoundError(
            f"Potato Social Read-Only Gate allowed '{binary}', but no real executable "
            "was found after the wrapper directory on PATH."
        )
    return found


def wrapper_dir(home: str | os.PathLike[str] | None = None) -> Path:
    root = Path(home).expanduser() if home is not None else Path.home()
    return root / ".agent-reach" / "readonly-bin"


def install_wrappers(home: str | os.PathLike[str] | None = None) -> Path:
    """Install PATH-shadowing wrappers for known social command entry points."""
    target = wrapper_dir(home)
    target.mkdir(parents=True, exist_ok=True)
    script = (
        "#!/usr/bin/env python3\n"
        "from agent_reach.social_readonly import wrapper_main\n"
        "raise SystemExit(wrapper_main())\n"
    )
    for binary in WRAPPER_BINARIES:
        path = target / binary
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
    return target


def uninstall_wrappers(home: str | os.PathLike[str] | None = None) -> None:
    target = wrapper_dir(home)
    if not target.exists():
        return
    for binary in WRAPPER_BINARIES:
        path = target / binary
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    try:
        target.rmdir()
    except OSError:
        pass


def activation_line(home: str | os.PathLike[str] | None = None) -> str:
    target = wrapper_dir(home)
    return f'export PATH="{target}:$PATH"'


def wrapper_main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by generated wrappers."""
    raw = list(sys.argv if argv is None else argv)
    if not raw:
        return 2
    binary = _basename(raw[0])
    command = [binary, *raw[1:]]
    try:
        require_read_only(command)
        real = find_real_executable(binary, Path(raw[0]).resolve().parent)
    except (SocialWriteBlocked, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 126

    os.execvpe(real, [real, *raw[1:]], os.environ.copy())
    return 0


def format_policy() -> str:
    lines = ["Potato Social Read-Only Gate", "=" * 31]
    for binary in ("twitter", "rdt", "bili", "xhs"):
        actions = ", ".join(sorted(_READ_ONLY_ACTIONS[binary]))
        lines.append(f"{binary}: {actions}")
    lines.append("OpenCLI social platforms: explicit per-platform allowlists; unknown actions block")
    lines.append("mcporter social calls: only provably read-only tool names pass")
    lines.append("Write actions: blocked; no runtime bypass flag")
    return "\n".join(lines)

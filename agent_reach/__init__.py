# -*- coding: utf-8 -*-
"""Agent Reach — Give your AI Agent eyes to see the entire internet.

Potato Lab hardening: local browser-cookie readers are disabled by default.
Set ``AGENT_REACH_ALLOW_BROWSER_COOKIE_READ=1`` only inside an intentionally
isolated environment/profile when browser-cookie extraction is required.
Manual credential configuration remains available without this opt-in.
"""

import os
import sys
import types

__version__ = "1.5.0"
__author__ = "Neo Reid"

_COOKIE_OPT_IN = "AGENT_REACH_ALLOW_BROWSER_COOKIE_READ"


def _cookie_read_blocked(*_args, **_kwargs):
    raise PermissionError(
        "Browser-cookie extraction is disabled by Potato Lab security policy. "
        f"Use an isolated browser profile/environment, then explicitly set {_COOKIE_OPT_IN}=1 "
        "for that session only."
    )


def _install_cookie_reader_guard() -> None:
    """Fail closed if optional browser-cookie extraction libraries are requested.

    ``cookie_extract.py`` prefers rookiepy when present and otherwise falls back
    to browser_cookie3. Replacing either module here prevents import order from
    bypassing the policy. The guard is installed only when the explicit opt-in
    is absent.
    """
    if os.environ.get(_COOKIE_OPT_IN) == "1":
        return

    rookiepy = types.ModuleType("rookiepy")
    for name in ("chrome", "firefox", "edge", "brave", "opera"):
        setattr(rookiepy, name, _cookie_read_blocked)
    sys.modules["rookiepy"] = rookiepy

    browser_cookie3 = types.ModuleType("browser_cookie3")
    for name in ("chrome", "firefox", "edge", "brave", "opera"):
        setattr(browser_cookie3, name, _cookie_read_blocked)
    sys.modules["browser_cookie3"] = browser_cookie3


_install_cookie_reader_guard()

from agent_reach.core import AgentReach

__all__ = ["AgentReach"]

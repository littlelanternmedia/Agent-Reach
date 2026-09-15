# -*- coding: utf-8 -*-
"""CLI for installing and inspecting the Potato Social Read-Only Gate."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from agent_reach.social_readonly import (
    SocialWriteBlocked,
    activation_line,
    check_social_command,
    format_policy,
    install_wrappers,
    require_read_only,
    uninstall_wrappers,
    wrapper_dir,
)


def _strip_separator(command: list[str]) -> list[str]:
    if command and command[0] == "--":
        return command[1:]
    return command


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="potato-social-guard",
        description="Install/check the Potato Social Read-Only Gate",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show policy and wrapper location")
    sub.add_parser("install", help="Install read-only PATH wrappers")
    sub.add_parser("uninstall", help="Remove read-only PATH wrappers")

    p_check = sub.add_parser("check", help="Check whether a command is allowed")
    p_check.add_argument("argv", nargs=argparse.REMAINDER)

    p_exec = sub.add_parser("exec", help="Execute a command only if read-only policy allows it")
    p_exec.add_argument("argv", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    if not args.command or args.command == "status":
        print(format_policy())
        print()
        target = wrapper_dir()
        print(f"Wrapper directory: {target}")
        print(f"Installed: {'yes' if target.exists() else 'no'}")
        print("Activation (current shell only):")
        print(f"  {activation_line()}")
        return 0

    if args.command == "install":
        target = install_wrappers()
        print(f"Installed Potato Social Read-Only wrappers in: {target}")
        print("Activate for this shell/session with:")
        print(f"  {activation_line()}")
        print("This command does not edit shell profiles or persist PATH changes.")
        return 0

    if args.command == "uninstall":
        uninstall_wrappers()
        print("Removed Potato Social Read-Only wrappers.")
        return 0

    command = _strip_separator(list(args.argv))
    if not command:
        parser.error(f"{args.command} requires a command after --")

    if args.command == "check":
        decision = check_social_command(command)
        status = "ALLOW" if decision.allowed else "BLOCK"
        print(f"{status}: {decision.reason}")
        return 0 if decision.allowed else 126

    if args.command == "exec":
        try:
            require_read_only(command)
        except SocialWriteBlocked as exc:
            print(str(exc), file=sys.stderr)
            return 126
        completed = subprocess.run(command, env=os.environ.copy(), check=False)
        return completed.returncode

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

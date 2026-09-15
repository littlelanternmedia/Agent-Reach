#!/usr/bin/env python3
"""Potato Security Gate deterministic, read-only honeypot/supply-chain preflight.

No dependency installation. No target code execution. No network access.
Scans bounded text/config files and Git metadata for risky indicators.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from pathlib import Path
from typing import Iterable

GATE_VERSION = "0.1.0"
MAX_FILE = 1_000_000
MAX_TOTAL = 50_000_000
SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "target", ".venv", "venv", "__pycache__", ".cache", "coverage"}
TEXT_EXTS = {"", ".json", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".md", ".txt", ".xml", ".html", ".css", ".dockerfile"}

PATTERNS = [
    ("credential-harvest", 8, "Reads likely credential/token/key material", r"(?i)(\.ssh/|id_rsa|id_ed25519|aws/credentials|gcloud/credentials|keychain|credential[^\n]{0,40}(read|load|steal|dump)|process\.env\[[^]]*(token|secret|key))"),
    ("browser-session-access", 8, "Touches browser cookies/session/profile stores", r"(?i)(Cookies|Login Data|Local State|chrome.*profile|chromium.*profile|firefox.*profiles|browser.*cookie|sessionstore\.jsonlz4)"),
    ("wallet-access", 10, "Touches wallet/seed/private-key material", r"(?i)(seed phrase|mnemonic|private[_ -]?key|metamask|wallet\.dat|keystore.*wallet)"),
    ("secret-exfil", 10, "Potential secret collection/exfiltration", r"(?i)(env\s*\|\s*(curl|wget)|cat\s+[^\n]*(\.env|credentials|id_rsa)[^\n]*\|\s*(curl|wget)|upload[^\n]{0,40}(token|secret|cookie|credential))"),
    ("destructive-shell", 10, "Contains destructive host-level shell behavior", r"(?i)(rm\s+-rf\s+/(\s|$)|mkfs\.|dd\s+if=.*of=/dev/|:>\s*/etc/|chmod\s+-R\s+777\s+/)"),
    ("persistence", 7, "Attempts persistence or host startup mutation", r"(?i)(crontab|launchctl|systemctl\s+enable|/etc/cron|autorun|startup folder|schtasks\s+/create)"),
    ("privileged-container", 6, "Requests privileged container/host access", r"(?i)(--privileged|privileged:\s*true|/var/run/docker\.sock|hostNetwork:\s*true|hostPID:\s*true)"),
    ("remote-script-exec", 6, "Downloads and directly executes remote script", r"(?i)((curl|wget)[^\n]{0,240}\|\s*(sh|bash|zsh|python|node)|Invoke-WebRequest[^\n]{0,240}Invoke-Expression)"),
    ("dynamic-code-fetch", 5, "Fetches remote code for dynamic execution", r"(?i)(eval\s*\([^\n]*(fetch|requests|get\(|http)|exec\s*\([^\n]*(requests|urlopen|http))"),
    ("telemetry-network", 2, "Contains telemetry/analytics network behavior requiring review", r"(?i)(telemetry|analytics|sentry|posthog|segment\.io|mixpanel|amplitude)"),
    ("dangerous-gha", 6, "Potentially dangerous GitHub Actions trust boundary", r"(?i)(pull_request_target|workflow_run:)[\s\S]{0,1400}(checkout|github\.event\.pull_request\.head|npm install|pip install|run:)"),
]

INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare"}

def git(args: list[str], cwd: Path) -> str | None:
    try:
        p = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False,
                           env={"PATH": os.environ.get("PATH", "")})
        return p.stdout.strip() if p.returncode == 0 else None
    except Exception:
        return None

def iter_files(root: Path) -> Iterable[Path]:
    total = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(base)/d).is_symlink()]
        for name in files:
            p = Path(base) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE:
                continue
            total += size
            if total > MAX_TOTAL:
                return
            ext = p.suffix.lower()
            if ext in TEXT_EXTS or name in {"Dockerfile", "Makefile", "Procfile", "package.json", "pyproject.toml", "Cargo.toml", "go.mod"}:
                yield p

def add(findings, fid, points, summary, path=None, evidence=None):
    item = {"id": fid, "points": points, "summary": summary}
    if path: item["path"] = path
    if evidence: item["evidence"] = evidence[:240]
    findings.append(item)

def scan_package_json(root: Path, findings):
    for p in root.rglob("package.json"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try: data = json.loads(p.read_text("utf-8"))
        except Exception: continue
        scripts = data.get("scripts") or {}
        for hook in sorted(INSTALL_HOOKS & scripts.keys()):
            add(findings, "npm-install-hook", 5, f"package.json defines {hook} hook", str(p.relative_to(root)), f"{hook}: {scripts[hook]}")
        deps = {}
        for k in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(data.get(k) or {})
        for name, spec in deps.items():
            if isinstance(spec, str) and re.search(r"(?i)^(git\+|https?://|github:|git://)", spec):
                add(findings, "nonregistry-dependency", 3, "Dependency resolves from VCS/URL rather than registry", str(p.relative_to(root)), f"{name}: {spec}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=".")
    ap.add_argument("--json-out")
    args = ap.parse_args()
    root = Path(args.target).resolve()
    if not root.is_dir():
        raise SystemExit(f"target is not a directory: {root}")

    findings = []
    scan_package_json(root, findings)
    compiled = [(a,b,c,re.compile(d)) for a,b,c,d in PATTERNS]
    seen = set()
    scanned = 0
    for p in iter_files(root):
        try: text = p.read_text("utf-8", errors="replace")
        except OSError: continue
        scanned += 1
        rel = str(p.relative_to(root))
        for fid, points, summary, rx in compiled:
            m = rx.search(text)
            key = (fid, rel)
            if m and key not in seen:
                seen.add(key)
                snippet = re.sub(r"\s+", " ", m.group(0)).strip()
                add(findings, fid, points, summary, rel, snippet)

    remote = git(["remote", "-v"], root)
    head = git(["rev-parse", "HEAD"], root)
    status = git(["status", "--porcelain=v1", "--untracked-files=no"], root)
    if status:
        add(findings, "dirty-worktree", 1, "Tracked worktree has local modifications; audit source ref is not pristine")

    score = sum(f["points"] for f in findings)
    hard_red = any(f["id"] in {"secret-exfil", "wallet-access", "destructive-shell"} for f in findings)
    verdict = "red" if hard_red or score >= 16 else "yellow" if score >= 4 else "green"
    result = {
        "gate_version": GATE_VERSION,
        "target": str(root),
        "preflight": {
            "verdict": verdict,
            "score": score,
            "files_scanned": scanned,
            "findings": findings,
            "git": {"head": head, "remote": remote, "dirty_tracked": bool(status)}
        },
        "cloudflare_stage": {
            "status": "blocked_by_preflight" if verdict == "red" else "ready",
            "profile": "quick" if verdict == "green" else "standard",
            "pin": "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
        },
        "final_verdict": "red" if verdict == "red" else "pending"
    }
    out = json.dumps(result, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(out + "\n", encoding="utf-8")
    print(out)
    return 2 if verdict == "red" else 1 if verdict == "yellow" else 0

if __name__ == "__main__":
    sys.exit(main())

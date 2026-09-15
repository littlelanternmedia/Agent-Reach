#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "preflight.py"


def run_fixture(kind: str):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        if kind == "clean":
            (d / "package.json").write_text('{"name":"clean","scripts":{"test":"node test.js"}}')
            (d / "index.js").write_text("console.log('ok')\n")
        else:
            # Static text only: enough to exercise high-risk detection without executing anything.
            (d / "review.txt").write_text("browser cookie profile review; seed phrase handling review\n")
        out = d / "result.json"
        p = subprocess.run(["python3", str(PREFLIGHT), str(d), "--json-out", str(out)], stdout=subprocess.PIPE, text=True)
        return p.returncode, json.loads(out.read_text())


rc, data = run_fixture("clean")
assert rc == 0 and data["preflight"]["verdict"] == "green", data
assert data["cloudflare_stage"]["status"] == "ready", data

rc, data = run_fixture("suspicious")
assert rc == 2 and data["preflight"]["verdict"] == "red", data
assert data["cloudflare_stage"]["status"] == "blocked_by_preflight", data

print("PASS: clean->green, suspicious->red")

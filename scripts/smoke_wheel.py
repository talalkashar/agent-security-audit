"""Smoke-test an installed wheel (not the source tree): entry points, packaged data and a scan of the local lab.

    python3 scripts/smoke_wheel.py <venv bin or Scripts folder>

Runs from a temporary folder so nothing is imported from src/. Only 127.0.0.1 is contacted.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8642


def tool(bindir, name):
    exe = Path(bindir) / (name + (".exe" if os.name == "nt" else ""))
    if not exe.is_file():
        sys.exit(f"{exe} not found: is the wheel installed in {bindir}?")
    return str(exe)


def run(cmd, cwd, **kw):
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=300, **kw)


def wait_ready(url, proc):
    for _ in range(100):
        if proc.poll() is not None:
            sys.exit(f"the lab exited early with code {proc.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    sys.exit(f"the lab did not answer at {url}")


def scan_lab(asa, cwd, mode):
    url = f"http://127.0.0.1:{PORT}"
    lab = subprocess.Popen([asa, "lab", "--mode", mode, "--port", str(PORT)], cwd=cwd,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_ready(url + "/", lab)
        out = Path(cwd) / f"{mode}.json"
        run([asa, "scan", url, "--rate-limit-path", "/api/login", "--format", "json", "--out", str(out),
             "--fail-on", "none"], cwd)
        return json.loads(out.read_text(encoding="utf-8"))["counts"]
    finally:
        lab.terminate()
        lab.wait(timeout=10)


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: smoke_wheel.py <venv bin folder>")
    bindir = argv[1]
    asa, mcp = tool(bindir, "asa"), tool(bindir, "asa-mcp")
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    with tempfile.TemporaryDirectory() as cwd:
        shown = run([asa, "--version"], cwd).stdout.strip()
        if not shown.endswith(version):
            sys.exit(f"asa --version printed {shown!r}, expected version {version}")
        if len(run([asa, "list"], cwd).stdout.splitlines()) < 50:
            sys.exit("asa list returned too few checks: is the catalog missing from the wheel?")
        if "AUTH-01" not in run([asa, "show", "AUTH-01"], cwd).stdout:
            sys.exit("asa show AUTH-01 did not print the check")
        run([mcp], cwd, stdin=subprocess.DEVNULL)
        vulnerable = scan_lab(asa, cwd, "vulnerable")
        fixed = scan_lab(asa, cwd, "fixed")
    print("vulnerable lab:", vulnerable, "\nfixed lab:", fixed)
    if vulnerable["fail"] == 0 or fixed["fail"] != 0:
        sys.exit("lab scan results are wrong: the vulnerable lab must fail checks and the fixed lab none")
    print(f"wheel smoke test passed ({shown})")


if __name__ == "__main__":
    main(sys.argv)

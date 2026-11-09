"""Check that every file that states the release version agrees, and (for a release) that the tag matches.

The version is written in four files: pyproject.toml, src/agent_security_audit/__init__.py, the Claude plugin manifest
and CITATION.cff. The release workflow runs this before publishing, so a tag can never ship with a stale file.

    python3 scripts/release_version.py           # print the version, exit 1 if the files disagree
    python3 scripts/release_version.py v0.2.0    # also exit 1 unless the tag is "v" + that version
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _init_version(root):
    tree = ast.parse((root / "src" / "agent_security_audit" / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "__version__" for t in node.targets):
            return ast.literal_eval(node.value)
    return None


def _pyproject_version(root):
    """The static version, or the __version__ it reads when the version is dynamic; None if neither holds."""
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    meta = project.get("project", {})
    if "version" in meta:
        return meta["version"]
    attr = project.get("tool", {}).get("setuptools", {}).get("dynamic", {}).get("version", {}).get("attr")
    if "version" in meta.get("dynamic", []) and attr == "agent_security_audit.__version__":
        return _init_version(root)
    return None


def _citation_version(root):
    text = (root / "CITATION.cff").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*[\"']?([^\"'\s]+)", text)
    return match.group(1) if match else None


def versions(root=ROOT):
    """Map of file to the version it states (None when the file states none)."""
    plugin = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    return {
        "src/agent_security_audit/__init__.py": _init_version(root),
        "pyproject.toml": _pyproject_version(root),
        ".claude-plugin/plugin.json": plugin.get("version"),
        "CITATION.cff": _citation_version(root),
    }


def problems(tag=None, root=ROOT):
    found = versions(root)
    errors = [f"{path}: no version found" for path, v in found.items() if not v]
    if len({v for v in found.values() if v}) > 1:
        errors.append("versions disagree: " + ", ".join(f"{p}={v}" for p, v in found.items()))
    want = found["src/agent_security_audit/__init__.py"]
    if tag is not None and tag != f"v{want}":
        errors.append(f"tag {tag!r} does not match version {want!r} (expected 'v{want}')")
    return errors


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    errors = problems(argv[0] if argv else None)
    for line in errors:
        print(line, file=sys.stderr)
    if not errors:
        print(versions()["src/agent_security_audit/__init__.py"])
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

"""Write a CycloneDX 1.6 SBOM (JSON) for the built distributions. Standard library only.

The package has no runtime dependencies, so the SBOM lists the package itself, its license, and the SHA-256 of each
file in dist/. The timestamp comes from SOURCE_DATE_EPOCH when set, so a rebuild of the same commit gives the same file.

    python3 scripts/make_sbom.py dist > agent-security-audit.cdx.json
"""

import hashlib
import json
import os
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv):
    if len(argv) != 2:
        sys.exit("usage: make_sbom.py <dist folder>")
    dist = Path(argv[1])
    files = sorted(p for p in dist.iterdir() if p.suffix in (".whl", ".gz"))
    if not files:
        sys.exit(f"no .whl or .tar.gz in {dist}")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name, version = project["name"], project["version"]
    if project.get("dependencies"):
        sys.exit("runtime dependencies found: list them as SBOM components before using this script")
    digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or datetime.now(UTC).timestamp())
    purl = f"pkg:pypi/{name}@{version}"
    repo = project["urls"]["Homepage"]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, purl + "#" + json.dumps(digests))),
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "description": project["description"],
                "licenses": [{"license": {"id": project["license"]}}],
                "purl": purl,
                "externalReferences": [{"type": "vcs", "url": repo}],
                "properties": [{"name": "python:requires", "value": project["requires-python"]}],
                "components": [
                    {"type": "file", "bom-ref": f"{purl}#{fname}", "name": fname,
                     "hashes": [{"alg": "SHA-256", "content": digest}]}
                    for fname, digest in digests.items()
                ],
            },
        },
        "components": [],  # no runtime dependencies: the package uses only the Python standard library
        "dependencies": [{"ref": purl, "dependsOn": []}],
    }
    json.dump(sbom, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)

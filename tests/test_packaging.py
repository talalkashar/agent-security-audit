"""Packaging and release guards that tests/test_release.py does not cover: the tag check script, every runtime file
inside the wheel, entry points, PyPI metadata, hash-pinned CI tools and workflow script injection."""

import contextlib
import fnmatch
import importlib
import importlib.util
import io
import json
import re
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "agent_security_audit"
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
VERSION_FILES = ("pyproject.toml", "CITATION.cff", ".claude-plugin/plugin.json", "src/agent_security_audit/__init__.py")


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


class ReleaseVersionScriptTest(unittest.TestCase):
    def setUp(self):
        self.rv = load_script("release_version")

    def test_repo_passes(self):
        from agent_security_audit import __version__

        self.assertEqual(self.rv.problems(), [])
        self.assertEqual(self.rv.problems(f"v{__version__}"), [])
        self.assertEqual(set(self.rv.versions().values()), {__version__})

    def test_wrong_tag_is_refused(self):
        from agent_security_audit import __version__

        self.assertTrue(self.rv.problems(__version__), "a tag without the v prefix must be refused")
        self.assertTrue(self.rv.problems("v0.0.0"))

    def test_a_stale_version_file_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in VERSION_FILES:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / rel, root / rel)
            self.assertEqual(self.rv.problems(root=root), [])
            plugin = json.loads((root / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
            plugin["version"] = "0.0.1"
            (root / ".claude-plugin/plugin.json").write_text(json.dumps(plugin), encoding="utf-8")
            self.assertTrue(any("disagree" in e for e in self.rv.problems(root=root)))
            (root / "CITATION.cff").write_text("cff-version: 1.2.0\n", encoding="utf-8")
            self.assertIn("CITATION.cff: no version found", self.rv.problems(root=root))

    def test_main_exit_codes(self):
        from agent_security_audit import __version__

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.rv.main([f"v{__version__}"]), 0)
            self.assertEqual(self.rv.main(["v0.0.0"]), 1)


class MetadataTest(unittest.TestCase):
    def test_license_ships_and_has_no_classifier(self):
        project = pyproject()["project"]
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])
        self.assertTrue((ROOT / "LICENSE").is_file())
        # PEP 639: no License :: classifier next to a license expression (setuptools refuses the build).
        self.assertFalse([c for c in project["classifiers"] if c.startswith("License ::")])

    def test_python_classifiers_match_requires_python_and_ci(self):
        project = pyproject()["project"]
        self.assertEqual(project["requires-python"], ">=3.11")
        listed = {c.rsplit(" ", 1)[1] for c in project["classifiers"]
                  if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)}
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        tested = set(re.findall(r'"(3\.\d+)"', re.search(r"python-version: \[(.*)\]", ci).group(1)))
        self.assertEqual(listed, tested)

    def test_project_urls(self):
        urls = pyproject()["project"]["urls"]
        for key in ("Homepage", "Documentation", "Issues", "Changelog", "Security"):
            self.assertTrue(urls.get(key, "").startswith("https://github.com/talalkashar/agent-security-audit"), key)

    def test_entry_points_resolve(self):
        scripts = pyproject()["project"]["scripts"]
        self.assertEqual(set(scripts), {"asa", "asa-mcp", "agent-security-audit"})
        for name, target in scripts.items():
            module, attr = target.split(":")
            with self.subTest(script=name):
                self.assertTrue(callable(getattr(importlib.import_module(module), attr)))

    def test_package_data_covers_every_runtime_file(self):
        # Every non-Python file in the package must match a package-data glob, or the wheel ships without it.
        globs = pyproject()["tool"]["setuptools"]["package-data"]["agent_security_audit"]
        data = [p.relative_to(PACKAGE).as_posix() for p in PACKAGE.rglob("*")
                if p.is_file() and p.suffix not in (".py", ".pyc") and "__pycache__" not in p.parts]
        self.assertTrue(data)
        for rel in data:
            with self.subTest(file=rel):
                self.assertTrue(any(fnmatch.fnmatch(rel, g) for g in globs), f"{rel} is not in package-data")


class WorkflowTest(unittest.TestCase):
    def test_no_expressions_inside_run_scripts(self):
        # ${{ }} in a run script is pasted into the shell before it runs; pass values through env instead.
        for wf in WORKFLOWS:
            for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
                if "${{" in line:
                    with self.subTest(workflow=wf.name, line=n):
                        self.assertRegex(line, r"^\s*(- )?(?!run:)[\w-]+: ")

    def test_version_comments_are_exact(self):
        # A "# v4" comment hides which release the SHA is; Dependabot and reviewers need the full version.
        for wf in WORKFLOWS:
            for line in wf.read_text(encoding="utf-8").splitlines():
                if "uses:" in line:
                    with self.subTest(workflow=wf.name, line=line.strip()):
                        self.assertRegex(line, r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$")

    def test_release_checks_the_tag_against_every_version_file_before_publishing(self):
        text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('python scripts/release_version.py "$TAG"', text)
        self.assertIn("unittest discover -s tests", text)
        needs = dict(re.findall(r"(?m)^  ([\w-]+):\n(?:    .*\n|\n)*?    needs: (.+)$", text))
        self.assertEqual(needs.get("build"), "verify")
        self.assertIn("build", needs.get("publish", ""))
        self.assertNotIn("password:", text, "publish through Trusted Publishing, not a stored token")

    def test_tools_are_installed_from_hash_pinned_files(self):
        for wf in WORKFLOWS:
            for line in wf.read_text(encoding="utf-8").splitlines():
                # The project itself (editable or the built wheel) is exempt: it has no dependencies to pin.
                if "pip install" in line and "dist/*.whl" not in line and not line.endswith("install -e ."):
                    with self.subTest(workflow=wf.name, line=line.strip()):
                        self.assertIn("--require-hashes -r .github/requirements/", line)
        for name in ("lint.txt", "build.txt"):
            text = (ROOT / ".github/requirements" / name).read_text(encoding="utf-8")
            pins = re.findall(r"(?m)^([\w.-]+)==\S+", text)
            with self.subTest(file=name):
                self.assertTrue(pins)
                self.assertGreaterEqual(text.count("--hash=sha256:"), len(pins))

    def test_wheel_is_installed_alone_and_built_with_the_pinned_backend(self):
        for name in ("ci.yml", "release.yml"):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("python -m build --no-isolation", text)
                self.assertIn("--no-index --no-deps", text)
                self.assertIn("scripts/smoke_wheel.py", text)


class GenDocsMarkerTest(unittest.TestCase):
    def test_missing_marker_fails_instead_of_skipping_the_file(self):
        gen = load_script("gen_docs")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("README.md", "skills/agent-security-audit/SKILL.md"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / rel, root / rel)
            gen.ROOT = root
            self.assertIn("README.md", gen.outputs())
            readme = (root / "README.md").read_text(encoding="utf-8")
            (root / "README.md").write_text(readme.replace("<!-- osi:end -->", ""), encoding="utf-8")
            with self.assertRaises(gen.MarkerError):
                gen.outputs()
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(gen.main(["--check"]), 1)
            self.assertIn("osi:end", err.getvalue())
            (root / "README.md").write_text(readme, encoding="utf-8")
            skill = root / "skills/agent-security-audit/SKILL.md"
            skill.write_text(skill.read_text(encoding="utf-8").replace(gen.SKILL_END, ""), encoding="utf-8")
            with self.assertRaises(gen.MarkerError):
                gen.outputs()


if __name__ == "__main__":
    unittest.main()

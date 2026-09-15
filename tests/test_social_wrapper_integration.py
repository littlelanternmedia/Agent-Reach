from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "agent_reach" / "social_readonly.py"
SPEC = importlib.util.spec_from_file_location("potato_social_wrapper_test_module", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
social = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = social
SPEC.loader.exec_module(social)


@unittest.skipIf(os.name == "nt", "PATH-shadow wrapper integration is currently POSIX-only")
class WrapperIntegrationTests(unittest.TestCase):
    def _fake_binary(self, directory: Path, name: str) -> Path:
        path = directory / name
        path.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import sys
                print("REAL-CLI", *sys.argv[1:])
                """
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def _env(self, wrapper_dir: Path, real_dir: Path) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join(
            [str(wrapper_dir), str(real_dir), env.get("PATH", "")]
        )
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(
            [str(ROOT), existing] if existing else [str(ROOT)]
        )
        return env

    def test_allowed_command_reaches_real_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrappers = social.install_wrappers(root)
            real_dir = root / "real-bin"
            real_dir.mkdir()
            self._fake_binary(real_dir, "twitter")

            result = subprocess.run(
                [str(wrappers / "twitter"), "search", "potatoes"],
                env=self._env(wrappers, real_dir),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("REAL-CLI search potatoes", result.stdout)

    def test_blocked_command_never_reaches_real_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrappers = social.install_wrappers(root)
            real_dir = root / "real-bin"
            real_dir.mkdir()
            self._fake_binary(real_dir, "twitter")

            result = subprocess.run(
                [str(wrappers / "twitter"), "post", "should-not-send"],
                env=self._env(wrappers, real_dir),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 126)
            self.assertIn("Potato Social Read-Only Gate blocked", result.stderr)
            self.assertNotIn("REAL-CLI", result.stdout)

    def test_opencli_social_write_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wrappers = social.install_wrappers(root)
            real_dir = root / "real-bin"
            real_dir.mkdir()
            self._fake_binary(real_dir, "opencli")

            result = subprocess.run(
                [str(wrappers / "opencli"), "instagram", "follow", "someone"],
                env=self._env(wrappers, real_dir),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 126)
            self.assertNotIn("REAL-CLI", result.stdout)


if __name__ == "__main__":
    unittest.main()

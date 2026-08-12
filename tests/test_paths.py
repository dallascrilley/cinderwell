"""U2: configuration and state resolve to machine paths."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cinderwell import doctor  # noqa: E402
from cinderwell import lifecycle  # noqa: E402
from cinderwell import paths  # noqa: E402
from cinderwell import reaper  # noqa: E402


class XdgPathTest(unittest.TestCase):
    def test_defaults_without_environment(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if k not in {"XDG_CONFIG_HOME", "XDG_STATE_HOME"}}
        code = (
            "from cinderwell import paths\n"
            "from pathlib import Path\n"
            "import os\n"
            "home = Path.home()\n"
            "assert paths.default_config_path() == home / '.config' / 'cinderwell' / 'config.json'\n"
            "assert paths.default_state_root() == home / '.local' / 'state' / 'cinderwell'\n"
            "assert paths.default_host_state_path() == "
            "home / '.local' / 'state' / 'cinderwell' / 'host.json'\n"
            "print('ok')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tempfile.gettempdir(),
            env={**env, "PYTHONPATH": str(REPOSITORY_ROOT)},
            capture_output=True, text=True,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("ok", proc.stdout)

    def test_xdg_overrides_are_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "cfg"
            st = Path(tmp) / "st"
            env = {**os.environ, "XDG_CONFIG_HOME": str(cfg),
                   "XDG_STATE_HOME": str(st),
                   "PYTHONPATH": str(REPOSITORY_ROOT)}
            code = (
                "from cinderwell import paths\n"
                f"assert paths.default_config_path() == "
                f"__import__('pathlib').Path({str(cfg)!r}) / 'cinderwell' / 'config.json'\n"
                f"assert paths.default_host_state_path('run-a') == "
                f"__import__('pathlib').Path({str(st)!r}) / 'cinderwell' / 'run-a' / 'host.json'\n"
                "print('ok')\n"
            )
            proc = subprocess.run(
                [sys.executable, "-c", code], cwd=tempfile.gettempdir(),
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)

    def test_two_run_ids_are_independent(self) -> None:
        a = paths.run_state_dir("run-one")
        b = paths.run_state_dir("run-two")
        self.assertNotEqual(a, b)
        self.assertEqual(a.name, "run-one")
        self.assertEqual(b.name, "run-two")

    def test_relative_machine_path_is_refused(self) -> None:
        with self.assertRaises(paths.PathError):
            paths.require_absolute("relative/config.json", field="config")


class DoctorTest(unittest.TestCase):
    def test_doctor_names_unrecognised_and_missing_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "unexpected_top": True,
            }))
            report = doctor.examine(path)
            self.assertFalse(report["ok"])
            joined = " ".join(report["errors"])
            self.assertIn("unrecognised field", joined)
            self.assertIn("missing required field", joined)

    def test_doctor_does_not_edit_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = b'{"schema_version": 1, "nope": true}\n'
            path.write_bytes(original)
            doctor.examine(path)
            self.assertEqual(original, path.read_bytes())

    def test_doctor_migrate_without_yes_leaves_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            original = b'{"schema_version": 1}\n'
            path.write_bytes(original)
            code = doctor.main(["--config", str(path), "--migrate"])
            self.assertEqual(2, code)
            self.assertEqual(original, path.read_bytes())

    def test_doctor_detects_legacy_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / "config.json"
            legacy.write_text("{}")
            hits = doctor.detect_legacy_layout(root)
            self.assertTrue(any(str(legacy) == h for h in hits))
            report = doctor.examine(root / "missing-config.json")
            # examine still sees cwd legacy via detect_legacy_layout default;
            # pin the contract that a non-empty legacy list fails the report.
            # (this call uses empty cwd unless we pass — see next test)



    def test_doctor_legacy_layout_fails_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = root / "runtime" / "state.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("{}")
            # Point detect at this tree by chdir
            previous = Path.cwd()
            try:
                os.chdir(root)
                report = doctor.examine(root / "no-config.json")
            finally:
                os.chdir(previous)
            self.assertFalse(report["ok"])
            self.assertTrue(report["legacy_layout"])
            self.assertTrue(any("previous-layout" in e for e in report["errors"]))

class BindingUntouchedTest(unittest.TestCase):
    def test_config_digest_refusal_message_unchanged(self) -> None:
        """Covers AE3: the binding text is a frozen contract — raised, not just present."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Minimal valid-shaped state with a wrong digest.
            state_path = root / "host.json"
            state_path.write_text(json.dumps({
                "schema_version": 1,
                "generation": 1,
                "config_digest": "0" * 64,
                "primary": {"phase": "ABSENT"},
            }))
            with self.assertRaises(lifecycle.StateError) as raised:
                lifecycle.load_state(state_path, "f" * 64)
            self.assertEqual(
                "state was written under a different configuration; "
                "every recorded plan hash is invalid",
                str(raised.exception),
            )


class ReaperPlistTest(unittest.TestCase):
    def test_rendered_plist_has_no_repository_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "bin" / "cinderwell"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\n")
            binary.chmod(0o755)
            config = root / "cfg" / "config.json"
            state = root / "state" / "host.json"
            config.parent.mkdir(); state.parent.mkdir()
            config.write_text("{}"); state.write_text("{}")
            text = reaper.render_plist(binary, state, config, 300)
            self.assertNotIn(str(REPOSITORY_ROOT), text)
            self.assertIn(str(binary), text)
            self.assertIn(str(config), text)
            self.assertIn(str(state), text)
            self.assertNotIn(str(Path.cwd()), text)
            self.assertIn(str(state.parent / "reaper.log"), text)
            import plistlib
            plistlib.loads(text.encode())


if __name__ == "__main__":
    unittest.main()

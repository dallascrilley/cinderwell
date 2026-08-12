"""The shipped examples are executable claims, so they are tested as such.

A README that shows a receipt nobody generates is a README that drifts. These
run the same commands the README tells a reader to run, and assert on what they
print.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_CONFIG = REPOSITORY_ROOT / "examples" / "config.example.json"
sys.path.insert(0, str(REPOSITORY_ROOT))

from cinderwell import lifecycle  # noqa: E402


def run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *argv], cwd=REPOSITORY_ROOT,
                          capture_output=True, text=True, timeout=120)


class ExampleConfigTest(unittest.TestCase):

    def test_the_shipped_example_config_loads(self) -> None:
        """The quickstart's first step, asserted rather than assumed."""
        config = lifecycle.load_config(EXAMPLE_CONFIG)
        self.assertEqual(1, config["schema_version"])

    def test_the_example_carries_no_credential_shaped_value(self) -> None:
        """`load_config` refuses those, so this is really a claim about the
        example: it must not need a secret to be readable."""
        text = EXAMPLE_CONFIG.read_text()
        self.assertEqual(text, lifecycle.redact(text))


class MockTeardownTest(unittest.TestCase):

    def test_the_mock_teardown_prints_a_passing_receipt(self) -> None:
        result = run("examples/mock_teardown.py")
        self.assertEqual(0, result.returncode, result.stderr)
        receipt = json.loads(result.stdout.split("\n}\n")[0] + "\n}")
        self.assertEqual("PASS", receipt["verdict"])
        self.assertEqual("down", receipt["operation"])
        self.assertIn("state after teardown: ABSENT_VERIFIED", result.stdout)

    def test_absence_is_proved_by_a_second_read_not_by_the_delete(self) -> None:
        """The claim the README makes about the receipt.

        `D2_deletions` says the delete calls were issued. `D3_absent_*` says a
        fresh provider read then found nothing. The receipt is only proof
        because both are present -- a receipt carrying D2 alone would say a
        command succeeded, not that a machine is gone.
        """
        result = run("examples/mock_teardown.py")
        receipt = json.loads(result.stdout.split("\n}\n")[0] + "\n}")
        identifiers = {entry["id"] for entry in receipt["results"]}
        self.assertIn("D2_deletions", identifiers)
        self.assertIn("D3_absent_servers", identifiers)
        self.assertIn("D3_absent_primary_ips", identifiers)

    def test_the_receipt_validates_against_the_shipped_schema(self) -> None:
        result = run("examples/mock_teardown.py")
        receipt = json.loads(result.stdout.split("\n}\n")[0] + "\n}")
        lifecycle.validate(receipt, lifecycle.load_schema("receipt.schema.json"))


class CommandLineTest(unittest.TestCase):

    def test_the_bare_command_prints_usage_and_refuses(self) -> None:
        result = run("-m", "cinderwell")
        self.assertEqual(2, result.returncode)
        self.assertIn("usage: cinderwell", result.stdout)

    def test_help_lists_every_dispatchable_command(self) -> None:
        from cinderwell import __main__ as entrypoint
        result = run("-m", "cinderwell", "--help")
        self.assertEqual(0, result.returncode, result.stderr)
        for command in entrypoint.COMMANDS:
            self.assertIn(command, result.stdout,
                          f"{command} dispatches but is undocumented")

    def test_doctor_reports_the_example_config_as_healthy(self) -> None:
        result = run("-m", "cinderwell", "doctor", "--config", str(EXAMPLE_CONFIG))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()

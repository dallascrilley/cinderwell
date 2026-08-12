#!/usr/bin/env python3
"""Write an approval for one plan (unit U2).

This creates no infrastructure and reads no credential. It takes a plan, checks
that the plan is internally consistent, and writes a small artifact saying that
this plan -- these exact bytes -- may be applied.

What the artifact proves, and what it does not:

* It proves the approval was made against one specific plan. Edit a byte of the
  plan and its hash changes and the approval stops matching, so an approval can
  never be carried over to a plan its approver did not see.
* It does **not** prove a human was present, and it does not authenticate
  `approved_by`, which is self-asserted. The terminal prompt in the CLI
  proved presence; nothing here does. That is the declared trade, not an
  oversight -- see D1 in the plan. A run authorized this way records
  `kind: "approval"` in its receipt, and nothing downstream reads that as
  equivalent to an operator having typed at a prompt.

`--approved-at` is an input rather than a generated value for the same reason
every other timestamp in this system is: the same review should produce the same
artifact, byte for byte, so two people can compare them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cinderwell import lifecycle
from cinderwell.lifecycle import ApprovalError, LifecycleError, redact  # noqa: E402


def build_approval(plan: dict, *, approved_by: str, approved_at: str,
                   reason: str | None = None) -> dict:
    """Assemble an approval for a plan, refusing a plan that fails its own hash.

    The hash check is here rather than only at apply time so that approving a
    tampered plan is impossible, instead of merely useless. An approval naming a
    hash the plan does not have would be refused later -- but it would also look
    like a legitimate approval sitting on disk until someone tried to use it.
    """
    lifecycle.verify_plan_hash(plan)
    operation = plan.get("operation")
    if not operation:
        raise ApprovalError("plan declares no operation; nothing to approve")
    approval = {"schema_version": 1, "plan_hash": plan["plan_hash"],
                "operation": operation, "approved_by": approved_by,
                "approved_at": approved_at}
    if reason:
        approval["reason"] = reason
    lifecycle.validate(approval, lifecycle.load_schema("approval.schema.json"))
    return approval


def write_approval(path: Path, approval: dict) -> Path:
    """Write mode 0600, created that way rather than chmod'ed afterwards.

    Not because an approval is a secret -- it is not, and it names no
    credential. Because an approval that any process can rewrite is an approval
    that authorizes whatever it was last edited to say.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(approval, indent=2, sort_keys=True) + "\n")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell approve",
        description="Approve one plan by its content hash. Creates nothing, "
                    "spends nothing, and needs no credential.")
    parser.add_argument("--plan-file", required=True, type=Path)
    parser.add_argument("--approved-by", required=True,
                        help="who is approving. Self-asserted and recorded "
                             "verbatim; this is attribution, not authentication")
    parser.add_argument("--approved-at", required=True,
                        help="RFC3339 timestamp, supplied so the same review "
                             "always produces the same artifact")
    parser.add_argument("--reason", default=None)
    parser.add_argument("--out", type=Path, default=None,
                        help="defaults to the plan file with .approval.json in "
                             "place of .json")
    args = parser.parse_args(argv)

    try:
        plan = json.loads(Path(args.plan_file).read_text())
        approval = build_approval(plan, approved_by=args.approved_by,
                                  approved_at=args.approved_at,
                                  reason=args.reason)
        out = args.out or Path(str(args.plan_file).removesuffix(".json")
                               + ".approval.json")
        written = write_approval(out, approval)
        print(json.dumps({"approval": str(written), **approval},
                         indent=2, sort_keys=True))
        return 0
    except json.JSONDecodeError as error:
        print(f"ApprovalError: plan is not valid JSON: {error}", file=sys.stderr)
        return 2
    except FileNotFoundError as error:
        print(f"ApprovalError: {error}", file=sys.stderr)
        return 2
    except LifecycleError as error:
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Report configuration drift without editing anything.

``cinderwell doctor`` validates the live configuration against the packaged
schema, names unrecognised / missing / deprecated fields, and detects a
previous-layout state tree. It never rewrites a configuration to silence a
mismatch. Migration on schema-version bump is a separate confirmed path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cinderwell import lifecycle
from cinderwell import paths


class DoctorError(lifecycle.LifecycleError):
    """Doctor found a problem and refused to claim health."""


def _walk_unrecognised(instance: Any, schema: dict, path: str = "$") -> list[str]:
    found: list[str] = []
    if not isinstance(instance, dict) or not isinstance(schema, dict):
        return found
    props = schema.get("properties") or {}
    additional = schema.get("additionalProperties", True)
    if additional is False:
        for key in instance:
            if key not in props and not str(key).startswith("$"):
                found.append(f"{path}.{key}" if path != "$" else f"$.{key}")
    for key, value in instance.items():
        if key in props:
            child = props[key]
            child_path = f"{path}.{key}" if path != "$" else f"$.{key}"
            if isinstance(value, dict):
                found.extend(_walk_unrecognised(value, child, child_path))
            elif isinstance(value, list) and isinstance(child.get("items"), dict):
                for index, item in enumerate(value):
                    found.extend(
                        _walk_unrecognised(item, child["items"], f"{child_path}[{index}]"))
    return found


def _missing_required(instance: Any, schema: dict, path: str = "$") -> list[str]:
    found: list[str] = []
    if not isinstance(schema, dict):
        return found
    if isinstance(instance, dict):
        for key in schema.get("required") or []:
            if key not in instance:
                found.append(f"{path}.{key}" if path != "$" else f"$.{key}")
        props = schema.get("properties") or {}
        for key, value in instance.items():
            if key in props:
                child_path = f"{path}.{key}" if path != "$" else f"$.{key}"
                found.extend(_missing_required(value, props[key], child_path))
    return found


def detect_legacy_layout(cwd: Path | None = None) -> list[str]:
    """Working-directory state files that predate the XDG layout.

    Config and state are machine-scoped, not project-scoped: a `config.json`
    sitting in whatever directory the operator happened to run from is state
    the reaper -- which runs from somewhere else entirely -- will never read.
    Naming it is the difference between "no host is leased" and "no host is
    leased *here*".
    """
    root = cwd if cwd is not None else Path.cwd()
    hits: list[str] = []
    candidates = [
        root / "config.json",
        root / "state.json",
        root / "runtime" / "state.json",
    ]
    for path in candidates:
        if path.exists():
            hits.append(str(path))
    return hits


def examine(config_path: Path, *, state_path: Path | None = None) -> dict:
    """Return a structured doctor report. Never mutates the filesystem."""
    schema = lifecycle.load_schema("config.schema.json")
    report: dict[str, Any] = {
        "config_path": str(config_path),
        "ok": True,
        "errors": [],
        "warnings": [],
        "unrecognised_fields": [],
        "missing_fields": [],
        "legacy_layout": detect_legacy_layout(),
    }
    if report["legacy_layout"]:
        report["ok"] = False
        report["errors"].append(
            "previous-layout paths still present; copy into the machine config/"
            "state roots then remove the repo-local copies after verification: "
            + ", ".join(report["legacy_layout"]))

    if not config_path.exists():
        report["ok"] = False
        report["errors"].append(f"configuration not found: {config_path}")
        return report

    try:
        raw = json.loads(config_path.read_text())
    except json.JSONDecodeError as error:
        report["ok"] = False
        report["errors"].append(f"configuration is not valid JSON: {error}")
        return report

    packaged_version = schema.get("properties", {}).get("schema_version", {}).get("const")
    live_version = raw.get("schema_version")
    if packaged_version is not None and live_version != packaged_version:
        report["ok"] = False
        report["errors"].append(
            f"schema_version mismatch: configuration has {live_version!r}, "
            f"packaged schema requires {packaged_version!r}")

    report["unrecognised_fields"] = _walk_unrecognised(raw, schema)
    report["missing_fields"] = _missing_required(raw, schema)
    if report["unrecognised_fields"] or report["missing_fields"]:
        report["ok"] = False
        for field in report["unrecognised_fields"]:
            report["errors"].append(f"unrecognised field: {field}")
        for field in report["missing_fields"]:
            report["errors"].append(f"missing required field: {field}")

    # Full semantic validation when structure is intact enough.
    if report["ok"] or (not report["missing_fields"] and live_version == packaged_version):
        try:
            lifecycle.load_config(config_path)
        except lifecycle.ConfigError as error:
            report["ok"] = False
            report["errors"].append(str(error))

    if state_path is not None and state_path.exists():
        try:
            config = lifecycle.load_config(config_path)
            lifecycle.load_state(state_path, lifecycle.digest(config))
        except (lifecycle.ConfigError, lifecycle.StateError) as error:
            report["ok"] = False
            report["errors"].append(str(error))

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell doctor",
        description="Validate cinderwell configuration against the installed schema. "
                    "Reports only; does not edit configuration.")
    parser.add_argument("--config", type=Path, default=None,
                        help="configuration file (default: XDG machine path)")
    parser.add_argument("--state", type=Path, default=None,
                        help="optional host state file to bind-check")
    parser.add_argument("--migrate", action="store_true",
                        help="reserved: schema-version migration (requires confirmation)")
    parser.add_argument("--yes", action="store_true",
                        help="confirm a migration (with --migrate)")
    args = parser.parse_args(argv)

    if args.migrate:
        if not args.yes:
            sys.stderr.write(
                "doctor --migrate requires --yes after reviewing the planned "
                "rewrite; refusing so the original stays byte-identical\n")
            return 2
        sys.stderr.write(
            "doctor --migrate: no schema-version migration is defined yet\n")
        return 2

    config_path = paths.resolve_config_path(args.config)
    # Always bind-check the machine host state when present; explicit --state
    # still wins. Omitting --state must not skip a digest mismatch on the
    # default path.
    state_path = paths.resolve_state_path(args.state)
    report = examine(config_path, state_path=state_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

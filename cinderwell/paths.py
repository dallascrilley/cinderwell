"""Machine-scoped configuration and state locations (XDG).

Explicit ``--config`` / ``--state`` always win. Defaults follow the XDG Base
Directory Specification with factory-specific suffixes documented in the plan:

* config: ``$XDG_CONFIG_HOME/cinderwell/config.json``
  (default ``~/.config/cinderwell/config.json``)
* state root: ``$XDG_STATE_HOME/cinderwell/``
  (default ``~/.local/state/cinderwell/``)
* per-run state: ``<state-root>/<run-id>/host.json``
* per-run preview: ``<state-root>/<run-id>/preview.json``

Paths inside machine configuration must be absolute; callers refuse relatives.
"""

from __future__ import annotations

import os
from pathlib import Path

CONFIG_BASENAME = "config.json"
HOST_STATE_BASENAME = "host.json"
PREVIEW_STATE_BASENAME = "preview.json"
PACKAGE = "cinderwell"


class PathError(ValueError):
    """A resolved path is unusable or a relative path was refused."""


def _home() -> Path:
    return Path.home()


def xdg_config_home() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME")
    if raw:
        return Path(raw).expanduser()
    return _home() / ".config"


def xdg_state_home() -> Path:
    raw = os.environ.get("XDG_STATE_HOME")
    if raw:
        return Path(raw).expanduser()
    return _home() / ".local" / "state"


def default_config_path() -> Path:
    return xdg_config_home() / PACKAGE / CONFIG_BASENAME


def default_state_root() -> Path:
    return xdg_state_home() / PACKAGE


def run_state_dir(run_id: str, *, state_root: Path | None = None) -> Path:
    if not run_id or "/" in run_id or run_id in {".", ".."}:
        raise PathError(f"run id is not a single path segment: {run_id!r}")
    root = state_root if state_root is not None else default_state_root()
    return root / run_id


def default_host_state_path(run_id: str | None = None,
                            *, state_root: Path | None = None) -> Path:
    """Host lifecycle state file.

    When ``run_id`` is None, returns the legacy single-file location under the
    state root (``host.json``) used when the operator has not scoped a run.
    """
    if run_id is None:
        root = state_root if state_root is not None else default_state_root()
        return root / HOST_STATE_BASENAME
    return run_state_dir(run_id, state_root=state_root) / HOST_STATE_BASENAME


def default_preview_state_path(run_id: str,
                               *, state_root: Path | None = None) -> Path:
    return run_state_dir(run_id, state_root=state_root) / PREVIEW_STATE_BASENAME


def resolve_config_path(explicit: Path | str | None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    return default_config_path()


def resolve_state_path(explicit: Path | str | None,
                       *, run_id: str | None = None) -> Path:
    if explicit is not None:
        return Path(explicit).expanduser()
    return default_host_state_path(run_id)


def require_absolute(path: Path | str, *, field: str) -> Path:
    """Refuse relative paths in machine configuration (cwd must not matter)."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise PathError(
            f"{field} must be an absolute path; refusing to resolve "
            f"{path!r} against the working directory")
    return candidate

#!/usr/bin/env python3
"""Read-only lifecycle planning for Cinderwell hosts (unit S2).

This module creates and deletes nothing. It reads provider state, prices a
proposed server, and emits an immutable hash-bound plan that a later unit (S3)
may apply. There is deliberately no `--apply` code path here: the absence of a
mutation verb is the safety property, not a flag that could be set by mistake.

Three rules shape everything below.

1. Absent evidence is `NOT_VERIFIED`, never success. A surface that cannot be
   read produces a typed unavailable result. Empty output from a command that
   failed is never reported as "no resources".
2. Plans are content-addressed. The hash covers every input that could change
   what gets created, so an operator can re-derive it and a later apply can
   refuse anything stale.
3. Secrets never enter this process's outputs. The API token is inherited from
   the environment and is never logged, hashed into a plan, or written to state.

Standard library only, by design: this design chose the `hcloud` CLI behind
one stdlib command rather than a second declarative state engine.
"""

from __future__ import annotations

import argparse
from cinderwell import paths
import importlib.resources
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

# Schemas ship as package data. SCHEMA_DIR remains a Path for callers that
# open templates by name (cloud-init, reaper plist); it points at the
# installed resources tree, never at a repository checkout.
def _resources() -> importlib.resources.abc.Traversable:
    return importlib.resources.files("cinderwell.resources")


def resource_text(name: str) -> str:
    """Read a packaged schema or template by basename."""
    try:
        return _resources().joinpath(name).read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise FileNotFoundError(
            f"cinderwell package is missing resource {name!r}"
        ) from error


# Backward-compatible name: Path used only when a caller still wants a
# filesystem path. Prefer resource_text / load_schema.
SCHEMA_DIR = Path(str(_resources()))
PRICING_URL = "https://api.hetzner.cloud/v1/pricing"
COMMAND_TIMEOUT_SECONDS = 30

# Surfaces this simplified path inventories. A fuller production path enumerates
# more; these are the ones an ephemeral source-only host can actually create or
# collide with. Anything outside this set is out of scope and is reported as
# such rather than silently assumed absent.
INVENTORY_SURFACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("servers", ("server", "list")),
    ("volumes", ("volume", "list")),
    ("primary_ips", ("primary-ip", "list")),
    ("floating_ips", ("floating-ip", "list")),
    ("firewalls", ("firewall", "list")),
    ("ssh_keys", ("ssh-key", "list")),
    ("snapshots", ("image", "list", "--type", "snapshot")),
)


# ── Errors ────────────────────────────────────────────────────────────────────

class LifecycleError(Exception):
    """Base class. Every failure here is typed so callers never guess."""


class SchemaError(LifecycleError):
    """An instance did not match its declared schema."""


class ConfigError(LifecycleError):
    """Configuration is structurally or semantically unusable."""


class StateError(LifecycleError):
    """Recorded state is missing, corrupt, or has gone backwards."""


class PlanError(LifecycleError):
    """A plan cannot be produced safely. Never means 'produced an empty plan'."""


class SurfaceUnavailable(LifecycleError):
    """A read failed. Maps to NOT_VERIFIED, never to an empty success."""


class ApprovalError(LifecycleError):
    """Authority to apply a plan is absent, malformed, or names another plan."""


class LeaseError(LifecycleError):
    """An expiry cannot be established, or a host has outlived one."""


# ── Canonical hashing ─────────────────────────────────────────────────────────

def canonical_json(value: Any) -> str:
    """Serialize so that key order can never change a digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


# ── Redaction ─────────────────────────────────────────────────────────────────

# Applied to any provider output before it can reach an error message, a
# receipt, or the console. Secret-fetching commands in configuration are
# intentionally NOT redacted: they are pointers, and showing them is how an
# operator debugs a wrong path.
_SECRET_PATTERNS = (
    re.compile(r"tskey-[A-Za-z0-9\-]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"\b[A-Za-z0-9]{40,}\b"),
)


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


# ── Minimal JSON Schema validation ────────────────────────────────────────────

# A deliberately small subset: enough to make the committed schemas load-bearing
# without taking a dependency. Unsupported keywords are ignored rather than
# silently treated as satisfied-by-default in a way that could hide a mismatch,
# so the schemas only use keywords implemented here.
_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _type_ok(value: Any, expected: Any) -> bool:
    # Draft-07 allows a list of alternatives. Without this branch a union type
    # raises TypeError deep inside the validator instead of validating, which
    # would look like a broken schema rather than a satisfied one.
    if isinstance(expected, list):
        return any(_type_ok(value, alternative) for alternative in expected)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    python_type = _TYPES.get(expected)
    if python_type is None:
        return True
    if python_type is not bool and isinstance(value, bool):
        return False
    return isinstance(value, python_type)


def validate(instance: Any, schema: dict, *, root: dict | None = None,
             path: str = "$") -> None:
    """Raise SchemaError on the first mismatch, naming the exact path."""
    root = root if root is not None else schema

    if "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/"):
            raise SchemaError(f"{path}: only local $ref is supported")
        target: Any = root
        for part in reference[2:].split("/"):
            target = target[part]
        validate(instance, target, root=root, path=path)
        return

    if "const" in schema and instance != schema["const"]:
        raise SchemaError(f"{path}: expected {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaError(f"{path}: {instance!r} is not one of {schema['enum']}")

    if "type" in schema and not _type_ok(instance, schema["type"]):
        raise SchemaError(f"{path}: expected type {schema['type']}, got "
                          f"{type(instance).__name__}")

    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if pattern is not None and not re.search(pattern, instance):
            raise SchemaError(f"{path}: {instance!r} does not match {pattern}")
        minimum_length = schema.get("minLength")
        if minimum_length is not None and len(instance) < minimum_length:
            raise SchemaError(f"{path}: shorter than minLength {minimum_length}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            raise SchemaError(f"{path}: {instance} is below minimum {minimum}")
        maximum = schema.get("maximum")
        if maximum is not None and instance > maximum:
            raise SchemaError(f"{path}: {instance} is above maximum {maximum}")

    if isinstance(instance, list):
        minimum_items = schema.get("minItems")
        if minimum_items is not None and len(instance) < minimum_items:
            raise SchemaError(f"{path}: fewer than minItems {minimum_items}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate(item, item_schema, root=root, path=f"{path}[{index}]")

    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                raise SchemaError(f"{path}: missing required property {required!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], root=root, path=f"{path}.{key}")
                continue
            extra = schema.get("additionalProperties", True)
            if extra is False:
                raise SchemaError(f"{path}: unknown property {key!r}")
            if isinstance(extra, dict):
                validate(value, extra, root=root, path=f"{path}.{key}")

    # Conditional composition. Kept minimal and additive: no schema shipped
    # before this used allOf/if/then, so existing validation is unchanged, and
    # the trust receipt needs exactly this to require a fact on one operation
    # and not the other. `if` is a probe, not an assertion -- a mismatch selects
    # the `else` branch rather than failing the instance.
    for subschema in schema.get("allOf", []):
        validate(instance, subschema, root=root, path=path)

    if "if" in schema:
        try:
            validate(instance, schema["if"], root=root, path=path)
        except SchemaError:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            validate(instance, branch, root=root, path=path)


def load_schema(name: str) -> dict:
    return json.loads(resource_text(name))


# ── Configuration ─────────────────────────────────────────────────────────────

def load_config(path: Path) -> dict:
    """Load, validate, and semantically check configuration.

    The schema catches shape. This function catches the things a schema cannot
    express but that would be dangerous to accept.
    """
    try:
        config = json.loads(Path(path).read_text())
    except FileNotFoundError as error:
        raise ConfigError(f"configuration not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ConfigError(f"configuration is not valid JSON: {error}") from error

    try:
        validate(config, load_schema("config.schema.json"))
    except SchemaError as error:
        raise ConfigError(str(error)) from error

    envelope = config["spend_envelope"]
    if envelope["max_hourly"] <= 0 or envelope["max_monthly"] <= 0:
        raise ConfigError("spend envelope must permit a non-zero amount; a zero "
                          "ceiling would silently block every plan")
    if envelope["max_monthly"] < envelope["max_hourly"]:
        raise ConfigError("monthly ceiling is below the hourly ceiling")

    _reject_secret_shaped_values(config)
    return config


# An SSH *public* key by construction: a known key type, then base64, then an
# optional comment. Private keys are PEM and never match this. Exempted because
# pinning a remote's public host keys is the alternative to trust-on-first-use,
# and a scanner that refuses them pushes an operator toward the unsafe option.
_PUBLIC_KEY = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-[A-Za-z0-9-]+) "
    r"[A-Za-z0-9+/]+=*(\s+\S.*)?$")


def _reject_secret_shaped_values(node: Any, path: str = "$") -> None:
    """Refuse a config that carries a literal credential.

    A command that fetches a secret is a pointer and is allowed, because it is
    argv rather than a value. A value that looks like the credential itself is
    not, because committing this file is the normal case.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            _reject_secret_shaped_values(value, f"{path}.{key}")
        return
    if isinstance(node, list):
        for index, value in enumerate(node):
            _reject_secret_shaped_values(value, f"{path}[{index}]")
        return
    if not isinstance(node, str):
        return
    if _PUBLIC_KEY.match(node.strip()) or _PUBLIC_KEY.match(
            node.strip().split(" ", 1)[-1] if " " in node.strip() else ""):
        return
    if redact(node) != node:
        raise ConfigError(f"{path}: value looks like a credential; store a "
                          f"command that fetches it instead")


# ── State ─────────────────────────────────────────────────────────────────────

def empty_state(config_digest: str) -> dict:
    return {"schema_version": 1, "generation": 0,
            "config_digest": config_digest, "primary": {"phase": "ABSENT"}}



def discover_alternate_host_states(default_state: Path) -> list[str]:
    """Host state files under the machine state root that are not the default.

    Used only to refuse a silent ABSENT when another record still names a live
    host. Never synthesizes state from these paths.
    """
    root = Path(default_state).expanduser().parent
    if not root.is_dir():
        return []
    hits: list[str] = []
    default = Path(default_state).expanduser().resolve()
    for path in sorted(root.rglob(paths.HOST_STATE_BASENAME)):
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved == default:
            continue
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            hits.append(str(path))
            continue
        phase = (payload.get("primary") or {}).get("phase")
        if phase and phase != "ABSENT":
            hits.append(str(path))
    return hits


def load_state(path: Path, config_digest: str) -> dict:
    """Load state, or synthesize the ABSENT starting state if none exists.

    A generation that has gone backwards is refused rather than repaired: a
    rollback means some other process wrote state we have not seen, and guessing
    which one is authoritative is exactly how duplicate servers get created.
    """
    state_path = Path(path)
    if not state_path.exists():
        return empty_state(config_digest)
    try:
        state = json.loads(state_path.read_text())
    except json.JSONDecodeError as error:
        raise StateError(f"state is not valid JSON: {error}") from error

    try:
        validate(state, load_schema("state.schema.json"))
    except SchemaError as error:
        raise StateError(str(error)) from error

    if state["config_digest"] != config_digest:
        raise StateError("state was written under a different configuration; "
                         "every recorded plan hash is invalid")
    return state


def assert_generation_advances(previous: dict, candidate: dict) -> None:
    if candidate["generation"] <= previous["generation"]:
        raise StateError(f"state generation must advance: "
                         f"{previous['generation']} -> {candidate['generation']}")


# ── Provider reads ────────────────────────────────────────────────────────────

Runner = Callable[[tuple[str, ...]], "subprocess.CompletedProcess[str]"]


def default_runner(argv: tuple[str, ...]) -> "subprocess.CompletedProcess[str]":
    """Run one bounded hcloud command. The API token is inherited, never passed."""
    return subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=COMMAND_TIMEOUT_SECONDS, check=False)


class Provider:
    """Read-only view of the provider. No method here mutates anything."""

    def __init__(self, context: str | None, runner: Runner | None = None,
                 pricing_reader: Callable[[], dict] | None = None,
                 project_assertion: dict | None = None) -> None:
        self.context = context
        self.project_assertion = project_assertion
        self._runner = runner or default_runner
        self._pricing_reader = pricing_reader or default_pricing_reader

    def _base(self) -> tuple[str, ...]:
        """Build the command prefix.

        A null context means the token is supplied through the environment from
        a secret manager. Passing `--context ''` would not do that: it would
        select a context literally named the empty string.
        """
        return ("hcloud",) if self.context is None else ("hcloud", "--context",
                                                         self.context)

    def _json(self, argv: tuple[str, ...]) -> Any:
        command = (*self._base(), *argv, "-o", "json")
        try:
            result = self._runner(command)
        except FileNotFoundError as error:
            raise SurfaceUnavailable("hcloud CLI is not installed") from error
        except subprocess.TimeoutExpired as error:
            raise SurfaceUnavailable(f"timed out: {' '.join(argv)}") from error
        if result.returncode != 0:
            raise SurfaceUnavailable(redact((result.stderr or "").strip()) or
                                     f"exit {result.returncode}: {' '.join(argv)}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SurfaceUnavailable(f"unparseable output: {' '.join(argv)}") from error

    def verify_account(self) -> None:
        """Prove the credential addresses the intended project, before anything else.

        A context *name* is only a local label. It proves nothing about which
        account a token belongs to, and the S2 finding showed that
        `hcloud --context <missing>` exits 0 while silently falling back to the
        ambient `HCLOUD_TOKEN`. So identity is established by describing a
        sentinel resource and requiring its name to match exactly: a token
        pointing at the wrong project either cannot see that ID at all or sees a
        different resource under it.

        The credential-source check below is a usability guard, not the identity
        proof. The project assertion is the identity proof, and it is required
        in both modes.
        """
        # Refuse a missing assertion before any I/O. A configuration fault
        # should never be discovered halfway through talking to the provider.
        if not self.project_assertion:
            raise ConfigError("no project assertion was supplied; the account "
                              "cannot be identified from a context name alone")

        if self.context is not None:
            try:
                result = self._runner(("hcloud", "context", "active"))
            except FileNotFoundError as error:
                raise SurfaceUnavailable("hcloud CLI is not installed") from error
            except subprocess.TimeoutExpired as error:
                raise SurfaceUnavailable("timed out reading hcloud context") from error
            if result.returncode != 0:
                raise SurfaceUnavailable("cannot read the active hcloud context")
            active = (result.stdout or "").strip()
            if active != self.context:
                raise SurfaceUnavailable(
                    f"active hcloud context is {active!r}, configuration expects "
                    f"{self.context!r}")
        elif not os.environ.get("HCLOUD_TOKEN", ""):
            raise SurfaceUnavailable(
                "configuration uses the ambient credential (hcloud_context is "
                "null) but HCLOUD_TOKEN is not set")

        self.verify_project()

    def verify_project(self) -> None:
        """Describe the sentinel firewall and require an exact name match."""
        assertion = self.project_assertion
        if not assertion:
            raise ConfigError("no project assertion was supplied; the account "
                              "cannot be identified from a context name alone")
        firewall_id = assertion["firewall_id"]
        described = self._json(("firewall", "describe", str(firewall_id)))
        if not isinstance(described, dict):
            raise SurfaceUnavailable(f"firewall {firewall_id} did not describe "
                                     f"as an object")
        observed = described.get("name")
        if observed != assertion["firewall_name"]:
            raise SurfaceUnavailable(
                f"firewall {firewall_id} is named {observed!r}, configuration "
                f"expects {assertion['firewall_name']!r}; this credential does "
                f"not address the intended project")

    def inventory(self) -> dict:
        """Read every in-scope surface. One failure never fails the others."""
        surfaces: dict[str, dict] = {}
        for name, argv in INVENTORY_SURFACES:
            try:
                items = self._json(argv)
            except SurfaceUnavailable as error:
                surfaces[name] = {"status": "NOT_VERIFIED", "detail": str(error)}
                continue
            if not isinstance(items, list):
                surfaces[name] = {"status": "NOT_VERIFIED",
                                  "detail": "expected a JSON array"}
                continue
            surfaces[name] = {"status": "PASS", "count": len(items),
                              "items": [_summarize(item) for item in items]}
        return surfaces

    def server_type_prices(self, server_type: str) -> list[dict]:
        described = self._json(("server-type", "describe", server_type))
        if not isinstance(described, dict) or "prices" not in described:
            raise SurfaceUnavailable(f"server type {server_type} has no prices")
        return described["prices"]

    def pricing(self) -> dict:
        return self._pricing_reader()


def project_assertion(config: dict) -> dict:
    """The sentinel that binds a credential to one project.

    Derived from configuration rather than passed separately, so no call site
    can construct a Provider that skips the identity proof by omission.
    """
    return {"firewall_id": config["firewall_id"],
            "firewall_name": config["firewall_name"]}


def provider_for(config: dict, **kwargs: Any) -> "Provider":
    return Provider(config["hcloud_context"],
                    project_assertion=project_assertion(config), **kwargs)


def _summarize(item: Any) -> dict:
    """Keep only identity fields. Provider payloads are not receipt material."""
    if not isinstance(item, dict):
        return {"id": None, "name": None}
    return {"id": item.get("id"), "name": item.get("name"),
            "labels": item.get("labels") or {}}


def default_pricing_reader() -> dict:
    """Read the pricing endpoint.

    The CLI does not expose currency or Primary IP pricing, so this is the only
    authoritative source for both. Without it, currency cannot be confirmed and
    a plan must not claim its spend figures are meaningful.
    """
    token = os.environ.get("HCLOUD_TOKEN", "")
    if not token:
        raise SurfaceUnavailable("HCLOUD_TOKEN is not set; pricing is unreadable")
    request = urllib.request.Request(
        PRICING_URL, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=COMMAND_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise SurfaceUnavailable(f"pricing endpoint unreadable: "
                                 f"{type(error).__name__}") from error
    pricing = payload.get("pricing")
    if not isinstance(pricing, dict):
        raise SurfaceUnavailable("pricing response has no pricing object")
    return pricing


# ── Pricing ───────────────────────────────────────────────────────────────────

def _net(entry: dict, key: str) -> float:
    try:
        return float(entry[key]["net"])
    except (KeyError, TypeError, ValueError) as error:
        raise SurfaceUnavailable(f"price field {key} is missing or unparseable") from error


def _price_for_location(prices: list, location: str, label: str) -> dict:
    for entry in prices:
        if isinstance(entry, dict) and entry.get("location") == location:
            return entry
    raise SurfaceUnavailable(f"{label} is not priced in location {location}")


def compute_spend(config: dict, provider: Provider) -> dict:
    """Price every billable resource the plan would create.

    An unpriced resource is refused rather than treated as free. Currency is
    compared against the configured envelope because a numerically small figure
    in the wrong currency is not a small figure.
    """
    location = config["location"]
    envelope = config["spend_envelope"]

    pricing = provider.pricing()
    currency = pricing.get("currency")
    if not currency:
        raise SurfaceUnavailable("pricing response declares no currency")
    if currency != envelope["currency"]:
        raise PlanError(f"provider prices in {currency}, envelope is denominated "
                        f"in {envelope['currency']}")

    server_price = _price_for_location(
        provider.server_type_prices(config["server_type"]), location,
        f"server type {config['server_type']}")
    hourly = _net(server_price, "price_hourly")
    monthly = _net(server_price, "price_monthly")
    lines = [{"resource": f"server:{config['server_type']}",
              "hourly": hourly, "monthly": monthly}]

    if config["public_net"]["enable_ipv4"]:
        ipv4 = next((entry for entry in pricing.get("primary_ips", [])
                     if isinstance(entry, dict) and entry.get("type") == "ipv4"), None)
        if ipv4 is None:
            raise SurfaceUnavailable("primary IPv4 is unpriced")
        ip_price = _price_for_location(ipv4.get("prices", []), location,
                                       "primary IPv4")
        lines.append({"resource": "primary_ip:ipv4",
                      "hourly": _net(ip_price, "price_hourly"),
                      "monthly": _net(ip_price, "price_monthly")})

    total_hourly = round(sum(line["hourly"] for line in lines), 6)
    total_monthly = round(sum(line["monthly"] for line in lines), 6)
    return {
        "currency": currency,
        "lines": lines,
        "hourly": total_hourly,
        "monthly": total_monthly,
        "within_envelope": (total_hourly <= envelope["max_hourly"] and
                            total_monthly <= envelope["max_monthly"]),
    }


# ── Planning ──────────────────────────────────────────────────────────────────

def plan_up(config: dict, state: dict, provider: Provider, run_id: str, *,
            planned_at: str, lease: str | None = None) -> dict:
    """Produce an immutable plan for creating one server. Mutates nothing.

    `run_id` and `planned_at` are explicit inputs rather than things generated
    here, so the same inputs always yield the same hash and an operator can
    re-derive a plan they were shown earlier.

    `planned_at` exists because the plan carries an expiry, and an expiry
    computed from `now()` would make every plan hash unrepeatable. It is also
    the reason the expiry lives in the plan at all: it gets approved along with
    the machine type and the spend, instead of being read separately at reaping
    time from a config that could have moved since.
    """
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", run_id):
        raise PlanError(f"invalid run id: {run_id!r}")
    if state["primary"]["phase"] not in {"ABSENT", "ABSENT_VERIFIED"}:
        raise PlanError(f"primary is in phase {state['primary']['phase']}; a new "
                        f"server may only be planned from an absent state")

    provider.verify_account()

    surfaces = provider.inventory()
    unreadable = sorted(name for name, result in surfaces.items()
                        if result["status"] != "PASS")
    if unreadable:
        raise PlanError(f"cannot plan against unread surfaces: {', '.join(unreadable)}")

    prefix = config["server_name_prefix"]
    existing = [item for item in surfaces["servers"]["items"]
                if str(item.get("name") or "").startswith(prefix)]
    if len(existing) >= config["spend_envelope"]["max_concurrent_servers"]:
        raise PlanError(f"{len(existing)} server(s) already match prefix {prefix!r}; "
                        f"the concurrency ceiling is "
                        f"{config['spend_envelope']['max_concurrent_servers']}")

    firewall_ids = {item.get("id") for item in surfaces["firewalls"]["items"]}
    if config["firewall_id"] not in firewall_ids:
        raise PlanError(f"firewall {config['firewall_id']} does not exist; it must "
                        f"be attached in the create request, not added after boot")

    if not config["ssh"].get("key_ids"):
        raise PlanError(
            "ssh.key_ids is empty; a host created without an authorized key "
            "cannot be provisioned, rehydrated, or torn down through its own "
            "work guards. Refusing at plan time rather than after the machine "
            "exists and is billing.")

    spend = compute_spend(config, provider)
    if not spend["within_envelope"]:
        raise PlanError(
            f"planned spend {spend['hourly']}/h and {spend['monthly']}/mo "
            f"{spend['currency']} exceeds the envelope "
            f"{config['spend_envelope']['max_hourly']}/h and "
            f"{config['spend_envelope']['max_monthly']}/mo")

    body = {
        "operation": "up",
        "schema_version": 1,
        "run_id": run_id,
        "config_digest": digest(config),
        # In the plan, and therefore in the hash, because when this machine
        # stops being allowed to exist is exactly the kind of thing an operator
        # should be approving rather than discovering.
        "lease": lease_for(config, planned_at, lease),
        "server": {
            "name": f"{prefix}-{run_id}",
            "type": config["server_type"],
            "image_id": config["image_id"],
            "location": config["location"],
            "firewall_id": config["firewall_id"],
            "public_net": config["public_net"],
            # In the plan, and therefore in the hash, because who may log into
            # the machine is exactly the kind of thing an operator should be
            # approving rather than discovering.
            "ssh_key_ids": config["ssh"].get("key_ids", []),
            "labels": {"managed-by": "cinderwell", "run-id": run_id},
        },
        "spend": spend,
        "preconditions": {
            "state_generation": state["generation"],
            "surfaces": {name: digest(result["items"])
                         for name, result in sorted(surfaces.items())},
        },
    }
    return {**body, "plan_hash": digest(body)}


def verify_plan_hash(plan: dict) -> None:
    """Recompute the hash so a hand-edited plan cannot be applied later."""
    body = {key: value for key, value in plan.items() if key != "plan_hash"}
    if digest(body) != plan.get("plan_hash"):
        raise PlanError("plan hash does not match plan content")


# ── The lease ─────────────────────────────────────────────────────────────────

# A host that requires somebody to remember to destroy it is not temporary; it
# is permanent with good intentions. So every host carries an expiry, it is set
# at plan time, and it travels inside the plan -- which means it is approved
# alongside the machine type and the spend, rather than configured somewhere it
# could quietly disagree with what was approved.

_DURATION = re.compile(r"^([0-9]+)([smhd])$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str) -> int:
    """`90m`, `4h`, `2d` -> seconds. Refuses anything else.

    A bare number is refused rather than assumed to be seconds: `--lease 4`
    should not silently mean four seconds when every other value in this file
    that reads like a duration is written with its unit.
    """
    match = _DURATION.match(str(value).strip())
    if not match:
        raise LeaseError(f"cannot read {value!r} as a duration; write it as "
                         f"30m, 4h or 2d")
    seconds = int(match.group(1)) * _DURATION_UNITS[match.group(2)]
    if seconds <= 0:
        raise LeaseError("a lease of zero would reap the host before it booted")
    return seconds


def parse_timestamp(value: str) -> datetime:
    """Read one RFC3339 instant, and refuse one with no timezone.

    A naive timestamp compared against an aware one raises deep inside the
    reaper; worse, silently treating it as UTC would make an expiry mean
    different moments on two machines.
    """
    try:
        moment = datetime.fromisoformat(str(value).strip())
    except ValueError as error:
        raise LeaseError(f"cannot read {value!r} as an RFC3339 timestamp") from error
    if moment.tzinfo is None:
        raise LeaseError(f"{value!r} names no timezone, so it names no instant")
    return moment.astimezone(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def lease_for(config: dict, planned_at: str, lease: str | None) -> dict:
    """The lease a plan carries: how long, and the instant it ends.

    `planned_at` is an input rather than `now()` for the same reason `run_id`
    is: the same inputs must always produce the same plan hash, or an operator
    cannot re-derive a plan they were shown earlier.
    """
    settings = config["lease"]
    seconds = (parse_duration(lease) if lease is not None
               else settings["default_seconds"])
    if seconds > settings["max_seconds"]:
        raise LeaseError(
            f"a lease of {seconds}s exceeds this project's ceiling of "
            f"{settings['max_seconds']}s; raise lease.max_seconds deliberately "
            f"if that is really the intent")
    start = parse_timestamp(planned_at)
    return {"seconds": seconds,
            "expires_at": format_timestamp(start + timedelta(seconds=seconds))}


def has_expired(expires_at: str | None, now: str) -> bool:
    """Whether a recorded expiry has passed.

    A host with no recorded expiry is **not** treated as expired. Reaping on
    missing evidence is the same mistake as passing a guard on missing
    evidence, and here it would delete a machine whose lease nobody can read.
    """
    if not expires_at:
        return False
    return parse_timestamp(now) >= parse_timestamp(expires_at)


# ── Authority ─────────────────────────────────────────────────────────────────

# The operator surface used to express authority as `read -r reply < /dev/tty`.
# That gate is load-bearing for a human and impassable for an agent, and it was
# never the security property it looked like: `/dev/tty` proves a human is
# present, not that anyone reviewed anything. The real primitive was already
# here -- plans are content-addressed, and `--apply` requires the exact hash.
#
# So authority becomes a value. It is established once, at the edge, where
# terminal-ness is knowable; it is then bound to one plan and passed inward,
# where every apply path re-checks it. A human at a prompt and an agent carrying
# an approval produce the same kind of record and the same evidence, and neither
# one can be used to apply a plan it does not name.


APPROVAL_HELP = (
    "path to an approval naming this plan's exact hash. Required when there is "
    "no controlling terminal: an unattended run has nobody to confirm at the "
    "prompt, so it carries its authority with it instead. Write one with "
    "`cinderwell approve`.")


def has_controlling_terminal(path: str = "/dev/tty") -> bool:
    """Whether a human could be prompted right now.

    Deliberately `/dev/tty` rather than `sys.stdin.isatty()`: the CLI's
    confirmation prompt reads from `/dev/tty`, so this asks the same question of
    the same device. Testing stdin instead would disagree with the prompt the
    moment a recipe redirected it -- one fact answered two ways, which is the
    defect shape this project keeps finding.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    os.close(descriptor)
    return True


def load_approval(path: Path) -> dict:
    """Read and schema-validate an approval. Binds it to nothing yet."""
    try:
        approval = json.loads(Path(path).read_text())
    except FileNotFoundError as error:
        raise ApprovalError(f"approval not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ApprovalError(f"approval is not valid JSON: {error}") from error
    try:
        validate(approval, load_schema("approval.schema.json"))
    except SchemaError as error:
        raise ApprovalError(f"approval is not a valid approval: {error}") from error
    return approval


def authorize(plan: dict, *, approval_path: Path | None,
              terminal_present: bool) -> dict:
    """Establish the authority under which this plan may be applied.

    Two paths, no third. An approval artifact naming this exact plan, or a
    controlling terminal at which the operator already confirmed the plan's own
    hash. Neither present is a refusal, not a default -- that refusal is the
    whole reason this function exists, because before it the mutating scripts
    would apply a plan for anyone who could name its hash, and the hash is
    printed on screen.
    """
    verify_plan_hash(plan)
    operation = plan.get("operation")

    if approval_path is not None:
        approval = load_approval(approval_path)
        if approval["plan_hash"] != plan["plan_hash"]:
            raise ApprovalError(
                f"approval names plan {approval['plan_hash']} but the plan being "
                f"applied is {plan['plan_hash']}; an approval is bound to the "
                f"exact bytes it was given")
        if approval["operation"] != operation:
            raise ApprovalError(
                f"approval authorizes {approval['operation']!r} but this plan is "
                f"{operation!r}")
        authority = {"kind": "approval", "plan_hash": approval["plan_hash"],
                     "operation": approval["operation"],
                     "approved_by": approval["approved_by"],
                     "approved_at": approval["approved_at"]}
        if approval.get("reason"):
            authority["reason"] = approval["reason"]
        return authority

    if terminal_present:
        return {"kind": "terminal", "plan_hash": plan["plan_hash"],
                "operation": operation}

    raise ApprovalError(
        "no approval was supplied and there is no controlling terminal, so "
        "nothing authorizes this plan. Either run it where an operator can "
        "confirm at the prompt, or write an approval: "
        "cinderwell approve --plan-file PLAN --approved-by WHO")


def assert_authorized(plan: dict, authority: Any) -> None:
    """Re-check, at the mutation, that the authority names *this* plan.

    Called by every apply path rather than trusted from the caller. The check at
    the edge decides *whether* there is authority; this one decides whether the
    authority that arrived belongs to the plan about to be applied. A guard that
    exists only at the entry point is a guard that a second entry point silently
    does without -- and this module has already grown five of them.
    """
    if not isinstance(authority, dict):
        raise ApprovalError("no authority record accompanied this plan")
    schema = load_schema("approval.schema.json")
    try:
        validate(authority, schema["definitions"]["authority"], root=schema)
    except SchemaError as error:
        raise ApprovalError(f"authority record is malformed: {error}") from error
    if authority["plan_hash"] != plan.get("plan_hash"):
        raise ApprovalError(
            f"authority names plan {authority['plan_hash']} but this plan is "
            f"{plan.get('plan_hash')}")
    if authority["operation"] != plan.get("operation"):
        raise ApprovalError(
            f"authority authorizes {authority['operation']!r} but this plan is "
            f"{plan.get('operation')!r}")


# ── Receipts ──────────────────────────────────────────────────────────────────

def build_receipt(run_id: str, operation: str, results: list[dict],
                  recorded_at: str, **extra: Any) -> dict:
    """Assemble a receipt whose verdict can never be better than its worst result."""
    statuses = {entry["status"] for entry in results}
    verdict = "FAIL" if "FAIL" in statuses else (
        "NOT_VERIFIED" if "NOT_VERIFIED" in statuses else "PASS")
    receipt = {"schema_version": 1, "run_id": run_id, "recorded_at": recorded_at,
               "operation": operation, "results": results, "verdict": verdict}
    receipt.update({key: value for key, value in extra.items() if value is not None})
    validate(receipt, load_schema("receipt.schema.json"))
    return receipt


# ── Command line ──────────────────────────────────────────────────────────────

def _emit(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cinderwell lifecycle",
        description="Read-only planning for Cinderwell hosts. This "
                    "command creates and deletes nothing.")
    parser.add_argument("--config", type=Path, default=None,
                        help="configuration file (default: "
                             "$XDG_CONFIG_HOME/cinderwell/config.json)")
    parser.add_argument("--state", type=Path, default=None,
                        help="runtime state file (default: "
                             "$XDG_STATE_HOME/cinderwell/host.json); required "
                             "for every command except inventory unless the "
                             "default path is acceptable")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inventory", help="read every in-scope provider surface")
    subparsers.add_parser("status", help="show recorded lifecycle state")
    subparsers.add_parser("validate", help="validate configuration and state only")
    up_parser = subparsers.add_parser("up", help="produce an immutable create plan")
    up_parser.add_argument("--plan", action="store_true", required=True,
                           help="the only supported mode; there is no --apply here")
    up_parser.add_argument("--run-id", required=True)
    up_parser.add_argument("--planned-at", required=True,
                           help="RFC3339 instant the lease is measured from. An "
                                "input rather than now(), so the same plan "
                                "always has the same hash")
    up_parser.add_argument("--lease", default=None, metavar="DURATION",
                           help="how long this host may exist, as 30m/4h/2d. "
                                "Defaults to the project's lease.default_seconds; "
                                "there is no way to ask for no expiry at all")

    args = parser.parse_args(argv)
    args.config = paths.resolve_config_path(args.config)
    state_was_explicit = args.state is not None
    if args.command != "inventory":
        args.state = paths.resolve_state_path(args.state)

    # Synthesizing ABSENT when `--state` was omitted made `status` report that
    # nothing existed while a server was running, which is the most dangerous
    # answer a status command can give. `inventory` is the only command that
    # asks a question state does not participate in. Defaults name a concrete
    # machine path; that path may honestly be missing only when no previous-
    # layout record is still discoverable.
    try:
        config = load_config(args.config)
        config_digest = digest(config)

        if args.command == "inventory":
            return _emit(provider_for(config).inventory())

        if (not state_was_explicit
                and not Path(args.state).exists()):
            blockers: list[str] = []
            blockers.extend(discover_alternate_host_states(Path(args.state)))
            if blockers:
                raise StateError(
                    "machine host state is absent at "
                    f"{args.state}, but other host records still exist "
                    f"({', '.join(blockers)}). Pass --state explicitly or "
                    "migrate with cinderwell doctor before trusting ABSENT")

        # A state file that does not exist yet is honestly ABSENT for the named
        # path; a path that was never named used to invent ABSENT while a host
        # ran under another file.
        state = load_state(args.state, config_digest)

        if args.command == "validate":
            return _emit({"config_digest": config_digest, "state_valid": True,
                          "phase": state["primary"]["phase"]})

        if args.command == "status":
            return _emit({"config_digest": config_digest,
                          "generation": state["generation"], "primary": state["primary"]})

        return _emit(plan_up(config, state, provider_for(config), args.run_id,
                             planned_at=args.planned_at, lease=args.lease))

    except LifecycleError as error:
        print(f"{type(error).__name__}: {redact(str(error))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

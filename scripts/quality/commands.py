#!/usr/bin/env python3
"""NEXT-10 protected command registry: loader, matcher, hasher.

The registry (scripts/quality/commands.json) is the trusted-harness
meta-policy for commands executed on behalf of evaluated candidates:
fixture/task-declared commands are valid only when they match a profile.
Evidence v2 records the registry hash so post-run tampering is detectable.

Stdlib only; imported by quality.py, run-smoke.py and covered by
test_quality.py (including tamper tests).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().parent / "commands.json"


class RegistryError(ValueError):
    """Registry missing, malformed, or command outside policy."""


def load_registry(path=None):
    """Parse and structurally validate the registry. Raises RegistryError."""
    p = Path(path) if path else REGISTRY_PATH
    try:
        doc = json.loads(p.read_text())
    except FileNotFoundError:
        raise RegistryError(f"command registry not found: {p}") from None
    except ValueError as exc:
        raise RegistryError(f"command registry is not valid JSON: {exc}") from None
    if doc.get("schema_version") != 1:
        raise RegistryError(f"unsupported registry schema_version: {doc.get('schema_version')!r}")
    profiles = doc.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise RegistryError("registry has no profiles")
    for name, rules in profiles.items():
        for key in ("exact", "prefix"):
            values = rules.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise RegistryError(f"profile {name!r}.{key} must be a list of strings")
    return doc


def registry_sha256(path=None):
    """Hash of the registry file bytes — the value evidence records."""
    p = Path(path) if path else REGISTRY_PATH
    return hashlib.sha256(p.read_bytes()).hexdigest()


def command_allowed(registry, profile, command):
    """True when command matches the profile's exact or prefix policy.

    Exact match: byte-equal (after rstrip) to an exact entry.
    Prefix match: command starts with the prefix AND the remainder contains
    no shell meta-characters (;&|><`$() beyond simple quoting) — a prefix
    cannot be widened into chaining or substitution.
    """
    command = command.strip()
    if not command:
        return False
    rules = (registry.get("profiles") or {}).get(profile)
    if not rules:
        return False
    if command in [e.rstrip() for e in rules.get("exact", [])]:
        return True
    for prefix in rules.get("prefix", []):
        if command.startswith(prefix):
            rest = command[len(prefix):]
            if re.search(r"[;&|><`]|\$\(|&&|\|\|", rest):
                return False
            return True
    return False

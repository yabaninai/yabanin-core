"""TP-23: deterministic precedence matrix for SDK config resolution.

Precedence: explicit arguments → canonical env → legacy env → deployment
defaults. Empty env values count as absent; whitespace is never trimmed.
Env is always restored via patch.dict; secret values are never asserted
into failure messages.
"""

import os
from unittest.mock import patch

import pytest

from tokenrouter.config import Config

CLEAN_ENV = {"YABANIN_DEPLOY_MODE": "", "YABANIN_REGION": ""}


def make(env=None, **kwargs):
    """Build a Config under a fully controlled environment."""
    merged = dict(CLEAN_ENV)
    merged.update(env or {})
    # patch.dict with clear=True removes HOME-inherited noise; os.environ is
    # restored afterwards, so no test leaks state.
    with patch.dict(os.environ, merged, clear=True):
        return Config(**kwargs)


# --- API key precedence ---


def test_key_explicit_beats_env():
    c = make(
        {"YABANIN_API_KEY": "canonical", "TOKENROUTER_API_KEY": "legacy"},
        api_key="explicit",
    )
    assert c.api_key == "explicit"


def test_key_canonical_beats_legacy():
    c = make({"YABANIN_API_KEY": "canonical", "TOKENROUTER_API_KEY": "legacy"})
    assert c.api_key == "canonical"


def test_key_legacy_when_no_canonical():
    c = make({"TOKENROUTER_API_KEY": "legacy"})
    assert c.api_key == "legacy"


def test_key_none_and_empty_keep_env_fallback():
    assert make({"YABANIN_API_KEY": "canonical"}, api_key=None).api_key == "canonical"
    assert make({"YABANIN_API_KEY": "canonical"}, api_key="").api_key == "canonical"


def test_key_empty_env_counts_as_absent():
    c = make({"YABANIN_API_KEY": "", "TOKENROUTER_API_KEY": "legacy"})
    assert c.api_key == "legacy"


def test_key_missing_error_is_static_no_env_interpolation():
    # The ValueError message is built from constants only — env values
    # (even secret-looking ones left in scope) can never leak into it.
    with pytest.raises(ValueError) as exc:
        make({"SOME_OTHER_SECRET": "do-not-print"}, api_key=None)
    assert str(exc.value) == (
        "API key required: set YABANIN_API_KEY (or legacy "
        "TOKENROUTER_API_KEY) or pass api_key=..."
    )


def test_key_whitespace_preserved_verbatim():
    # Compatibility fixture: whitespace semantics are NOT trimmed silently.
    assert make(api_key="  padded  ").api_key == "  padded  "
    assert make({"YABANIN_API_KEY": " "}).api_key == " "  # truthy, used as-is
    with pytest.raises(ValueError):
        make({})  # no key anywhere


def test_key_all_empty_everywhere_raises():
    with pytest.raises(ValueError):
        make({"YABANIN_API_KEY": "", "TOKENROUTER_API_KEY": ""})


# --- base_url / admin_url precedence ---


def test_urls_explicit_non_none_wins_outright():
    c = make(
        {
            "YABANIN_BASE_URL": "http://canonical",
            "YABANIN_ADMIN_URL": "http://canonical-admin",
            "YABANIN_DEPLOY_MODE": "onprem",
        },
        base_url="http://explicit",
        admin_url="http://explicit-admin",
        api_key="k",
    )
    assert c.base_url == "http://explicit"
    assert c.admin_url == "http://explicit-admin"


def test_urls_explicit_empty_string_keeps_previous_semantics():
    # Any non-None explicit value wins, including "" (documented semantics).
    c = make(base_url="", admin_url="", api_key="k")
    assert c.base_url == ""
    assert c.admin_url == ""


def test_urls_canonical_env_beats_deploy_defaults():
    c = make(
        {
            "YABANIN_DEPLOY_MODE": "onprem",
            "YABANIN_BASE_URL": "http://canonical",
            "YABANIN_ADMIN_URL": "http://canonical-admin",
        },
        api_key="k",
    )
    assert c.base_url == "http://canonical"
    assert c.admin_url == "http://canonical-admin"


def test_urls_empty_env_counts_as_absent():
    c = make({"YABANIN_BASE_URL": "", "YABANIN_ADMIN_URL": ""}, api_key="k")
    assert c.base_url == "https://api.yabanin.io"
    assert c.admin_url == "https://admin.yabanin.io"


# --- deployment defaults (unchanged behavior) ---


@pytest.mark.parametrize(
    "env,base,admin",
    [
        ({}, "https://api.yabanin.io", "https://admin.yabanin.io"),
        ({"YABANIN_DEPLOY_MODE": "onprem"}, "http://localhost:8082", "http://localhost:9086"),
        ({"YABANIN_REGION": "onprem"}, "http://localhost:8082", "https://admin.yabanin.io"),
        ({"YABANIN_DEPLOY_MODE": "saas"}, "https://api.yabanin.io", "https://admin.yabanin.io"),
    ],
)
def test_deployment_defaults_matrix(env, base, admin):
    c = make(env, api_key="k")
    assert c.base_url == base
    assert c.admin_url == admin

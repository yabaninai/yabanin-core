"""Yabanin SDK configuration — auto-detects SaaS vs on-prem.

Precedence (TP-23): explicit arguments → canonical env (`YABANIN_API_KEY`,
`YABANIN_BASE_URL`, `YABANIN_ADMIN_URL`) → legacy env (`TOKENROUTER_API_KEY`)
→ deployment defaults. An EMPTY env value counts as absent. Values are never
trimmed: a whitespace-only credential is preserved verbatim (compatibility
fixtures pin this), it is simply used as-is.
"""

import os

# Canonical environment (TP-23) — takes precedence over the legacy name.
CANONICAL_API_KEY_ENV = "YABANIN_API_KEY"
CANONICAL_BASE_URL_ENV = "YABANIN_BASE_URL"
CANONICAL_ADMIN_URL_ENV = "YABANIN_ADMIN_URL"
# Legacy environment kept for documented backwards compatibility.
LEGACY_API_KEY_ENV = "TOKENROUTER_API_KEY"


def _env(name):
    """Read an env var; an empty value counts as absent (None)."""
    value = os.environ.get(name, "")
    return value if value != "" else None


class Config:
    """Configuration for the Yabanin gateway client.

    Auto-detects deployment mode:
      - On-prem (deploy_mode=onprem or region=onprem): defaults to http://localhost:8082
      - SaaS (default): defaults to https://api.yabanin.io

    URL resolution: an explicit non-None argument wins outright (previous
    semantics preserved, including the empty string); otherwise the canonical
    env (`YABANIN_BASE_URL`/`YABANIN_ADMIN_URL`); otherwise deployment
    defaults. API key: a nonempty explicit key wins; None/"" fall back to
    canonical `YABANIN_API_KEY`, then legacy `TOKENROUTER_API_KEY`.
    """

    def __init__(self, base_url=None, admin_url=None, api_key=None):
        # base_url: explicit (any non-None) > canonical env > deploy default.
        if base_url is None:
            base_url = _env(CANONICAL_BASE_URL_ENV)
        if base_url is None:
            deploy_mode = os.environ.get("YABANIN_DEPLOY_MODE", "saas")
            region = os.environ.get("YABANIN_REGION", "")
            if deploy_mode == "onprem" or region == "onprem":
                self.base_url = "http://localhost:8082"
            else:
                self.base_url = "https://api.yabanin.io"
        else:
            self.base_url = base_url

        # admin_url: explicit (any non-None) > canonical env > deploy default.
        if admin_url is None:
            admin_url = _env(CANONICAL_ADMIN_URL_ENV)
        if admin_url is None:
            deploy_mode = os.environ.get("YABANIN_DEPLOY_MODE", "saas")
            if deploy_mode == "onprem":
                self.admin_url = "http://localhost:9086"
            else:
                self.admin_url = "https://admin.yabanin.io"
        else:
            self.admin_url = admin_url

        # api_key: explicit nonempty > canonical env > legacy env.
        if not api_key:  # None or "" keep the env fallback (documented)
            api_key = _env(CANONICAL_API_KEY_ENV) or _env(LEGACY_API_KEY_ENV) or ""
        self.api_key = api_key
        if not self.api_key:
            raise ValueError(
                "API key required: set YABANIN_API_KEY (or legacy "
                "TOKENROUTER_API_KEY) or pass api_key=..."
            )


def config_from_env():
    return Config()

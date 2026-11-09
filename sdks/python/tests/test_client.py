"""Tests for Yabanin Python SDK."""

import os
from unittest.mock import patch

import httpx
import pytest
import respx


def _client(gw="http://gw.test", admin="http://admin.test"):
    """Build a Client pointed at mock gateways (avoids real network)."""
    from tokenrouter.config import Config
    from tokenrouter.client import Client

    return Client(config=Config(base_url=gw, admin_url=admin, api_key="test-key"))


# --- Config tests (existing) ---


def test_missing_key_raises():
    """Config raises ValueError when no API key is set."""
    with patch.dict(os.environ, {}, clear=True):
        from tokenrouter.config import Config
        with pytest.raises(ValueError, match="API key required"):
            Config()


def test_uses_env_base_url():
    """Config respects base_url override."""
    from tokenrouter.config import Config
    c = Config(base_url="http://custom:9090", api_key="k")
    assert c.base_url == "http://custom:9090"


def test_onprem_auto_detect():
    """On-prem mode defaults to localhost."""
    with patch.dict(os.environ, {"YABANIN_DEPLOY_MODE": "onprem", "TOKENROUTER_API_KEY": "k"}):
        from tokenrouter.config import Config
        c = Config()
        assert c.base_url == "http://localhost:8082"


def test_saas_default():
    """SaaS mode defaults to api.yabanin.io."""
    with patch.dict(os.environ, {"YABANIN_DEPLOY_MODE": "saas", "TOKENROUTER_API_KEY": "k"}, clear=True):
        from tokenrouter.config import Config
        c = Config()
        assert c.base_url == "https://api.yabanin.io"


# --- chat.completions namespace (I1.3 regression) ---


def test_documented_chat_namespace():
    """c.chat.completions.create must exist — the documented OpenAI-like API."""
    c = _client()
    assert hasattr(c.chat, "completions")
    assert hasattr(c.chat.completions, "create")


@respx.mock
def test_chat_completions_create_posts_to_gateway():
    """chat.completions.create POSTs to the gateway /v1/chat/completions."""
    route = respx.post("http://gw.test/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"id": "chatcmpl-1", "choices": []})
    )
    c = _client()
    resp = c.chat.completions.create(model="smart", messages=[{"role": "user", "content": "hi"}])
    assert resp == {"id": "chatcmpl-1", "choices": []}
    assert route.called
    assert route.calls[0].request.url.path == "/v1/chat/completions"


@respx.mock
def test_chat_completions_raises_on_401():
    """A 401 must raise, not silently return the error body as JSON."""
    respx.post("http://gw.test/v1/chat/completions").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    c = _client()
    with pytest.raises(httpx.HTTPStatusError):
        c.chat.completions.create(model="smart", messages=[])


# --- spend (admin analytics) ---


@respx.mock
def test_spend_hits_admin_savings():
    """spend() queries the admin savings endpoint, not the gateway."""
    route = respx.get("http://admin.test/api/analytics/savings").mock(
        return_value=httpx.Response(200, json={"savings_usd": 12.3})
    )
    c = _client()
    resp = c.spend(days=7)
    assert resp == {"savings_usd": 12.3}
    assert route.called


@respx.mock
def test_spend_sends_days_param():
    """spend(days=N) must forward N as the days query parameter."""
    route = respx.get("http://admin.test/api/analytics/savings").mock(
        return_value=httpx.Response(200, json={"savings_usd": 1.0})
    )
    c = _client()
    c.spend(days=30)
    assert route.called
    sent_url = str(route.calls.last.request.url)
    assert "days=30" in sent_url


# --- lineage (admin control plane) ---


@respx.mock
def test_admin_url_passthrough():
    """Client(admin_url=...) must point spend() at the given admin, not the default."""
    route = respx.get("http://my-admin.test/api/analytics/savings").mock(
        return_value=httpx.Response(200, json={"savings_usd": 1.0})
    )
    from tokenrouter.client import Client

    c = Client(base_url="http://gw.test", api_key="k", admin_url="http://my-admin.test")
    assert c.spend() == {"savings_usd": 1.0}
    assert route.called


@respx.mock
def test_lineage_get_hits_admin_api():
    """LineageHelper.get hits admin /api/lineage/{id}."""
    route = respx.get("http://admin.test/api/lineage/req-123").mock(
        return_value=httpx.Response(200, json={"request_id": "req-123", "model": "gpt-4o"})
    )
    from tokenrouter.lineage import LineageHelper
    h = LineageHelper(config=_client().config)
    resp = h.get("req-123")
    assert resp["request_id"] == "req-123"
    assert route.called


@respx.mock
def test_lineage_verify_hits_admin_api():
    """LineageHelper.verify POSTs admin /api/lineage/{id}/verify."""
    route = respx.post("http://admin.test/api/lineage/req-123/verify").mock(
        return_value=httpx.Response(200, json={"verified": True})
    )
    from tokenrouter.lineage import LineageHelper
    h = LineageHelper(config=_client().config)
    resp = h.verify("req-123")
    assert resp == {"verified": True}
    assert route.called


@respx.mock
def test_lineage_get_raises_on_401():
    respx.get("http://admin.test/api/lineage/req-123").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    from tokenrouter.lineage import LineageHelper
    h = LineageHelper(config=_client().config)
    with pytest.raises(httpx.HTTPStatusError):
        h.get("req-123")

"""Contract parity: the SDK error surface against contracts/api-contract.json.

The contract file is the canonical fixture source for every SDK. When the
envelope or the schema_version changes, these tests and the gateway contract
tests fail together (see docs/api/CONTRACT.md).
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from tokenrouter.client import Client
from tokenrouter.config import Config
from tokenrouter.errors import APIError

CONTRACT_PATH = Path(__file__).resolve().parents[3] / "contracts" / "api-contract.json"


def _contract():
    return json.loads(CONTRACT_PATH.read_text())


def _fixtures():
    contract = _contract()
    assert contract["schema_version"] == 1, (
        "schema_version changed — the contract calls that breaking; update "
        "every parity test with the bump"
    )
    return contract["fixtures"]


def _client(gw="http://gw.test", admin="http://admin.test"):
    return Client(config=Config(base_url=gw, admin_url=admin, api_key="test-key"))


@respx.mock
def test_chat_completions_error_envelope_surfaces():
    """A 401 carrying the canonical envelope raises APIError with its fields."""
    fx = _fixtures()["error_401"]
    respx.post("http://gw.test/v1/chat/completions").mock(
        return_value=httpx.Response(401, json=fx)
    )
    c = _client()
    with pytest.raises(APIError) as excinfo:
        c.chat.completions.create(model="smart", messages=[])
    err = excinfo.value
    assert err.status == 401
    assert err.message == fx["error"]["message"]
    assert err.type == fx["error"]["type"]
    assert "invalid api key" in str(err), "the envelope message must reach the exception text"
    assert "401" in str(err), "the HTTP status must reach the exception text"


@respx.mock
def test_spend_error_envelope_surfaces():
    """A 503 carrying the canonical envelope (with code) raises APIError."""
    fx = _fixtures()["error_upstream"]
    respx.get("http://admin.test/api/analytics/savings").mock(
        return_value=httpx.Response(503, json=fx)
    )
    c = _client()
    with pytest.raises(APIError) as excinfo:
        c.spend(days=7)
    err = excinfo.value
    assert err.status == 503
    assert err.message == fx["error"]["message"]
    assert err.code == fx["error"]["code"]


@respx.mock
def test_lineage_error_envelope_surfaces():
    """The lineage helper surfaces the canonical envelope as APIError too."""
    fx = _fixtures()["error_401"]
    respx.get("http://admin.test/api/lineage/req-1").mock(
        return_value=httpx.Response(401, json=fx)
    )
    from tokenrouter.lineage import LineageHelper

    h = LineageHelper(config=_client().config)
    with pytest.raises(APIError) as excinfo:
        h.get("req-1")
    assert excinfo.value.status == 401
    assert excinfo.value.message == fx["error"]["message"]


@respx.mock
def test_non_envelope_error_body_keeps_transport_error():
    """A non-2xx body that is NOT the canonical envelope keeps raising
    httpx.HTTPStatusError — the fallback must not mask unusual bodies."""
    respx.get("http://admin.test/api/analytics/savings").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    c = _client()
    with pytest.raises(httpx.HTTPStatusError):
        c.spend(days=7)

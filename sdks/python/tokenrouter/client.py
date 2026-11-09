"""Yabanin AI gateway client — cost-aware model routing."""

import httpx

from .errors import raise_for_api_error
from .config import Config


class Client:
    """Thin wrapper around the Yabanin OpenAI-compatible API.

    Usage:
        from tokenrouter import Client
        c = Client(api_key="your-key")
        resp = c.chat.completions.create(model="smart", messages=[...])
        spend = c.spend(days=7)
    """

    def __init__(self, config=None, base_url=None, api_key=None, admin_url=None):
        self.config = config or Config(base_url=base_url, api_key=api_key, admin_url=admin_url)
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        # Gateway client: OpenAI-compatible inference endpoint.
        self._http = httpx.Client(
            base_url=self.config.base_url + "/v1",
            headers=headers,
            timeout=30.0,
        )
        # Admin client: analytics, cost, lineage control-plane API.
        self._admin = httpx.Client(
            base_url=self.config.admin_url,
            headers=headers,
            timeout=30.0,
        )
        self.chat = ChatNamespace(self)

    def spend(self, days=7):
        """Fetch cost/savings analytics for the authenticated org.

        Hits the admin savings report endpoint. Raises
        tokenrouter.errors.APIError when the response carries the canonical
        error envelope (contracts/api-contract.json), httpx.HTTPStatusError
        for any other non-2xx — an error body is never returned as JSON.
        """
        resp = self._admin.get("/api/analytics/savings", params={"days": days})
        raise_for_api_error(resp)
        return resp.json()


class ChatNamespace:
    """chat.* namespace mirroring the OpenAI client layout."""

    def __init__(self, client):
        self.completions = Completions(client)


class Completions:
    """chat.completions.* — create() posts to the gateway."""

    def __init__(self, client):
        self._client = client

    def create(self, **kwargs):
        """Create a chat completion. Pass model, messages, stream, etc.

        Mirrors openai.ChatCompletion.create / client.chat.completions.create.
        Raises tokenrouter.errors.APIError when the response carries the
        canonical error envelope (contracts/api-contract.json),
        httpx.HTTPStatusError for any other non-2xx.
        """
        resp = self._client._http.post("/chat/completions", json=kwargs)
        raise_for_api_error(resp)
        return resp.json()

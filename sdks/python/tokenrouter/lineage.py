"""Lineage helper for Yabanin SDK."""

import httpx

from .errors import raise_for_api_error
from .config import Config


class LineageHelper:
    """Verify jurisdictional lineage attestations via the admin control plane.

    Routes match services/admin/handlers/router.go:
      - GET  /api/lineage/{request_id}        -> lookup
      - POST /api/lineage/{request_id}/verify -> verification
    """

    def __init__(self, config=None):
        c = config or Config()
        self._admin = httpx.Client(
            base_url=c.admin_url,
            headers={
                "Authorization": f"Bearer {c.api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    def get(self, request_id):
        """GET lineage by request ID.

        Raises tokenrouter.errors.APIError on a canonical error envelope,
        httpx.HTTPStatusError for any other non-2xx.
        """
        resp = self._admin.get(f"/api/lineage/{request_id}")
        raise_for_api_error(resp)
        return resp.json()

    def verify(self, request_id):
        """POST lineage verification.

        Raises tokenrouter.errors.APIError on a canonical error envelope,
        httpx.HTTPStatusError for any other non-2xx.
        """
        resp = self._admin.post(f"/api/lineage/{request_id}/verify")
        raise_for_api_error(resp)
        return resp.json()

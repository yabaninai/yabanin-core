"""Canonical API error envelope handling.

The wire shape is fixed by contracts/api-contract.json (error_envelope): every
non-2xx JSON body is {"error": {message, type, param?, code?}} — no bare
strings, no nested deviations. Clients may rely on those shapes; changes are
breaking and require a schema_version bump.
"""


class APIError(Exception):
    """A non-2xx response whose body carried the canonical error envelope.

    Attributes mirror the envelope fields; ``status`` is the HTTP status
    code. The exception text carries the status and the envelope message so
    logged tracebacks keep both.
    """

    def __init__(self, status, message, error_type, param=None, code=None):
        self.status = status
        self.message = message
        self.type = error_type
        self.param = param
        self.code = code
        text = f"{status}: {message} (type={error_type}"
        if code is not None:
            text += f", code={code}"
        if param is not None:
            text += f", param={param}"
        text += ")"
        super().__init__(text)


def raise_for_api_error(resp):
    """Raise for a non-2xx response, preferring the canonical envelope.

    A body that parses as the canonical envelope raises APIError with the
    envelope fields; any other non-2xx body falls back to
    httpx.HTTPStatusError so unusual responses keep their transport-level
    semantics.
    """
    if resp.is_success:
        return
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        err = body["error"]
        message = err.get("message")
        error_type = err.get("type")
        if isinstance(message, str) and message and isinstance(error_type, str) and error_type:
            raise APIError(resp.status_code, message, error_type, err.get("param"), err.get("code"))
    resp.raise_for_status()

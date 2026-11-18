# SPDX-License-Identifier: Apache-2.0
"""Provision the disposable demo via the same authenticated API as the dashboard."""
from datetime import datetime, timedelta
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
import re
import time
from urllib.parse import quote, urlencode


class Console:
    def __init__(self, port):
        self.port = port
        self.cookies = SimpleCookie()
        self.org = ""

    def headers(self, method, form):
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        if method != "GET":
            headers["Origin"] = f"http://127.0.0.1:{self.port}"
        # Only send name=value pairs; cookie attributes belong to responses.
        headers["Cookie"] = "; ".join(f"{k}={v.value}" for k, v in self.cookies.items())
        if self.org:
            headers["X-Yabanin-Org-Id"] = self.org
        if "yabanin_csrf_token" in self.cookies:
            headers["X-CSRF-Token"] = self.cookies["yabanin_csrf_token"].value
        return headers

    def request(self, method, path, data=None, *, form=False, expected=(200,)):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=15)
        headers = self.headers(method, form)
        body = urlencode(data) if form else json.dumps(data)
        try:
            conn.request(method, path, body if data is not None else None, headers)
            response = conn.getresponse()
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    self.cookies.load(value)
            raw = response.read()
            if response.status not in expected:
                raise ValueError(f"dashboard {method} {path} returned {response.status}")
            return response.status, raw
        finally:
            conn.close()

    def get(self, path):
        return json.loads(self.request("GET", path)[1])

    def sign_in(self, password, email):
        self.request("GET", "/auth/login")
        self.request("POST", "/auth/login", {"email": email, "password": password,
                     "_csrf": self.cookies["yabanin_csrf_token"].value}, form=True, expected=(302,))
        user = self.get("/api/me")["id"]
        self.org = next((o["id"] for o in self.get("/api/organizations")["data"] if o["slug"] == "seed"), "")
        if not self.org:
            raise ValueError("Seed organization is missing")
        members = f"/api/organizations/{self.org}/members"
        if user not in {m["user_id"] for m in self.get(members)["data"] or []}:
            self.request("POST", members, {"user_id": user, "role": "reader"}, expected=(200, 201))

    def requests_link(self, run_id):
        times = []
        for job in ("docs", "tools", "review", "support"):
            row = self.get(f"/api/organizations/{self.org}/requests/{run_id}-{job}")
            if row["status_code"] != 200 or row["labels"].get("ci.job_name") != job:
                raise ValueError("dashboard request details did not match the sample traffic")
            timestamp = re.sub(r"(?<=:\d{2})\.\d+", "", row["created_at"])
            times.append(datetime.fromisoformat(timestamp.replace("Z", "+00:00")))
        # Explorer time controls use minutes. Include the entire last sample minute.
        start = min(times).replace(second=0, microsecond=0)
        end = max(times).replace(second=0, microsecond=0) + timedelta(minutes=1)
        params = urlencode({"org": self.org, "from": start.isoformat(), "to": end.isoformat()})
        return f"http://127.0.0.1:{self.port}/#requests-explorer?{params}"

    def verify_route(self, request_id, model):
        for _ in range(35):
            status, raw = self.request("GET", f"/api/organizations/{self.org}/requests/{request_id}",
                                       expected=(200, 404))
            if status == 200:
                row = json.loads(raw)
                if (row["model_requested"], row["model_used"], row["status_code"]) != (model, model, 200):
                    raise ValueError("provider probe reached a different model")
                return
            time.sleep(1)
        raise ValueError("provider probe missing from request history")

    def register(self, model, url, key):
        path = "/api/models/" + quote(model, safe="")
        status, _ = self.request("GET", path, expected=(200, 404))
        body = {"model_name": model, "display_name": model, "tier": "smart", "provider": "openai-compat",
                "upstream_url": url, "upstream_api_key": key.decode(), "tier_pool": ["easy", "medium", "hard"]}
        if status == 404:
            self.request("POST", "/api/models", body, expected=(201,))
        else:
            self.request("PUT", path, body)

    def verify_model(self, model, url):
        actual = self.get("/api/models/" + quote(model, safe=""))
        if actual["upstream_url"] != url or not actual["has_key"]:
            raise ValueError("registered model does not match requested configuration")

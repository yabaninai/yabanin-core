# DNS and TLS setup

This is an edge-routing reference for an operator-managed deployment. The public
core does not include a hosted DNS account, a certificate issuer, or an installed
reverse proxy. Start with the [local quickstart](../quickstart.md) for evaluation;
use the [deployment checklist](../runbooks/public-stand-deploy.md) before exposing
an instance outside the host.

## Choose the public origins

Two origins are sufficient for a typical deployment:

| Example origin | Routes | Private backend |
| --- | --- | --- |
| `api.example.com` | `/v1/...` and gateway `/healthz` | Gateway, normally port 8082 |
| `console.example.com` | `/api/...`, `/auth/...`, dashboard assets and client routes | Admin API on port 8086 plus a separately built dashboard |

The admin service serves authentication pages and JSON APIs; port 8086 does not
serve the React dashboard. Keeping the dashboard, `/auth`, and `/api` on the same
origin avoids a separate cross-origin cookie deployment. A third origin for a
website or documentation is optional. These hostnames are examples, not defaults
that the gateway discovers from DNS.

Create A records for the edge IPv4 address and, only if configured end to end,
AAAA records for IPv6. Configure the application's public admin origin/cookie
settings for the chosen host. Check [OIDC SSO](../sso-oidc.md) when callback URLs are used.

## Reverse-proxy reference

For example, the following Caddy configuration assumes **Caddy runs on the host**,
the two application ports are reachable on host loopback, and the dashboard build
has already been installed in `/srv/yabanin-dashboard`:

```caddyfile
api.example.com {
    reverse_proxy 127.0.0.1:8082
}

console.example.com {
    handle /api/* {
        reverse_proxy 127.0.0.1:8086
    }
    handle /auth/* {
        reverse_proxy 127.0.0.1:8086
    }
    handle {
        root * /srv/yabanin-dashboard
        try_files {path} /index.html
        file_server
    }
}
```

This follows the [Caddy SPA and proxy patterns](https://caddyserver.com/docs/caddyfile/patterns#single-page-apps-spas).
It is an operator configuration example, not a bundled installation command.
Containerized proxies must use their actual network/service addresses; their
`127.0.0.1` is not the host. Review proxy timeouts and response buffering with a
streaming request. Never publish PostgreSQL, Redis, profiling, or metrics ports
through this public route configuration.

Configure your chosen proxy's certificate issuer and renewal mechanism. For ACME
HTTP validation, the domain must resolve to the proxy and port 80 must be
reachable; other challenge methods have different prerequisites. Test config
validation and certificate renewal using your proxy's tooling before relying on
unattended operation. For Caddy, review the [automatic HTTPS prerequisites](https://caddyserver.com/docs/automatic-https).

## Verify each boundary

Set the actual hostnames before running these examples:

```bash
API_HOST=api.example.com
CONSOLE_HOST=console.example.com
dig +short "$API_HOST" A
dig +short "$CONSOLE_HOST" A
curl --fail-with-body --show-error --silent "https://$API_HOST/healthz"
curl --fail-with-body --show-error --silent \
  "https://$CONSOLE_HOST/auth/login" -o /dev/null
curl --fail-with-body --show-error --silent \
  "https://$CONSOLE_HOST/" -o /dev/null
```

Use a trusted certificate without `curl -k`. A successful health response does
not establish authenticated inference. Repeat the quickstart's model listing
and chat request against `https://$API_HOST`; then log in through the console,
verify a protected API request, log out, and confirm the session is rejected.
Check a dashboard deep link after a browser refresh to exercise the SPA fallback.

If DNS succeeds but TLS fails, inspect the certificate hostname, chain, expiry,
proxy logs, firewall and issuer challenge result. If HTML loads but login fails,
inspect the `/auth` and `/api` routes, public origin and cookie attributes. If
streaming stalls, compare a direct private gateway request with the proxied
request and inspect proxy buffering/timeouts. Redact keys, cookies and request
content before sharing diagnostics.

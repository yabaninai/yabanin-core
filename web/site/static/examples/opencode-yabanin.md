# OpenCode through Yabanin

Use `opencode.json` as a starting point for an OpenAI-compatible provider.
Set `YABANIN_OPENAI_BASE_URL` to your gateway URL ending in `/v1` and
`YABANIN_GATEWAY_API_KEY` to an organization or agent key issued for your deployment.
Replace both occurrences of `YOUR_MODEL_ID` with a model returned by your gateway's
`GET /v1/models` endpoint. Keep credentials in environment variables, not in this file.

The local quickstart uses `http://127.0.0.1:8086/v1`. Its mock model checks gateway
connectivity; configure a real provider and model before using it for coding tasks.
Use HTTPS when connecting over a network.

This configuration routes model requests through Yabanin. File access, shell commands
and other local tools remain controlled by OpenCode and your workspace permissions.
It does not enable delegation bridges or change agent approval settings.

See the [OpenCode guide](https://yabanin.ai/docs/clients/opencode) for current
compatibility limits and the [provider guide](https://yabanin.ai/docs/providers)
for upstream configuration. Verify streaming and tool calls with the client version
you intend to use; a successful model-list request alone does not test those features.

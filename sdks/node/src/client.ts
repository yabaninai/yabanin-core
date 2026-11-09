import { BASE_URL, ADMIN_URL, API_KEY } from "./config.js";

export interface ClientConfig {
  baseUrl?: string;
  adminUrl?: string;
  apiKey?: string;
}

/**
 * Options for {@link Client.chat}.
 */
export interface ChatOptions {
  /**
   * Provider-extension fields merged into the top-level request body
   * (extra_body semantics), mirroring the Go SDK's `ChatRequest.Extra`
   * (sdks/go/yabanin.go, N07-P01-T04): keys are merged verbatim into the
   * body top level and take precedence over same-named typed fields
   * (`messages`, `model`). The `extraBody` key itself never appears on
   * the wire.
   *
   * Values serialize through JSON.stringify. For byte-exact extension
   * values — e.g. integer literals beyond Number.MAX_SAFE_INTEGER, which
   * the Go SDK preserves via json.RawMessage — pass `JSON.rawJSON(...)`
   * (Node >= 21) instead of a JS number.
   */
  extraBody?: Record<string, unknown>;
}

export class Client {
  private baseUrl: string;
  private adminUrl: string;
  private apiKey: string;

  constructor(config?: ClientConfig) {
    this.baseUrl = config?.baseUrl || BASE_URL;
    this.adminUrl = config?.adminUrl || ADMIN_URL;
    this.apiKey = config?.apiKey || API_KEY;
    if (!this.apiKey) {
      throw new Error("API key required: set YABANIN_API_KEY or pass apiKey");
    }
  }

  /**
   * Create a chat completion against the gateway's OpenAI-compatible endpoint.
   * Throws on any non-2xx (including 401/429/503) instead of returning the
   * error body as if it were a completion.
   *
   * Provider-extension request fields ride `options.extraBody` (top-level
   * merge, typed-field precedence — see {@link ChatOptions}). Unknown
   * top-level response fields need no opt-in: the untyped return value
   * already preserves them, the loose counterpart of the Go SDK's
   * `ChatResponse.Extra` capture.
   */
  async chat(
    messages: Array<{ role: string; content: string }>,
    model?: string,
    options?: ChatOptions,
  ): Promise<any> {
    const resp = await fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      // Typed fields first, extraBody spread last: an explicit extension
      // key overrides a same-named typed field, matching ChatRequest.Extra
      // merge semantics on the Go SDK. Without extraBody the body is
      // byte-identical to the previous {messages, model} shape.
      body: JSON.stringify({ messages, model, ...options?.extraBody }),
    });
    if (!resp.ok) {
      throw new Error(`chat failed: ${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }
    return resp.json();
  }

  /**
   * Fetch cost/savings analytics from the admin control plane.
   * Hits the real admin endpoint (/api/analytics/savings).
   */
  async spend(days = 7): Promise<any> {
    const resp = await fetch(`${this.adminUrl}/api/analytics/savings?days=${days}`, {
      headers: { "Authorization": `Bearer ${this.apiKey}` },
    });
    if (!resp.ok) {
      throw new Error(`spend failed: ${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }
    return resp.json();
  }
}

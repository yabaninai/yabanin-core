import { ADMIN_URL, API_KEY } from "./config.js";

export class LineageHelper {
  private adminUrl: string;
  private apiKey: string;

  constructor(config?: { adminUrl?: string; apiKey?: string }) {
    this.adminUrl = config?.adminUrl || ADMIN_URL;
    this.apiKey = config?.apiKey || API_KEY;
  }

  /** GET /api/lineage/{id} — lookup an attestation. Throws on non-2xx. */
  async get(requestId: string): Promise<any> {
    const resp = await fetch(`${this.adminUrl}/api/lineage/${requestId}`, {
      headers: { "Authorization": `Bearer ${this.apiKey}` },
    });
    if (!resp.ok) {
      throw new Error(`lineage get failed: ${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }
    return resp.json();
  }

  /** POST /api/lineage/{id}/verify — verify the Ed25519 signature. Throws on non-2xx. */
  async verify(requestId: string): Promise<any> {
    const resp = await fetch(`${this.adminUrl}/api/lineage/${requestId}/verify`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
    });
    if (!resp.ok) {
      throw new Error(`lineage verify failed: ${resp.status} ${resp.statusText}: ${await resp.text()}`);
    }
    return resp.json();
  }
}

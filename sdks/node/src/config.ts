// BR-01: YABANIN_* is canonical; the legacy TOKENROUTER_* names are honored
// as a fallback so existing deployments keep working.
export const BASE_URL = process.env.YABANIN_BASE_URL || process.env.TOKENROUTER_BASE_URL || "https://api.yabanin.io";
export const ADMIN_URL = process.env.YABANIN_ADMIN_URL || process.env.TOKENROUTER_ADMIN_URL || "https://admin.yabanin.io";
export const API_KEY = process.env.YABANIN_API_KEY || process.env.TOKENROUTER_API_KEY || "";

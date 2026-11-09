
import { fetchJSON, postJSON, type RequestOptions } from './http.ts'

// MCP server registry (mcpagg.Server shape; store nil → the server answers 503).
export interface McpServer {
  id: string
  org_id: string
  name: string
  display_name?: string
  url: string
  transport: string
  allowed_tools: string[]
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export async function listMcpServers(orgId: string, opts?: RequestOptions): Promise<McpServer[]> {
  const rows = await fetchJSON<McpServer[] | null>(
    `/organizations/${encodeURIComponent(orgId)}/mcp/servers`, opts)
  return Array.isArray(rows) ? rows : []
}

export async function updateMcpServer(
  orgId: string, name: string, patch: { enabled?: boolean }, opts?: RequestOptions,
): Promise<McpServer> {
  return postJSON<McpServer>(
    `/organizations/${encodeURIComponent(orgId)}/mcp/servers/${encodeURIComponent(name)}`,
    patch, 'PATCH', opts)
}

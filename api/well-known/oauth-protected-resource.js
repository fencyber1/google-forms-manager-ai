// OAuth 2.0 Protected Resource Metadata (RFC 9728) for the MCP server.
// Served publicly at /.well-known/oauth-protected-resource via vercel.json
// rewrites. No secrets here: resource identity and scope names only.
import { issuerIdentifier, resourceIdentifier, MCP_SCOPES } from '../../lib/mcp-oauth.js';

export function protectedResourceMetadata() {
  return {
    resource: resourceIdentifier(),
    authorization_servers: [issuerIdentifier()],
    scopes_supported: MCP_SCOPES.filter((s) => s !== 'offline_access'),
    resource_documentation: `${issuerIdentifier()}/api/health`,
  };
}

export default function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'application/json');
  return res.status(200).json(protectedResourceMetadata());
}

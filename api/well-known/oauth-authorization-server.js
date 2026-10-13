// OAuth 2.0 Authorization Server Metadata (RFC 8414) for the MCP
// authorization server. Served publicly at
// /.well-known/oauth-authorization-server via vercel.json rewrites.
// Advertises CIMD-preferred client registration with public-client (`none`)
// token exchange + mandatory PKCE S256. DCR is also available.
import { issuerIdentifier, resourceIdentifier } from '../../lib/mcp-oauth.js';

export function authorizationServerMetadata() {
  const issuer = issuerIdentifier();
  return {
    issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    scopes_supported: ['forms:read', 'forms:write', 'offline_access'],
  };
}

export function resourceForMetadata() {
  return resourceIdentifier();
}

export default function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'application/json');
  return res.status(200).json(authorizationServerMetadata());
}

// Remote MCP endpoint (Streamable HTTP, stateless).
//
// POST /api/mcp accepts JSON-RPC messages per the MCP Streamable HTTP
// transport. Each request is handled independently with a fresh transport
// and server, which is required on Vercel serverless (no in-memory session
// state survives across invocations).
//
// Authentication: the caller's gfm_session cookie identifies the Google
// account, exactly like the REST endpoints. Unauthenticated callers receive
// MCP error content telling them to connect; no tokens, secrets, or keys
// are ever exposed. This cookie flow does not support ChatGPT remote
// connectors, which require a separate MCP OAuth authorization flow.
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { buildMcpServer, MCP_SERVER_NAME } from '../lib/mcp-server.js';
import { createSupabaseOAuthStore, issuerIdentifier, resourceIdentifier, validateMcpAccessToken } from '../lib/mcp-oauth.js';

function methodNotAllowed(res, message) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(405).json({
    jsonrpc: '2.0',
    id: null,
    error: { code: -32000, message },
  });
}

function wwwAuthenticateHeader(scope) {
  let metadataUrl = '';
  try {
    metadataUrl = `${issuerIdentifier()}/.well-known/oauth-protected-resource`;
  } catch {
    metadataUrl = '';
  }
  return `Bearer resource_metadata="${metadataUrl}"${scope ? `, scope="${scope}"` : ''}`;
}

function bearerChallenge(res, status, error, description, scope) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('WWW-Authenticate', wwwAuthenticateHeader(scope));
  return res.status(status).json({
    jsonrpc: '2.0',
    id: null,
    error: { code: -32000, message: `${error}: ${description}` },
  });
}

function extractBearer(req) {
  const header = req.headers.authorization || req.headers.Authorization;
  if (!header) return { present: false, token: null };
  const match = /^Bearer\s+(.+)$/i.exec(String(header).trim());
  if (!match) return { present: false, token: null };
  return { present: true, token: match[1].trim() };
}

// Validates a supplied Bearer token against server-side records and
// attaches the MCP identity to req.mcpAuth. Returns true when the caller
// may continue, false when this function already answered (401/403).
// Exported for tests; production passes the Supabase store.
export async function authorizeMcpRequest(req, res, store) {
  const bearer = extractBearer(req);
  if (!bearer.present) return true;
  if (!bearer.token) {
    bearerChallenge(res, 401, 'invalid_token', 'A Bearer access token is required.', 'forms:read');
    return false;
  }
  try {
    const identity = await validateMcpAccessToken(store, bearer.token, {
      issuer: issuerIdentifier(),
      resource: resourceIdentifier(),
    });
    req.mcpAuth = { googleSub: identity.googleSub, scopes: identity.scopes, clientId: identity.clientId };
    return true;
  } catch (e) {
    if (e?.code === 'INSUFFICIENT_SCOPE') {
      bearerChallenge(res, 403, 'insufficient_scope', 'Additional permissions are required.', 'forms:read forms:write');
      return false;
    }
    bearerChallenge(res, 401, 'invalid_token', 'Connect your Google account to continue.', 'forms:read');
    return false;
  }
}

function appBaseHost() {
  try {
    return new URL(process.env.APP_BASE_URL).host.toLowerCase();
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    return methodNotAllowed(res, `Use POST for the ${MCP_SERVER_NAME} MCP endpoint.`);
  }

  // DNS-rebinding protection: reject a present-but-foreign Origin header.
  const origin = req.headers.origin;
  const expectedHost = appBaseHost();
  if (origin && expectedHost) {
    try {
      if (new URL(origin).host.toLowerCase() !== expectedHost) {
        return res.status(403).json({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32000, message: 'Forbidden origin.' },
        });
      }
    } catch {
      return res.status(403).json({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32000, message: 'Forbidden origin.' },
      });
    }
  }

  // Vercel parses JSON bodies; accept a raw string too.
  let parsedBody = req.body;
  if (typeof parsedBody === 'string' && parsedBody) {
    try {
      parsedBody = JSON.parse(parsedBody);
    } catch {
      return res.status(400).json({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Request body must be valid JSON-RPC.' },
      });
    }
  }
  if (!parsedBody || typeof parsedBody !== 'object') {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Request body must be a JSON-RPC message.' },
    });
  }

  // Bearer-first authentication. When a Bearer token is supplied it MUST
  // validate: an invalid or expired Bearer token is always rejected with a
  // WWW-Authenticate challenge and NEVER falls back to the cookie session,
  // so a stolen/expired token plus a victim's cookie cannot escalate.
  const bearer = extractBearer(req);
  if (bearer.present) {
    const handled = await authorizeMcpRequest(req, res, createSupabaseOAuthStore());
    if (!handled) return;
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  try {
    const server = buildMcpServer(req);
    await server.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch (e) {
    // Never leak tokens, secrets, or keys in logs or responses.
    console.error('MCP request failed:', e?.message || 'unknown error');
    if (!res.headersSent) {
      return res.status(500).json({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32603, message: 'MCP request failed.' },
      });
    }
  } finally {
    try {
      await transport.close();
    } catch {
      // Cleanup only; transport already answered or failed.
    }
  }
}

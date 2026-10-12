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

function methodNotAllowed(res, message) {
  res.setHeader('Cache-Control', 'no-store');
  return res.status(405).json({
    jsonrpc: '2.0',
    id: null,
    error: { code: -32000, message },
  });
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

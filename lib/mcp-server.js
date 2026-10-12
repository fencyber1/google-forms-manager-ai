// Server-only MCP server factory for Google Forms Manager AI.
//
// Builds a fresh McpServer per request (safe for Vercel serverless: no
// shared state — tool data lives in Supabase/Google, auth in the request).
// Authentication per tool call, in order:
//   1. req.mcpAuth (validated MCP Bearer identity attached by /api/mcp) —
//      resolves the Google client for that exact Google sub.
//   2. Otherwise the session cookie via runAuthenticatedTool's default.
// Tool schemas contain no identity fields, so callers cannot request
// another user's data.
//
// SDK gap: installed @modelcontextprotocol/sdk v1 does not emit
// `securitySchemes` in tools/list. After registering tools we replace the
// tools/list handler (public remove/setRequestHandler API) with a wrapper
// that injects our declared securitySchemes. The discovery test asserts
// their presence, so an SDK upgrade that changes this seam fails loudly
// instead of silently dropping the metadata.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { getAuthenticatedOAuthClient } from './google-connections.js';
import { TOOL_DEFINITIONS, runAuthenticatedTool } from './mcp-tools.js';

export const MCP_SERVER_NAME = 'google-forms-manager-ai';
export const MCP_SERVER_VERSION = '1.0.0';

// `req` is captured per request so each tool invocation authenticates the
// caller of that HTTP request, not a fixed user.
export function buildMcpServer(req) {
  const server = new McpServer({ name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION });
  const bearer = req?.mcpAuth || null;
  const clientResolver = bearer
    ? async () => getAuthenticatedOAuthClient(bearer.googleSub)
    : undefined;
  const grantedScopes = bearer ? bearer.scopes : null;
  for (const tool of TOOL_DEFINITIONS) {
    const config = {
      description: tool.description,
      inputSchema: tool.shape,
      annotations: tool.annotations,
      _meta: tool.meta,
    };
    if (tool.outputShape) config.outputSchema = tool.outputShape;
    server.registerTool(
      tool.name,
      config,
      async (args) => runAuthenticatedTool(req, tool.operation, args, clientResolver, grantedScopes),
    );
  }
  augmentListTools(server);
  return server;
}

function augmentListTools(server) {
  const inner = server?.server;
  if (!inner || typeof inner.removeRequestHandler !== 'function' || typeof inner.setRequestHandler !== 'function') {
    return false;
  }
  const handlers = inner._requestHandlers;
  const original = handlers instanceof Map ? handlers.get('tools/list') : null;
  if (typeof original !== 'function') return false;
  const schemesByName = Object.fromEntries(TOOL_DEFINITIONS.map((t) => [t.name, t.securitySchemes]));
  inner.removeRequestHandler('tools/list');
  inner.setRequestHandler(ListToolsRequestSchema, async (request, extra) => {
    const result = await original(request, extra);
    if (result && Array.isArray(result.tools)) {
      for (const tool of result.tools) {
        if (schemesByName[tool.name]) tool.securitySchemes = schemesByName[tool.name];
      }
    }
    return result;
  });
  return true;
}

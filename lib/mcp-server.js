// Server-only MCP server factory for Google Forms Manager AI.
//
// Builds a fresh McpServer per request (safe for Vercel serverless: no
// shared state — tool data lives in Supabase/Google, auth in the cookie).
// Every tool call resolves the current request's session cookie and operates
// only on that user's Google account. Tool schemas contain no identity
// fields, so callers cannot request another user's data.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { TOOL_DEFINITIONS, runAuthenticatedTool } from './mcp-tools.js';

export const MCP_SERVER_NAME = 'google-forms-manager-ai';
export const MCP_SERVER_VERSION = '1.0.0';

// `req` is captured per request so each tool invocation authenticates the
// caller of that HTTP request, not a fixed user.
export function buildMcpServer(req) {
  const server = new McpServer({ name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION });
  for (const tool of TOOL_DEFINITIONS) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: tool.shape },
      async (args) => runAuthenticatedTool(req, tool.operation, args),
    );
  }
  return server;
}

// Server-only MCP authentication bridge.
//
// Resolves the current cookie-session user to an authenticated Google OAuth2
// client for MCP tool execution. Unlike getAuthenticatedGoogleClient(), this
// never writes an HTTP response — it throws coded errors the MCP server maps
// to safe JSON-RPC error content. It never accepts a user ID or email as an
// identity override: identity always comes from the session cookie.
import { resolveAuthenticatedClient } from './session.js';

export async function resolveMcpClient(req) {
  try {
    return await resolveAuthenticatedClient(req);
  } catch (e) {
    // Re-throw with MCP-safe messages only (no tokens, secrets, or keys).
    const err = new Error(e?.message || 'Could not authenticate with Google. Try reconnecting.');
    err.code = e?.code || 'UPSTREAM';
    throw err;
  }
}

export function toMcpAuthErrorContent(err) {
  if (err?.code === 'UNAUTHENTICATED' || err?.code === 'RECONNECT_REQUIRED') {
    return {
      content: [
        {
          type: 'text',
          text: `${err.message} Complete Google sign-in first, then retry the tool call.`,
        },
      ],
      isError: true,
    };
  }
  return {
    content: [{ type: 'text', text: 'Could not authenticate with Google. Try reconnecting.' }],
    isError: true,
  };
}

// MCP Access Token Validator
//
// Validates opaque MCP access tokens against the token store.
// Throws on failure with coded errors: INVALID, INSUFFICIENT_SCOPE.
import { sha256Hex, createSupabaseOAuthStore } from './mcp-oauth.js';

export async function validateMcpAccessToken(tokenValue, { issuer, resource, requiredScopes = [] }) {
  const fail = (message) => {
    const err = new Error(message);
    err.code = 'INVALID';
    throw err;
  };

  if (typeof tokenValue !== 'string' || !tokenValue) {
    fail('Missing access token.');
  }

  const store = createSupabaseOAuthStore();
  const row = await getTokenByHash(sha256Hex(tokenValue));
  if (!row || row.kind !== 'access') {
    fail('Unknown access token.');
  }
  if (row.revoked) {
    fail('Access token revoked.');
  }
  const now = Date.now();
  if (row.not_before && Date.parse(row.not_before) > Date.now()) {
    fail('Access token not yet valid.');
  }
  if (Date.parse(row.expires_at) <= Date.now()) {
    fail('Access token expired.');
  }
  if (row.issuer !== issuer) {
    fail('Token issuer mismatch.');
  }
  if (row.audience !== resource) {
    fail('Token audience mismatch.');
  }
  const scopes = Array.isArray(row.scopes) ? row.scopes : [];
  if (!requiredScopes.every((s) => scopes.includes(s))) {
    const err = new Error('Insufficient scope for this operation.');
    err.code = 'INSUFFICIENT_SCOPE';
    throw err;
  }
  if (!row.google_sub || !row.client_id) {
    fail('Token identity missing.');
  }
  return { googleSub: row.google_sub, scopes, clientId: row.client_id };
}

// Import getTokenByHash from the store
import { getTokenByHash } from './mcp-oauth-store.js';
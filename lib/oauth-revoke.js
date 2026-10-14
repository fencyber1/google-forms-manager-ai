// MCP OAuth revocation endpoint (RFC 7009). Revokes an access or refresh
// token by value (SHA-256 lookup). Always returns 200 for valid requests,
// whether or not the token existed, so callers learn nothing about the
// token store. Never logs token values.
import { createSupabaseOAuthStore, revokeTokens } from './mcp-oauth.js';

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  const out = {};
  for (const [k, v] of new URLSearchParams(String(req.body))) out[k] = v;
  return out;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'invalid_request', error_description: 'Use POST.' });
  }
  const body = parseBody(req);
  if (!body.token) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'A token is required.' });
  }
  try {
    await revokeTokens(createSupabaseOAuthStore(), body.token);
  } catch (e) {
    console.error('Revocation failed:', e?.message || 'unknown error');
  }
  return res.status(200).json({});
}

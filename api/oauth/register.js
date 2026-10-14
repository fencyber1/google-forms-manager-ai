// MCP OAuth Dynamic Client Registration (RFC 7591, public clients only).
//
// POST /api/oauth/register accepts { redirect_uris, client_name? } and
// issues an opaque client_id bound to exactly those redirect URIs.
// Only https redirect URIs on the ChatGPT host are accepted; anything else
// is rejected. Grant/response types and token auth method are fixed to what
// this server supports (PKCE code flow, `none`) — caller-supplied values
// for those fields are ignored, never stored as authoritative.
import { randomBytes } from 'node:crypto';
import { CHATGPT_HOST, createSupabaseOAuthStore, oauthError } from '../../lib/mcp-oauth.js';

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  try {
    return JSON.parse(String(req.body));
  } catch {
    return {};
  }
}

function validateRedirectUris(input) {
  if (!Array.isArray(input) || input.length === 0 || input.length > 10) {
    throw oauthError('invalid_redirect_uri', 'redirect_uris must be a non-empty array (max 10).');
  }
  const seen = new Set();
  for (const uri of input) {
    if (typeof uri !== 'string' || !uri) {
      throw oauthError('invalid_redirect_uri', 'Each redirect_uri must be a string.');
    }
    let parsed;
    try {
      parsed = new URL(uri);
    } catch {
      throw oauthError('invalid_redirect_uri', 'Each redirect_uri must be a valid URL.');
    }
    if (parsed.protocol !== 'https:' || parsed.host.toLowerCase() !== CHATGPT_HOST) {
      throw oauthError('invalid_redirect_uri', 'Redirect URIs must be https URLs on the ChatGPT host.');
    }
    if (seen.has(uri)) throw oauthError('invalid_redirect_uri', 'Duplicate redirect_uri.');
    seen.add(uri);
  }
  return [...seen];
}

// Core registration logic with injectable store. Exported for tests.
export async function processClientRegistration(body, store) {
  const redirectUris = validateRedirectUris(body?.redirect_uris);
  const clientName = typeof body?.client_name === 'string' && body.client_name.trim()
    ? body.client_name.trim().slice(0, 128)
    : 'ChatGPT';
  const clientId = `mcp_client_${randomBytes(24).toString('base64url')}`;
  const nowIso = new Date().toISOString();
  await store.saveOAuthClient({
    client_id: clientId,
    redirect_uris: redirectUris,
    client_name: clientName,
    token_endpoint_auth_method: ['none'],
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    created_at: nowIso,
  });
  return {
    client_id: clientId,
    redirect_uris: redirectUris,
    client_name: clientName,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    client_id_issued_at: Math.floor(Date.now() / 1000),
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(400).json({ error: 'invalid_request', error_description: 'Use POST.' });
  }
  try {
    const response = await processClientRegistration(parseBody(req), createSupabaseOAuthStore());
    return res.status(201).json(response);
  } catch (e) {
    console.error('Client registration failed:', e?.code || 'unknown error');
    return res.status(400).json({ error: e?.code || 'invalid_request', error_description: e?.message || 'Invalid request.' });
  }
}

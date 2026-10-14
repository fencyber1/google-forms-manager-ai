// MCP OAuth 2.1 Token Endpoint
//
// POST /api/oauth/token
// Supports grant_type=authorization_code (PKCE S256, public clients only)
// and grant_type=refresh_token (atomic rotation with reuse detection).
// Client authentication method: `none` (public clients via PKCE).
// Any client_secret present is rejected with invalid_client.
// `resource` is required on both grants and must match the canonical resource.
import { oauthError, issuerIdentifier, resourceIdentifier } from '../../lib/mcp-oauth.js';
import { redeemAuthorizationCode, mintTokenPair, refreshGrant, createSupabaseOAuthStore, resolveOAuthClient } from '../../lib/mcp-oauth.js';

function tokenError(res, err) {
  const code = err?.code || 'invalid_request';
  const status = err?.status || 400;
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json({ error: code, error_description: err?.message || 'Invalid request.' });
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  const out = {};
  for (const [k, v] of new URLSearchParams(String(req.body))) out[k] = v;
  return out;
}

// Full grant processing with injectable store + fetch. Exported for tests.
export async function processTokenGrant(body, store, fetchImpl) {
  const issuer = issuerIdentifier();
  const resource = resourceIdentifier();
  const grantType = body.grant_type;
  if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
    throw oauthError('unsupported_grant_type', 'Only authorization_code and refresh_token grants are supported.');
  }
  if (body.client_secret !== undefined) {
    throw oauthError('invalid_client', 'This authorization server accepts public clients only.', 401);
  }
  const clientId = body.client_id;
  if (!clientId) throw oauthError('invalid_client', 'A client_id is required.', 401);
  // Re-resolve the client on every token call (cheap, strict): CIMD URLs
  // are re-validated, DCR ids are looked up in the store.
  await resolveOAuthClient({ clientId, store, fetchImpl });
  if (body.resource !== undefined && body.resource !== resource) {
    throw oauthError('invalid_target', 'Unknown resource.');
  }

  if (body.grant_type === 'authorization_code') {
    if (!body.code) throw oauthError('invalid_request', 'An authorization code is required.');
    if (!body.redirect_uri) throw oauthError('invalid_request', 'A redirect_uri is required.');
    if (!body.code_verifier) throw oauthError('invalid_request', 'A PKCE code_verifier is required.');
    const grant = await redeemAuthorizationCode(store, {
      code: body.code,
      clientId,
      redirectUri: body.redirect_uri,
      verifier: body.code_verifier,
      resource,
    });
    const pair = await mintTokenPair(store, {
      googleSub: grant.googleSub,
      clientId,
      scopes: grant.scopes,
      audience: resource,
      issuer,
    });
    return {
      access_token: pair.accessToken,
      token_type: 'Bearer',
      expires_in: 15 * 60,
      scope: grant.scopes.join(' '),
      ...(pair.refreshToken ? { refresh_token: pair.refreshToken } : {}),
    };
  }

  if (!body.refresh_token) throw oauthError('invalid_request', 'A refresh_token is required.');
  const rotated = await refreshGrant(store, {
    refreshToken: body.refresh_token,
    clientId,
    issuer,
    resource,
  });
  return {
    access_token: rotated.accessToken,
    token_type: 'Bearer',
    expires_in: 15 * 60,
    scope: rotated.scopes.join(' '),
    refresh_token: rotated.refreshToken,
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'invalid_request', error_description: 'Use POST.' });
  }
  const store = createSupabaseOAuthStore();
  const body = parseBody(req);
  const issuer = issuerIdentifier();
  const resource = resourceIdentifier();

  try {
    const response = await processTokenGrant(parseBody(req), store);
    return res.status(200).json(response);
  } catch (e) {
    // Never log token values; messages here are safe (no secrets).
    console.error('Token endpoint failed:', e?.code || 'unknown error');
    return tokenError(res, e);
  }
}
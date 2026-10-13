// Server-only MCP OAuth 2.1 authorization server core (Phase 2).
//
// Issues opaque MCP tokens bound to a Google account (stable `sub`).
// Google access/refresh tokens are NEVER used as MCP tokens.
// Trust model for opaque tokens: 256-bit unguessable values, SHA-256 hash
// lookup server-side, exact audience/issuer/scope/expiry checks, TLS.
// There is deliberately NO signature validation step: opaque tokens have
// no signatures; validation is purely server-side record verification.
//
// Atomicity: authorization-code redemption is a single conditional UPDATE;
// refresh rotation runs in the rotate_mcp_refresh() RPC transaction with
// SELECT ... FOR UPDATE (see supabase/migrations). The in-memory store
// below mirrors the same interface for tests only; production atomicity
// comes from PostgreSQL, not application read-then-write.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { getSupabaseServiceClient } from './supabase.js';

export const GOOGLE_SCOPES = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/forms.body', 'https://www.googleapis.com/auth/forms.responses.readonly'];
export const MCP_SCOPES = ['forms:read', 'forms:write', 'offline_access'];
export const CODE_TTL_MS = 10 * 60 * 1000;
export const ACCESS_TTL_MS = 15 * 60 * 1000;
export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const CSRF_TTL_MS = 15 * 60 * 1000;
export const STABLE_CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
export const CHATGPT_HOST = 'chatgpt.com';
const CIMD_FETCH_TIMEOUT_MS = 8000;
const CIMD_MAX_BYTES = 32 * 1024;
const CIMD_MAX_REDIRECTS = 3;

export function canonicalBase() {
  const base = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
  if (!base) throw new Error('APP_BASE_URL is missing');
  return base;
}
export function issuerIdentifier() {
  return canonicalBase();
}
export function resourceIdentifier() {
  return `${canonicalBase()}/api/mcp`;
}

export function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function randomToken(prefix) {
  return `${prefix}${randomBytes(32).toString('base64url')}`;
}

export function oauthError(code, description, status = 400) {
  const err = new Error(description);
  err.code = code;
  err.status = status;
  return err;
}

// ---- PKCE (S256 only; `plain` is rejected) ----
export function verifyPkceS256(verifier, challenge) {
  if (typeof verifier !== 'string' || verifier.length < 43 || verifier.length > 128) return false;
  if (typeof challenge !== 'string' || !challenge) return false;
  const computed = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---- HTML escaping for consent rendering ----
export function escHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[c]);
}

// ---- CSRF tokens for the consent POST (bound to the Google sub) ----
function csrfKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is missing');
  return createHmac('sha256', secret).update('mcp-oauth-csrf').digest();
}
export function mintCsrfToken(googleSub) {
  const ts = Date.now().toString();
  const sig = createHmac('sha256', csrfKey()).update(`${googleSub}.${ts}`).digest('base64url');
  return `${ts}.${sig}`;
}
export function verifyCsrfToken(token, googleSub, maxAgeMs = CSRF_TTL_MS) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const age = Date.now() - Number(parts[0]);
  if (!Number.isFinite(age) || age < 0 || age > maxAgeMs) return false;
  const expected = createHmac('sha256', csrfKey()).update(`${googleSub}.${parts[0]}`).digest('base64url');
  const a = Buffer.from(expected);
  const b = Buffer.from(parts[1]);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---- CIMD fetching + validation (HTTPS-only, timeout, size cap) ----
async function readCapped(response, maxBytes) {
  if (!response.body) {
    const text = await response.text();
    if (text.length > maxBytes) throw new Error('CIMD document too large.');
    return text;
  }
  const reader = response.body.getReader();
  let received = 0;
  const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.length;
    if (received > maxBytes) {
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      throw new Error('CIMD document too large.');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function fetchCimd(clientIdUrl, fetchImpl = globalThis.fetch) {
  let current;
  try {
    current = new URL(clientIdUrl);
  } catch {
    throw oauthError('invalid_client', 'Client ID must be an HTTPS URL.', 401);
  }
  if (current.protocol !== 'https:') {
    throw oauthError('invalid_client', 'Client ID must use HTTPS.', 401);
  }
  let response = null;
  for (let hop = 0; hop <= CIMD_MAX_REDIRECTS; hop += 1) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), CIMD_FETCH_TIMEOUT_MS);
    try {
      response = await fetchImpl(current.toString(), {
        method: 'GET',
        headers: { accept: 'application/json' },
        redirect: 'manual',
        signal: ctrl.signal,
      });
    } catch {
      throw oauthError('invalid_client', 'Could not fetch client metadata.', 401);
    } finally {
      clearTimeout(timer);
    }
    if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
      try {
        current = new URL(response.headers.get('location'), current);
      } catch {
        throw oauthError('invalid_client', 'Invalid client metadata redirect.', 401);
      }
      if (current.protocol !== 'https:') {
        throw oauthError('invalid_client', 'Client metadata redirect must use HTTPS.', 401);
      }
      continue;
    }
    break;
  }
  if (!response || response.status !== 200) {
    throw oauthError('invalid_client', 'Client metadata unavailable.', 401);
  }
  const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw oauthError('invalid_client', 'Client metadata must be JSON.', 401);
  }
  let raw;
  try {
    raw = await readCapped(response, CIMD_MAX_BYTES);
  } catch (e) {
    if (e?.message === 'CIMD document too large.') throw oauthError('invalid_client', e.message, 401);
    throw oauthError('invalid_client', 'Could not read client metadata.', 401);
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw oauthError('invalid_client', 'Client metadata is not valid JSON.', 401);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw oauthError('invalid_client', 'Client metadata is invalid.', 401);
  }
  const redirectUris = Array.isArray(doc.redirect_uris) ? doc.redirect_uris.filter((u) => typeof u === 'string') : [];
  if (!redirectUris.length) {
    throw oauthError('invalid_client', 'Client metadata must list redirect_uris.', 401);
  }
  if (doc.grant_types && (!Array.isArray(doc.grant_types) || !doc.grant_types.includes('authorization_code'))) {
    throw oauthError('invalid_client', 'Client must support the authorization_code grant.', 401);
  }
  if (doc.response_types && (!Array.isArray(doc.response_types) || !doc.response_types.includes('code'))) {
    throw oauthError('invalid_client', 'Client must support the code response type.', 401);
  }
  const methods = Array.isArray(doc.token_endpoint_auth_methods_supported)
    ? doc.token_endpoint_auth_methods_supported
    : doc.token_endpoint_auth_method
      ? [doc.token_endpoint_auth_method]
      : [];
  if (!methods.includes('none')) {
    throw oauthError('invalid_client', 'Token endpoint auth method not supported for this client.', 401);
  }
  return { doc, redirectUris, clientName: typeof doc.client_name === 'string' ? doc.client_name : null };
}

// Exact redirect validation: the stable ChatGPT URI, or an exact member of
// the validated CIMD document's redirect_uris on the chatgpt.com host.
// No wildcards, no prefixes, no Rest-of-host matching.
export function validateRedirectUri(redirectUri, cimd) {
  if (typeof redirectUri !== 'string' || !redirectUri) {
    throw oauthError('invalid_request', 'A redirect_uri is required.');
  }
  if (redirectUri === STABLE_CHATGPT_REDIRECT) return redirectUri;
  let parsed;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw oauthError('invalid_request', 'The redirect_uri is invalid.');
  }
  if (parsed.protocol !== 'https:' || parsed.host.toLowerCase() !== CHATGPT_HOST) {
    throw oauthError('invalid_request', 'The redirect_uri host is not allowed.');
  }
  if (!cimd || !cimd.redirectUris.includes(redirectUri)) {
    throw oauthError('invalid_request', 'The redirect_uri is not registered for this client.');
  }
  return redirectUri;
}

export function normalizeMcpScopes(input) {
  const list = Array.isArray(input) ? input : typeof input === 'string' ? input.split(/\s+/) : [];
  const scopes = [...new Set(list.filter((s) => MCP_SCOPES.includes(s)))];
  if (!scopes.some((s) => s === 'forms:read' || s === 'forms:write')) {
    throw oauthError('invalid_scope', 'At least one of forms:read or forms:write is required.', 400);
  }
  return scopes;
}

// ---- Storage interface (Supabase production / in-memory for tests) ----
export function createSupabaseOAuthStore() {
  const supabase = getSupabaseServiceClient();
  return {
    async saveAuthCode(row) {
      const { error } = await supabase.from('mcp_auth_codes').insert(row);
      if (error) throw new Error(`Could not store authorization code: ${error.message}`);
    },
    // Atomic single-statement claim: exactly one concurrent redeemer wins.
    async claimAuthCode(codeHash, nowIso) {
      const { data, error } = await supabase
        .from('mcp_auth_codes')
        .update({ used: true, used_at: nowIso })
        .eq('code_hash', codeHash)
        .eq('used', false)
        .gt('expires_at', nowIso)
        .select()
        .maybeSingle();
      if (error) throw new Error(`Could not redeem authorization code: ${error.message}`);
      return data || null;
    },
    async saveToken(row) {
      const { error } = await supabase.from('mcp_tokens').insert(row);
      if (error) throw new Error(`Could not store token: ${error.message}`);
    },
    async getTokenByHash(tokenHash) {
      const { data, error } = await supabase
        .from('mcp_tokens')
        .select('*')
        .eq('token_hash', tokenHash)
        .maybeSingle();
      if (error) throw new Error(`Could not load token: ${error.message}`);
      return data || null;
    },
    async revokeTokenByHash(tokenHash, nowIso) {
      const { error } = await supabase
        .from('mcp_tokens')
        .update({ revoked: true, revoked_at: nowIso })
        .eq('token_hash', tokenHash);
      if (error) throw new Error(`Could not revoke token: ${error.message}`);
    },
    async revokeFamily(familyId, nowIso) {
      const { error } = await supabase
        .from('mcp_tokens')
        .update({ revoked: true, revoked_at: nowIso })
        .eq('family_id', familyId)
        .eq('revoked', false);
      if (error) throw new Error(`Could not revoke token family: ${error.message}`);
    },
    // Atomic rotation inside the rotate_mcp_refresh() RPC transaction.
    async rotateRefresh(oldHash, newRow) {
      const { data, error } = await supabase.rpc('rotate_mcp_refresh', {
        p_old_hash: oldHash,
        p_new_hash: newRow.token_hash,
        p_new_expires: newRow.expires_at,
        p_scopes: newRow.scopes,
      });
      if (error) throw new Error(`Could not rotate refresh token: ${error.message}`);
      return data;
    },
  };
}

// Test-only store. Check-and-set blocks run synchronously (no awaits
// between check and mutation), which gives exact-once semantics in
// single-threaded tests. Production atomicity comes from PostgreSQL.
export function createMemoryOAuthStore() {
  const codes = new Map();
  const tokens = new Map();
  return {
    async saveAuthCode(row) {
      codes.set(row.code_hash, { ...row });
    },
    async claimAuthCode(codeHash, nowIso) {
      const row = codes.get(codeHash);
      if (!row || row.used || row.expires_at <= nowIso) return null;
      row.used = true;
      row.used_at = nowIso;
      return { ...row };
    },
    async saveToken(row) {
      tokens.set(row.token_hash, { ...row });
    },
    async getTokenByHash(tokenHash) {
      const row = tokens.get(tokenHash);
      return row ? { ...row } : null;
    },
async revokeTokenByHash(tokenHash, nowIso) {
      const row = tokens.get(tokenHash);
      if (row && !row.revoked) {
        row.revoked = true;
        row.revoked_at = nowIso;
      }
    },
    async revokeFamily(familyId, nowIso) {
      for (const row of tokens.values()) {
        if (row.family_id === familyId && !row.revoked) {
          row.revoked = true;
          row.revoked_at = nowIso;
        }
      }
    },
    async rotateRefresh(oldHash, newRow) {
      const old = tokens.get(oldHash);
      if (!old || old.kind !== 'refresh') return { ok: false, missing: true };
      const rotated = [...tokens.values()].some((t) => t.rotated_from === oldHash);
      if (old.revoked || rotated) {
        for (const row of tokens.values()) {
          if (row.family_id === old.family_id && !row.revoked) {
            row.revoked = true;
            row.revoked_at = new Date().toISOString();
          }
        }
        return { ok: false, reused: true };
      }
      if (old.expires_at <= new Date().toISOString()) return { ok: false, expired: true };
      old.revoked = true;
      old.revoked_at = new Date().toISOString();
      tokens.set(newRow.token_hash, { ...newRow });
      return { ok: true, reused: false };
    },
  };
}

// ---- High-level operations (store-agnostic) ----
export async function issueAuthorizationCode(store, { clientId, redirectUri, challenge, resource, googleSub, scopes }) {
  const code = randomToken('mcp_code_');
  const now = new Date();
  await store.saveAuthCode({
    code_hash: sha256Hex(code),
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource,
    google_sub: googleSub,
    scopes,
    expires_at: new Date(now.getTime() + CODE_TTL_MS).toISOString(),
    used: false,
    used_at: null,
    created_at: now.toISOString(),
  });
  return code;
}

export async function redeemAuthorizationCode(store, { code, clientId, redirectUri, verifier, resource }) {
  const nowIso = new Date().toISOString();
  const row = await store.claimAuthCode(sha256Hex(code), nowIso);
  // Consumed-or-absent either way: fail closed, never re-issuable.
  if (!row) throw oauthError('invalid_grant', 'Authorization code invalid, expired, or already used.');
  if (row.client_id !== clientId) throw oauthError('invalid_grant', 'Authorization code was issued to a different client.');
  if (row.redirect_uri !== redirectUri) throw oauthError('invalid_grant', 'Redirect URI mismatch.');
  if (row.resource !== resource) throw oauthError('invalid_grant', 'Resource mismatch.');
  if (!verifyPkceS256(verifier, row.code_challenge)) {
    throw oauthError('invalid_grant', 'PKCE verification failed.');
  }
  return { googleSub: row.google_sub, scopes: row.scopes, clientId: row.client_id, resource: row.resource };
}

function tokenRow({ hash, kind, familyId, issuer, sub, clientId, audience, scopes, expiresAt, rotatedFrom = null }) {
  const nowIso = new Date().toISOString();
  return {
    token_hash: hash,
    kind,
    family_id: familyId,
    issuer,
    google_sub: sub,
    client_id: clientId,
    audience,
    scopes,
    expires_at: expiresAt,
    not_before: nowIso,
    revoked: false,
    revoked_at: null,
    rotated_from: rotatedFrom,
    created_at: nowIso,
  };
}

export async function mintTokenPair(store, { googleSub, clientId, scopes, audience, issuer }) {
  const now = Date.now();
  const familyId = randomBytes(16).toString('hex');
  const access = randomToken('mcp_at_');
  const pair = {
    accessToken: access,
    accessExpiresAt: new Date(now + ACCESS_TTL_MS).toISOString(),
    refreshToken: null,
    refreshExpiresAt: null,
  };
  await store.saveToken(
    tokenRow({
      hash: sha256Hex(access),
      kind: 'access',
      familyId,
      issuer,
      sub: googleSub,
      clientId,
      audience,
      scopes: scopes.filter((s) => s !== 'offline_access'),
      expiresAt: pair.accessExpiresAt,
    }),
  );
  if (scopes.includes('offline_access')) {
    const refresh = randomToken('mcp_rt_');
    pair.refreshToken = refresh;
    pair.refreshExpiresAt = new Date(now + REFRESH_TTL_MS).toISOString();
    await store.saveToken(
      tokenRow({
        hash: sha256Hex(refresh),
        kind: 'refresh',
        familyId,
        issuer,
        sub: googleSub,
        clientId,
        audience,
        scopes,
        expiresAt: pair.refreshExpiresAt,
      }),
    );
  }
  return pair;
}

export async function refreshGrant(store, { refreshToken, clientId, issuer, resource }) {
  const oldHash = sha256Hex(refreshToken);
  const old = await store.getTokenByHash(oldHash);
  if (!old || old.kind !== 'refresh') throw oauthError('invalid_grant', 'Refresh token unknown.');
  if (old.client_id !== clientId) throw oauthError('invalid_grant', 'Refresh token bound to a different client.');
  if (old.issuer !== issuer) throw oauthError('invalid_grant', 'Refresh token issuer mismatch.');
  if (resource && old.audience !== resource) throw oauthError('invalid_grant', 'Resource mismatch.');
  const now = Date.now();
  const nextRefresh = randomToken('mcp_rt_');
  const rotated = await store.rotateRefresh(oldHash, {
    token_hash: sha256Hex(nextRefresh),
    kind: 'refresh',
    family_id: old.family_id,
    issuer: old.issuer,
    google_sub: old.google_sub,
    client_id: old.client_id,
    audience: old.audience,
    scopes: old.scopes,
    expires_at: new Date(now + REFRESH_TTL_MS).toISOString(),
    not_before: new Date().toISOString(),
    revoked: false,
    revoked_at: null,
    rotated_from: oldHash,
    created_at: new Date().toISOString(),
  });
  if (!rotated || rotated.ok !== true) {
    if (rotated && rotated.reused === true) {
      // RPC already revoked the family; mirror for non-RPC stores.
      await store.revokeFamily(old.family_id, new Date().toISOString());
      throw oauthError('invalid_grant', 'Refresh token already used; the token family was revoked.');
    }
    if (rotated && rotated.expired === true) throw oauthError('invalid_grant', 'Refresh token expired.');
    throw oauthError('invalid_grant', 'Refresh token invalid.');
  }
  const access = randomToken('mcp_at_');
  const accessExpiresAt = new Date(now + ACCESS_TTL_MS).toISOString();
  await store.saveToken(
    tokenRow({
      hash: sha256Hex(access),
      kind: 'access',
      familyId: old.family_id,
      issuer: old.issuer,
      sub: old.google_sub,
      clientId: old.client_id,
      audience: old.audience,
      scopes: old.scopes.filter((s) => s !== 'offline_access'),
      expiresAt: accessExpiresAt,
    }),
  );
  return {
    accessToken: access,
    accessExpiresAt,
    refreshToken: nextRefresh,
    refreshExpiresAt: new Date(now + REFRESH_TTL_MS).toISOString(),
    scopes: old.scopes,
  };
}

export async function revokeTokens(store, tokenValue) {
  if (typeof tokenValue !== 'string' || !tokenValue) return;
  await store.revokeTokenByHash(sha256Hex(tokenValue), new Date().toISOString());
}

// Full server-side validation chain for opaque MCP access tokens.
// Throws { code: 'INVALID' } (→ HTTP 401 + challenge) or
// { code: 'INSUFFICIENT_SCOPE' } (→ HTTP 403 + challenge).
export async function validateMcpAccessToken(store, tokenValue, { issuer, resource, requiredScopes = [], now = Date.now() }) {
  const fail = (message) => {
    const err = new Error(message);
    err.code = 'INVALID';
    throw err;
  };
  if (typeof tokenValue !== 'string' || !tokenValue) fail('Missing access token.');
  const row = await store.getTokenByHash(sha256Hex(tokenValue));
  if (!row || row.kind !== 'access') fail('Unknown access token.');
  if (row.revoked) fail('Access token revoked.');
  if (row.issuer !== issuer) fail('Token issuer mismatch.');
  if (Date.parse(row.not_before) > now) fail('Access token not yet valid.');
  if (Date.parse(row.expires_at) <= now) fail('Access token expired.');
  if (row.audience !== resource) fail('Token audience mismatch.');
  const scopes = Array.isArray(row.scopes) ? row.scopes : [];
  if (!requiredScopes.every((s) => scopes.includes(s))) {
    const err = new Error('Insufficient scope for this operation.');
    err.code = 'INSUFFICIENT_SCOPE';
    throw err;
  }
  if (!row.google_sub || !row.client_id) fail('Token identity missing.');
return { googleSub: row.google_sub, scopes, clientId: row.client_id };
}

export { saveAuthCode, getTokenByHash } from './mcp-oauth-store.js';



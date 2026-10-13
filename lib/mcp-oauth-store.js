// Server-only MCP OAuth 2.1 store.
// Handles clients, authorization codes, and tokens using service-role Supabase client.
import { createHash, randomBytes } from 'node:crypto';
import { GOOGLE_CONNECTIONS_TABLE, getSupabaseServiceClient } from './supabase.js';

export const MCP_OAUTH_CLIENTS_TABLE = 'mcp_oauth_clients';
export const MCP_AUTH_CODES_TABLE = 'mcp_auth_codes';
export const MCP_TOKENS_TABLE = 'mcp_tokens';

const ACCESS_TTL_MS = 15 * 60 * 1000;     // 15 minutes
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const CODE_TTL_MS = 10 * 60 * 1000;        // 10 minutes
const FAMILY_ID_BYTES = 16;

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function randomToken(prefix = '') {
  return `${prefix}${randomBytes(32).toString('base64url')}`;
}

function newFamilyId() {
  return randomBytes(FAMILY_ID_BYTES).toString('hex');
}

function nowIso() {
  return new Date().toISOString();
}

// ---- Client Management (CIMD + DCR) ----

export async function getOAuthClient(clientId) {
  const supabase = getSupabaseServiceClient();
  const { data, error } = await supabase
    .from('mcp_oauth_clients')
    .select('*')
    .eq('client_id', clientId)
    .maybeSingle();
  if (error) throw new Error(`Could not load OAuth client: ${error.message}`);
  return data || null;
}

export async function upsertOAuthClient(client) {
  const supabase = getSupabaseServiceClient();
  const { error } = await supabase
    .from('mcp_oauth_clients')
    .upsert(client, { onConflict: 'client_id' });
  if (error) throw new Error(`Could not save OAuth client: ${error.message}`);
}

// ---- Authorization Codes ----

export async function saveAuthCode({
  code,
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod,
  resource,
  googleSub,
  scopes,
}) {
  const supabase = getSupabaseServiceClient();
  const codeHash = sha256Hex(code);
  const now = new Date();
  const { error } = await supabase
    .from('mcp_auth_codes')
    .insert({
      code_hash: codeHash,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      resource,
      google_sub: googleSub,
      scopes,
      expires_at: new Date(Date.now() + CODE_TTL_MS).toISOString(),
      used: false,
      created_at: nowIso(),
    });
  if (error) throw new Error(`Could not save auth code: ${error.message}`);
}

export async function claimAuthCode(codeHash, clientId, redirectUri, resource) {
  const supabase = getSupabaseServiceClient();
  const nowIsoStr = nowIso();
  const { data, error } = await supabase
    .from('mcp_auth_codes')
    .update({ used: true, used_at: nowIsoStr })
    .eq('code_hash', codeHash)
    .eq('client_id', clientId)
    .eq('redirect_uri', redirectUri)
    .eq('resource', resource)
    .eq('used', false)
    .gt('expires_at', nowIsoStr)
    .select()
    .maybeSingle();
  if (error) throw new Error(`Could not claim auth code: ${error.message}`);
  return data || null;
}

// ---- Token Management ----

export async function mintTokenPair({
  googleSub,
  clientId,
  scopes,
  audience,
  issuer,
}) {
  const now = Date.now();
  const familyId = newFamilyId();

  // Access token (short-lived, no refresh token in scopes)
  const accessToken = randomToken('mcp_at_');
  const accessHash = sha256Hex(accessToken);
  const accessExpiresAt = new Date(now + ACCESS_TTL_MS).toISOString();

  const supabase = getSupabaseServiceClient();
  const { error: accessError } = await supabase
    .from('mcp_tokens')
    .insert({
      token_hash: accessHash,
      kind: 'access',
      family_id: familyId,
      issuer,
      google_sub: googleSub,
      client_id: clientId,
      audience,
      scopes: scopes.filter(s => s !== 'offline_access'),
      expires_at: accessExpiresAt,
      not_before: nowIso(),
      revoked: false,
      created_at: nowIso(),
    });
  if (accessError) throw new Error(`Could not save access token: ${accessError.message}`);

  // Refresh token (long-lived, includes offline_access)
  const refreshToken = randomToken('mcp_rt_');
  const refreshHash = sha256Hex(refreshToken);
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_MS).toISOString();

  const { error: refreshError } = await supabase
    .from('mcp_tokens')
    .insert({
      token_hash: refreshHash,
      kind: 'refresh',
      family_id: familyId,
      issuer,
      google_sub: googleSub,
      client_id: clientId,
      audience,
      scopes,
      expires_at: refreshExpiresAt,
      not_before: nowIso(),
      revoked: false,
      created_at: nowIso(),
    });
  if (refreshError) throw new Error(`Could not save refresh token: ${refreshError.message}`);

  return {
    accessToken,
    accessExpiresAt,
    refreshToken,
    refreshExpiresAt,
  };
}

export async function getTokenByHash(tokenHash) {
  const supabase = getSupabaseServiceClient();
  const { data, error } = await supabase
    .from('mcp_tokens')
    .select('*')
    .eq('token_hash', sha256Hex(tokenHash))
    .maybeSingle();
  if (error) throw new Error(`Could not load token: ${error.message}`);
  return data || null;
}

export async function revokeTokenByHash(tokenHash) {
  const supabase = getSupabaseServiceClient();
  const nowIsoStr = nowIso();
  const { error } = await supabase
    .from('mcp_tokens')
    .update({ revoked: true, revoked_at: nowIsoStr })
    .eq('token_hash', sha256Hex(tokenHash));
  if (error) throw new Error(`Could not revoke token: ${error.message}`);
}

export async function revokeFamily(familyId) {
  const supabase = getSupabaseServiceClient();
  const nowIsoStr = nowIso();
  const { error } = await supabase
    .from('mcp_tokens')
    .update({ revoked: true, revoked_at: nowIsoStr })
    .eq('family_id', familyId)
    .eq('revoked', false);
  if (error) throw new Error(`Could not revoke token family: ${error.message}`);
}

export async function rotateRefreshToken({
  oldRefreshTokenHash,
  newRefreshToken,
  newExpiresAt,
  scopes,
}) {
  const oldHash = sha256Hex(oldRefreshTokenHash);
  const newHash = sha256Hex(newRefreshToken);
  const supabase = getSupabaseServiceClient();

  // Fetch the old refresh token FOR UPDATE to serialize concurrent rotations
  const { data: old, error: fetchError } = await supabase
    .from('mcp_tokens')
    .select('*')
    .eq('token_hash', oldRefreshTokenHash)
    .eq('kind', 'refresh')
    .single();

  if (fetchError || !old) {
    throw new Error('Refresh token not found');
  }

  // Reuse detection: already revoked or already rotated
  if (old.revoked) {
    // Already revoked - check if family has been rotated
    const { data: rotated } = await supabase
      .from('mcp_tokens')
      .select('token_hash')
      .eq('rotated_from', old.token_hash)
      .limit(1);
    if (rotated && rotated.length > 0) {
      return { ok: false, reused: true };
    }
    return { ok: false, missing: true };
  }

  const { data: rotated } = await supabase
    .from('mcp_tokens')
    .select('token_hash')
    .eq('rotated_from', old.token_hash)
    .limit(1);
  if (rotated && rotated.length > 0) {
    // Already rotated - this is a reuse attempt, revoke entire family
    await revokeFamily(old.family_id);
    return { ok: false, reused: true };
  }

  if (new Date(old.expires_at) <= new Date()) {
    return { ok: false, expired: true };
  }

  // Revoke old, insert new
  const nowIsoStr = nowIso();
  const newRefreshTokenHash = sha256Hex(newRefreshToken);

  const { error: revokeError } = await supabase
    .from('mcp_tokens')
    .update({ revoked: true, revoked_at: new Date().toISOString() })
    .eq('token_hash', oldRefreshTokenHash);
  if (revokeError) throw new Error(`Could not revoke old refresh token: ${revokeError.message}`);

  const { error: insertError } = await supabase
    .from('mcp_tokens')
    .insert({
      token_hash: newRefreshTokenHash,
      kind: 'refresh',
      family_id: old.family_id,
      issuer: old.issuer,
      google_sub: old.google_sub,
      client_id: old.client_id,
      audience: old.audience,
      scopes: scopes ?? old.scopes,
      expires_at: newExpiresAt.toISOString(),
      not_before: new Date().toISOString(),
      revoked: false,
      rotated_from: old.token_hash,
      created_at: nowIsoStr,
    });
  if (insertError) throw new Error(`Could not save new refresh token: ${insertError.message}`);

  return { ok: true, reused: false };
}

export async function revokeTokensByFamily(familyId) {
  const supabase = getSupabaseServiceClient();
  const nowIsoStr = nowIso();
  const { error } = await supabase
    .from('mcp_tokens')
    .update({ revoked: true, revoked_at: nowIso() })
    .eq('family_id', familyId)
    .eq('revoked', false);
  if (error) throw new Error(`Could not revoke token family: ${error.message}`);
}
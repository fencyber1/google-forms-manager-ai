// Server-only per-user Google connection store.
//
// Each user's OAuth tokens are encrypted with AES-256-GCM (lib/crypto.js)
// before being written to public.google_connections. Plaintext tokens are
// never stored, logged, or returned in API responses.
import { google } from 'googleapis';
import { decryptToken, encryptToken } from './crypto.js';
import { GOOGLE_CONNECTIONS_TABLE, getSupabaseServiceClient } from './supabase.js';

export const GOOGLE_SCOPES = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/forms.body',
  'https://www.googleapis.com/auth/forms.responses.readonly',
];

function getRedirectUri() {
  const base = (process.env.APP_BASE_URL || '').replace(/\/$/, '');
  if (!base) throw new Error('APP_BASE_URL is missing');
  return `${base}/api/auth/callback`;
}

export function buildOAuthClient() {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    throw new Error('Google OAuth is not configured.');
  }
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    getRedirectUri(),
  );
}

function normalizeScopes(input) {
  if (Array.isArray(input)) return input.filter((s) => typeof s === 'string' && s);
  if (typeof input === 'string' && input.trim()) return input.trim().split(/\s+/);
  return [...GOOGLE_SCOPES];
}

function expiryToIso(expiryDate) {
  if (!expiryDate || Number.isNaN(Number(expiryDate))) return null;
  return new Date(Number(expiryDate)).toISOString();
}

// Save or update one user's connection. userId must be the stable Google
// account ID (userinfo "sub"), not an email address alone.
export async function saveGoogleConnection({ userId, googleEmail, tokens, scopes }) {
  if (!userId || typeof userId !== 'string') throw new Error('saveGoogleConnection requires userId.');
  if (!tokens || typeof tokens !== 'object') throw new Error('saveGoogleConnection requires tokens.');
  const supabase = getSupabaseServiceClient();

  // Preserve the existing encrypted refresh token when Google does not
  // return a new one on this authorization (e.g. re-consent without rotation).
  let encryptedRefreshToken = null;
  if (typeof tokens.refresh_token === 'string' && tokens.refresh_token) {
    encryptedRefreshToken = encryptToken(tokens.refresh_token);
  } else {
    const { data: existing } = await supabase
      .from(GOOGLE_CONNECTIONS_TABLE)
      .select('encrypted_refresh_token')
      .eq('user_id', userId)
      .maybeSingle();
    encryptedRefreshToken = existing?.encrypted_refresh_token || null;
  }
  if (!encryptedRefreshToken) {
    throw new Error('No refresh token available; ask the user to reconnect with consent.');
  }

  let encryptedAccessToken = null;
  if (typeof tokens.access_token === 'string' && tokens.access_token) {
    encryptedAccessToken = encryptToken(tokens.access_token);
  } else {
    const { data: existing } = await supabase
      .from(GOOGLE_CONNECTIONS_TABLE)
      .select('encrypted_access_token,access_token_expires_at')
      .eq('user_id', userId)
      .maybeSingle();
    encryptedAccessToken = existing?.encrypted_access_token || null;
  }

  const row = {
    user_id: userId,
    google_email: typeof googleEmail === 'string' ? googleEmail : null,
    encrypted_refresh_token: encryptedRefreshToken,
    encrypted_access_token: encryptedAccessToken,
    access_token_expires_at: expiryToIso(tokens.expiry_date),
    scopes: normalizeScopes(scopes ?? tokens.scope),
    updated_at: new Date().toISOString(),
  };

  const { error } = await supabase
    .from(GOOGLE_CONNECTIONS_TABLE)
    .upsert(row, { onConflict: 'user_id' });
  if (error) throw new Error(`Could not save Google connection: ${error.message}`);
}

// Load the raw connection row for exactly one user. Returns null when the
// user has never connected. Callers must not return this row to the browser.
export async function getGoogleConnection(userId) {
  if (!userId) return null;
  const supabase = getSupabaseServiceClient();
  const { data, error } = await supabase
    .from(GOOGLE_CONNECTIONS_TABLE)
    .select('*')
    .eq('user_id', userId)
    .maybeSingle();
  if (error) throw new Error(`Could not load Google connection: ${error.message}`);
  return data || null;
}

// Resolve valid (decrypted, non-expired) tokens for one user, refreshing the
// access token via the stored refresh token when needed.
export async function getValidGoogleTokens(userId) {
  const row = await getGoogleConnection(userId);
  if (!row?.encrypted_refresh_token) {
    const err = new Error('Google is not connected.');
    err.code = 'GOOGLE_RECONNECT_REQUIRED';
    throw err;
  }

  let refreshToken;
  let accessToken = null;
  try {
    refreshToken = decryptToken(row.encrypted_refresh_token);
    if (row.encrypted_access_token) accessToken = decryptToken(row.encrypted_access_token);
  } catch {
    const err = new Error('Stored Google credentials are unreadable; reconnect.');
    err.code = 'GOOGLE_RECONNECT_REQUIRED';
    throw err;
  }

  const expiresAt = row.access_token_expires_at ? Date.parse(row.access_token_expires_at) : 0;
  const needsRefresh = !accessToken || !expiresAt || Date.now() > expiresAt - 60_000;
  if (!needsRefresh) return { access_token: accessToken, refresh_token: refreshToken };

  const oauth2 = buildOAuthClient();
  oauth2.setCredentials({ refresh_token: refreshToken });
  let refreshed;
  try {
    ({ credentials: refreshed } = await oauth2.refreshAccessToken());
  } catch (e) {
    const err = new Error('Google authorization expired; reconnect.');
    err.code = 'GOOGLE_RECONNECT_REQUIRED';
    err.cause = e;
    throw err;
  }

  const nextAccessToken = refreshed.access_token || accessToken;
  const nextRefreshToken = refreshed.refresh_token || refreshToken;
  const supabase = getSupabaseServiceClient();
  const { error } = await supabase
    .from(GOOGLE_CONNECTIONS_TABLE)
    .update({
      encrypted_access_token: nextAccessToken ? encryptToken(nextAccessToken) : row.encrypted_access_token,
      encrypted_refresh_token: encryptToken(nextRefreshToken),
      access_token_expires_at: expiryToIso(refreshed.expiry_date) || row.access_token_expires_at,
      updated_at: new Date().toISOString(),
    })
    .eq('user_id', userId);
  if (error) throw new Error(`Could not refresh Google connection: ${error.message}`);
  return { access_token: nextAccessToken, refresh_token: nextRefreshToken };
}

// Build an OAuth2 client authenticated as exactly one user.
export async function getAuthenticatedOAuthClient(userId) {
  const tokens = await getValidGoogleTokens(userId);
  const oauth2 = buildOAuthClient();
  oauth2.setCredentials(tokens);
  return oauth2;
}

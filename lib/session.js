// Server-only session helpers.
//
// The gfm_session cookie now holds ONLY the authenticated Google user ID
// ({ uid, v: 1 }), encrypted with SESSION_SECRET. Google OAuth tokens live
// exclusively in Supabase (encrypted with TOKEN_ENCRYPTION_KEY) and each
// request resolves only the current cookie user's connection.
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { getAuthenticatedOAuthClient } from './google-connections.js';

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is missing');
  return createHmac('sha256', secret).update('gfm-cookie-key').digest();
}

function parseCookies(header = '') {
  return Object.fromEntries(
    header
      .split(';')
      .map((v) => v.trim())
      .filter(Boolean)
      .map((v) => {
        const i = v.indexOf('=');
        return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
      }),
  );
}

export function encryptSession(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getKey(), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

// Returns the stable Google user ID (userinfo "sub") or null. Legacy cookies
// that stored raw tokens intentionally fail validation (force reconnect).
export function getUserId(req) {
  const cookie = parseCookies(req.headers.cookie).gfm_session;
  if (!cookie) return null;
  try {
    const raw = Buffer.from(cookie, 'base64url');
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const body = raw.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', getKey(), iv);
    decipher.setAuthTag(tag);
    const decoded = JSON.parse(
      Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8'),
    );
    if (!decoded || decoded.v !== 1 || typeof decoded.uid !== 'string' || !decoded.uid) return null;
    return decoded.uid;
  } catch {
    return null;
  }
}

export function requireMethod(req, res, method = 'POST') {
  if (req.method !== method) {
    res.status(405).json({ error: `Use ${method}.` });
    return false;
  }
  return true;
}

export function requireUserId(req, res) {
  const userId = getUserId(req);
  if (!userId) {
    res.status(401).json({ error: 'Google is not connected. Open /api/auth/google to connect first.' });
    return null;
  }
  return userId;
}

// Resolve an OAuth2 client for the current cookie user only, without
// writing an HTTP response. Throws a coded AuthError instead:
//   code 'UNAUTHENTICATED' — no valid session cookie (connect first).
//   code 'RECONNECT_REQUIRED' — Google grant expired/revoked (reconnect).
//   code 'UPSTREAM' — unexpected server-side failure (message is safe).
// Shared by the REST endpoints (via the wrapper below) and the MCP server.
export async function resolveAuthenticatedClient(req) {
  const userId = getUserId(req);
  if (!userId) {
    const err = new Error('Google is not connected. Open /api/auth/google to connect first.');
    err.code = 'UNAUTHENTICATED';
    throw err;
  }
  try {
    return await getAuthenticatedOAuthClient(userId);
  } catch (e) {
    if (e?.code === 'GOOGLE_RECONNECT_REQUIRED') {
      const err = new Error('Google connection expired. Open /api/auth/google to reconnect.');
      err.code = 'RECONNECT_REQUIRED';
      throw err;
    }
    console.error('Google auth failed:', e?.message || 'unknown error');
    const err = new Error('Could not authenticate with Google. Try reconnecting.');
    err.code = 'UPSTREAM';
    throw err;
  }
}

// Resolve an OAuth2 client for the current cookie user only. Sends the HTTP
// error response itself and returns null when the user must reconnect.
export async function getAuthenticatedGoogleClient(req, res) {
  try {
    return await resolveAuthenticatedClient(req);
  } catch (e) {
    if (e?.code === 'UNAUTHENTICATED') {
      res.status(401).json({ error: e.message });
      return null;
    }
    if (e?.code === 'RECONNECT_REQUIRED') {
      res.status(401).json({ error: e.message });
      return null;
    }
    res.status(500).json({ error: e.message });
    return null;
  }
}

export function noCache(res) {
  res.setHeader('Cache-Control', 'no-store');
}

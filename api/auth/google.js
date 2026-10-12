import { createHmac, randomBytes } from 'node:crypto';
import { GOOGLE_SCOPES, buildOAuthClient } from '../../lib/google-connections.js';

function sign(value) {
  return createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
}

export default function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'APP_BASE_URL', 'SESSION_SECRET'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) return res.status(500).json({ error: `Missing environment variables: ${missing.join(', ')}` });

  const redirectUri = `${process.env.APP_BASE_URL.replace(/\/$/, '')}/api/auth/callback`;
  const oauth2 = buildOAuthClient();
  const state = randomBytes(24).toString('base64url');
  const issuedAt = Date.now().toString();
  const payload = `${state}.${issuedAt}`;
  const cookie = `${payload}.${sign(payload)}`;
  res.setHeader('Set-Cookie', `gfm_oauth_state=${encodeURIComponent(cookie)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);

  const url = oauth2.generateAuthUrl({
    access_type: 'offline', prompt: 'consent', include_granted_scopes: true, state,
    scope: GOOGLE_SCOPES
  });
  return res.redirect(302, url);
}

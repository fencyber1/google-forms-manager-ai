import { google } from 'googleapis';
import { createHmac, randomBytes } from 'node:crypto';

function sign(value) {
  return createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
}

export default function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'APP_BASE_URL', 'SESSION_SECRET'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) return res.status(500).json({ error: `Missing environment variables: ${missing.join(', ')}` });

  const redirectUri = `${process.env.APP_BASE_URL.replace(/\/$/, '')}/api/auth/callback`;
  const oauth2 = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri);
  const state = randomBytes(24).toString('base64url');
  const issuedAt = Date.now().toString();
  const payload = `${state}.${issuedAt}`;
  const cookie = `${payload}.${sign(payload)}`;
  res.setHeader('Set-Cookie', `gfm_oauth_state=${encodeURIComponent(cookie)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);

  const url = oauth2.generateAuthUrl({
    access_type: 'offline', prompt: 'consent', include_granted_scopes: true, state,
    scope: ['https://www.googleapis.com/auth/forms.body', 'https://www.googleapis.com/auth/forms.responses.readonly']
  });
  return res.redirect(302, url);
}

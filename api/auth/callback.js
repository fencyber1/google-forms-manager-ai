import { google } from 'googleapis';
import { createHmac, timingSafeEqual, createCipheriv, randomBytes } from 'node:crypto';

function sign(value) { return createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url'); }
function encrypt(value) {
  const key = createHmac('sha256', process.env.SESSION_SECRET).update('gfm-cookie-key').digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}
function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).send('Use GET.');
  const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'APP_BASE_URL', 'SESSION_SECRET'];
  if (required.some(k => !process.env[k])) return res.status(500).send('Backend environment is incomplete.');
  if (req.query.error) return res.status(400).send('Google authorization was cancelled or denied. You can close this page.');

  const cookies = parseCookies(req.headers.cookie);
  const parts = (cookies.gfm_oauth_state || '').split('.');
  const queryState = req.query.state;
  if (parts.length !== 3 || !queryState || parts[0] !== queryState) return res.status(400).send('OAuth state check failed. Start again from the connect link.');
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(parts[2]);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual) || Date.now() - Number(parts[1]) > 600000) return res.status(400).send('OAuth state expired or invalid. Start again.');

  try {
    const redirectUri = `${process.env.APP_BASE_URL.replace(/\/$/, '')}/api/auth/callback`;
    const oauth2 = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, redirectUri);
    const { tokens } = await oauth2.getToken(req.query.code);
    const session = encrypt({ tokens, createdAt: Date.now() });
    res.setHeader('Set-Cookie', [
      `gfm_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
      'gfm_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
    ]);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send('<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connected</title></head><body style="font-family:system-ui;max-width:680px;margin:4rem auto;padding:0 1rem"><h1>Google Forms connected</h1><p>Authorization completed. You can close this tab and return to Google Forms Manager AI.</p><p>For safety, this backend keeps the session in an encrypted, HTTP-only cookie. If you clear cookies or change devices, connect again.</p></body></html>');
  } catch (e) {
    console.error('OAuth callback failed:', e?.message);
    return res.status(500).send('Could not complete Google authorization. Check the OAuth redirect URI and environment variables, then try again.');
  }
}

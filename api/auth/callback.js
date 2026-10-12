import { createHmac, timingSafeEqual } from 'node:crypto';
import { GOOGLE_SCOPES, buildOAuthClient, saveGoogleConnection } from '../../lib/google-connections.js';
import { encryptSession } from '../../lib/session.js';

function sign(value) {
  return createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
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

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).send('Use GET.');
  const required = [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'APP_BASE_URL',
    'SESSION_SECRET',
    'SUPABASE_URL',
    'SUPABASE_SECRET_KEY',
    'TOKEN_ENCRYPTION_KEY',
  ];
  if (required.some((k) => !process.env[k])) {
    return res.status(500).send('Backend environment is incomplete.');
  }
  if (req.query.error) {
    return res.status(400).send('Google authorization was cancelled or denied. You can close this page.');
  }

  const cookies = parseCookies(req.headers.cookie);
  const parts = (cookies.gfm_oauth_state || '').split('.');
  const queryState = req.query.state;
  if (parts.length !== 3 || !queryState || parts[0] !== queryState) {
    return res.status(400).send('OAuth state check failed. Start again from the connect link.');
  }
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(parts[2]);
  if (
    expected.length !== actual.length ||
    !timingSafeEqual(expected, actual) ||
    Date.now() - Number(parts[1]) > 600000
  ) {
    return res.status(400).send('OAuth state expired or invalid. Start again.');
  }

  try {
    const oauth2 = buildOAuthClient();
    const { tokens } = await oauth2.getToken(req.query.code);
    if (!tokens?.access_token && !tokens?.refresh_token) {
      throw new Error('Google did not return tokens.');
    }
    oauth2.setCredentials(tokens);

    // Securely identify the Google account: stable "sub" is user_id.
    const { data: profile } = await oauth2.userinfo.get();
    const userId = profile?.id;
    const googleEmail = profile?.email || null;
    if (!userId) throw new Error('Could not identify the Google account.');

    await saveGoogleConnection({
      userId,
      googleEmail,
      tokens,
      scopes: tokens.scope || GOOGLE_SCOPES,
    });

    const session = encryptSession({ uid: userId, v: 1, createdAt: Date.now() });
    res.setHeader('Set-Cookie', [
      `gfm_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
      'gfm_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
    ]);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(
      '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connected</title></head>' +
        '<body style="font-family:system-ui;max-width:680px;margin:4rem auto;padding:0 1rem">' +
        '<h1>Google Forms connected</h1>' +
        '<p>Authorization completed. You can close this tab and return to Google Forms Manager AI.</p>' +
        '<p>For safety, your Google tokens are encrypted and stored per-user on the server. ' +
        'If you clear cookies or change devices, connect again.</p>' +
        '<p><em>Note: ChatGPT MCP authentication is a separate task and is not complete.</em></p>' +
        '</body></html>',
    );
  } catch (e) {
    // Never log tokens, emails, secrets, or encryption keys.
    console.error('OAuth callback failed:', e?.message || 'unknown error');
    return res
      .status(500)
      .send('Could not complete Google authorization. Check the OAuth redirect URI and environment variables, then try again.');
  }
}

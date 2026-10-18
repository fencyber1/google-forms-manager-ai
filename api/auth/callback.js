import { createHmac, timingSafeEqual } from 'node:crypto';
import { google } from 'googleapis';
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

// TEMPORARY DIAGNOSTICS — remove once the callback failure is resolved.
// Logs only stage name, error name, safe error code, and a sanitized
// message. Never logs URLs, query parameters, codes, tokens, cookies,
// secrets, or stack traces.
function sanitizeForLog(value) {
  return String(value ?? '')
    .replace(/https?:\/\/[^\s'"]+/g, '[redacted-url]')
    .replace(/ya29\.[A-Za-z0-9_\-]+/g, '[redacted-google-token]')
    .replace(/mcp_(?:at|rt|code)_[A-Za-z0-9_\-]+/g, '[redacted-token]')
    .replace(/\b(code|state|token)=[^&\s]+/gi, '$1=[redacted]')
    .replace(/\b[A-Za-z0-9_\-]{40,}\b/g, '[redacted-long-value]')
    .slice(0, 300);
}

function logStageError(stage, e) {
  const code =
    typeof e?.code === 'string' && /^[a-z0-9_\-]{1,64}$/i.test(e.code) ? e.code : null;
  console.error(
    JSON.stringify({
      event: 'oauth-callback-failed',
      stage,
      errorName: e?.name || 'Error',
      code: code || null,
      message: sanitizeForLog(e?.message),
    }),
  );
}

// Fetches the authenticated Google profile (stable id + email) using the
// OAuth2 v2 userinfo endpoint. `googleApi` is injectable for tests.
// Throws when the profile or its stable id is missing.
export async function fetchGoogleProfile(oauth2, googleApi = google) {
  const userInfo = googleApi.oauth2({ version: 'v2', auth: oauth2 });
  const { data: profile } = await userInfo.userinfo.get();
  const userId = profile?.id;
  const googleEmail = profile?.email || null;
  if (!userId) throw new Error('Could not identify the Google account.');
  return { userId, googleEmail };
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

  let stage = 'token-exchange';
  try {
    const oauth2 = buildOAuthClient();
    const { tokens } = await oauth2.getToken(req.query.code);
    if (!tokens?.access_token && !tokens?.refresh_token) {
      throw new Error('Google did not return tokens.');
    }
    oauth2.setCredentials(tokens);

    // Securely identify the Google account: stable "sub" is user_id.
    stage = 'userinfo';
    const { userId, googleEmail } = await fetchGoogleProfile(oauth2);

    stage = 'save-connection';
    await saveGoogleConnection({
      userId,
      googleEmail,
      tokens,
      scopes: tokens.scope || GOOGLE_SCOPES,
    });

    stage = 'session-cookie';
    const session = encryptSession({ uid: userId, v: 1, createdAt: Date.now() });
    const clearCookies = [
      'gfm_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
      'gfm_post_login=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
    ];

    // If login was started from the MCP authorize endpoint, resume that
    // flow instead of showing the static page: the MCP client (ChatGPT)
    // is waiting for an authorization code redirect.
    const postParts = (cookies.gfm_post_login || '').split('.');
    if (postParts.length === 3) {
      const [pSig, pTs, pPayload] = postParts;
      try {
        const expected = Buffer.from(sign(`${pTs}.${pPayload}`));
        const actual = Buffer.from(pSig);
        if (expected.length === actual.length && timingSafeEqual(expected, actual) && Date.now() - Number(pTs) <= 600000) {
          const returnTo = Buffer.from(pPayload, 'base64url').toString('utf8');
          if (/^\/api\/oauth\/authorize(\?|$)/.test(returnTo)) {
            res.setHeader('Set-Cookie', [
              `gfm_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
              ...clearCookies,
            ]);
            return res.redirect(302, returnTo);
          }
        }
      } catch {
        // invalid resume cookie — fall through to the static page
      }
    }

    res.setHeader('Set-Cookie', [
      `gfm_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
      ...clearCookies,
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
    logStageError(stage, e);
    return res
      .status(500)
      .send('Could not complete Google authorization. Check the OAuth redirect URI and environment variables, then try again.');
  }
}

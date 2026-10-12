// MCP OAuth authorization endpoint (authorization_code + PKCE S256).
//
// GET validates the request and renders a consent page; POST (CSRF-bound
// to the Google session) issues a single-use authorization code.
// Requires an authenticated Google session FIRST: grants are bound to the
// session's Google `sub`. No user-supplied identity is ever accepted.
// redirect_uri is validated BEFORE any redirect or error redirect happens;
// `iss` is attached to success and error redirects (RFC 9207).
import {
  STABLE_CHATGPT_REDIRECT,
  escHtml,
  fetchCimd,
  issueAuthorizationCode,
  issuerIdentifier,
  mintCsrfToken,
  normalizeMcpScopes,
  oauthError,
  resourceIdentifier,
  validateRedirectUri,
  verifyCsrfToken,
  createSupabaseOAuthStore,
} from '../../lib/mcp-oauth.js';
import { getUserId } from '../../lib/session.js';
import { getGoogleConnection } from '../../lib/google-connections.js';

function htmlPage(title, body) {
  return (
    '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">' +
    `<title>${escHtml(title)}</title></head>` +
    '<body style="font-family:system-ui;max-width:640px;margin:3rem auto;padding:0 1rem">' +
    body +
    '</body></html>'
  );
}

function loginRequired(res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res
    .status(401)
    .send(
      htmlPage(
        'Connect Google first',
        '<h1>Connect your Google account first</h1>' +
          '<p>Open <a href="/api/auth/google">/api/auth/google</a> to connect Google, then restart the ChatGPT authorization.</p>',
      ),
    );
}

function describeScope(scope) {
  if (scope === 'forms:read') return 'Read your Google Forms and their responses';
  if (scope === 'forms:write') return 'Create Google Forms in your account';
  if (scope === 'offline_access') return 'Stay connected (refresh access without asking each time)';
  return scope;
}

// Validates everything except the session. Returns validated params or
// throws oauthError. Exported for tests (fetchImpl injectable).
export async function validateAuthorizeRequest(params, fetchImpl) {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, resource } = params;
  if (response_type !== 'code') throw oauthError('unsupported_response_type', 'Only response_type=code is supported.');
  if (!client_id) throw oauthError('invalid_request', 'A client_id is required.');
  if (code_challenge_method !== 'S256') throw oauthError('invalid_request', 'code_challenge_method must be S256.');
  if (!code_challenge) throw oauthError('invalid_request', 'A PKCE code_challenge is required.');
  if (resource !== resourceIdentifier()) throw oauthError('invalid_target', 'Unknown resource.');
  const cimd = await fetchCimd(client_id, fetchImpl);
  const redirectUri = validateRedirectUri(redirect_uri, cimd);
  const scopes = normalizeMcpScopes(scope);
  if (state !== undefined && (typeof state !== 'string' || state.length > 1024)) {
    throw oauthError('invalid_request', 'Invalid state parameter.');
  }
  return { clientId: client_id, redirectUri, scopes, state, challenge: code_challenge, cimd };
}

function errorRedirect(redirectUri, error, description, state) {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  url.searchParams.set('iss', issuerIdentifier());
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

// Processes the consent POST. Revalidates all client-controlled fields,
// enforces the CSRF token bound to the Google session, and either returns
// { redirect } (allow → code redirect, deny → error redirect with iss) or
// throws oauthError. Exported for tests (store + fetch injectable).
export async function processAuthorizeDecision({ body, googleSub, store, fetchImpl }) {
  if (!verifyCsrfToken(body.csrf, googleSub)) {
    const err = new Error('Invalid or expired form. Start again.');
    err.code = 'CSRF';
    err.status = 403;
    throw err;
  }
  const validated = await validateAuthorizeRequest(
    {
      response_type: 'code',
      client_id: body.client_id,
      redirect_uri: body.redirect_uri,
      scope: body.scope,
      state: body.state || undefined,
      code_challenge: body.code_challenge,
      code_challenge_method: 'S256',
      resource: body.resource,
    },
    fetchImpl,
  );
  if (body.decision !== 'allow') {
    return { redirect: errorRedirect(validated.redirectUri, 'access_denied', 'The user denied the request.', validated.state) };
  }
  const code = await issueAuthorizationCode(store, {
    clientId: validated.clientId,
    redirectUri: validated.redirectUri,
    challenge: validated.challenge,
    resource: resourceIdentifier(),
    googleSub,
    scopes: validated.scopes,
  });
  const url = new URL(validated.redirectUri);
  url.searchParams.set('code', code);
  url.searchParams.set('iss', issuerIdentifier());
  if (validated.state) url.searchParams.set('state', validated.state);
  return { redirect: url.toString() };
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  const out = {};
  for (const [k, v] of new URLSearchParams(String(req.body))) out[k] = v;
  return out;
}

function consentPage({ googleEmail, clientName, clientId, redirectHost, scopes, csrf, fields }) {
  const hidden = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${escHtml(k)}" value="${escHtml(v)}">`)
    .join('');
  const scopeItems = scopes.map((s) => `<li>${escHtml(describeScope(s))} <code>${escHtml(s)}</code></li>`).join('');
  return htmlPage(
    'Authorize ChatGPT',
    '<h1>Authorize ChatGPT?</h1>' +
      `<p><strong>${escHtml(clientName || 'ChatGPT')}</strong> (<code>${escHtml(clientId)}</code>) wants to access Google Forms Manager AI and will redirect back to <code>${escHtml(redirectHost)}</code>.</p>` +
      `<p>Signed in to Google as <strong>${escHtml(googleEmail || 'your account')}</strong>. The grant will be bound to this Google account only.</p>` +
      '<p>Permissions requested:</p><ul>' +
      scopeItems +
      '</ul>' +
      '<form method="POST">' +
      hidden +
      `<input type="hidden" name="csrf" value="${escHtml(csrf)}">` +
      '<button type="submit" name="decision" value="allow">Allow</button> ' +
      '<button type="submit" name="decision" value="deny">Deny</button>' +
      '</form>',
  );
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const store = createSupabaseOAuthStore();

  if (req.method === 'GET') {
    const googleSub = getUserId(req);
    if (!googleSub) return loginRequired(res);
    let validated;
    try {
      validated = await validateAuthorizeRequest(req.query || {});
    } catch (e) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(e?.status || 400).send(htmlPage('Authorization error', `<h1>Cannot start authorization</h1><p>${escHtml(e?.message || 'Invalid request.')}</p>`));
    }
    let redirectHost = '';
    try {
      redirectHost = new URL(validated.redirectUri).host;
    } catch {
      redirectHost = validated.redirectUri;
    }
    const csrf = mintCsrfToken(googleSub);
    // Best-effort display email; failure only hides the email line.
    let googleEmail = null;
    try {
      googleEmail = (await getGoogleConnection(googleSub))?.google_email || null;
    } catch {
      googleEmail = null;
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(
      consentPage({
        googleEmail,
        clientName: validated.cimd.clientName,
        clientId: validated.clientId,
        redirectHost,
        scopes: validated.scopes,
        csrf,
        fields: {
          client_id: validated.clientId,
          redirect_uri: validated.redirectUri,
          scope: validated.scopes.join(' '),
          state: validated.state || '',
          code_challenge: validated.challenge,
          resource: resourceIdentifier(),
        },
      }),
    );
  }

  if (req.method === 'POST') {
    const googleSub = getUserId(req);
    if (!googleSub) return loginRequired(res);
    const body = parseBody(req);
    try {
      const { redirect } = await processAuthorizeDecision({ body, googleSub, store });
      return res.redirect(302, redirect);
    } catch (e) {
      if (e?.code === 'CSRF') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(403).send(htmlPage('Forbidden', `<h1>${escHtml(e.message)}</h1>`));
      }
      if (e?.code && e?.status) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(e.status).send(htmlPage('Authorization error', `<h1>Cannot complete authorization</h1><p>${escHtml(e.message)}</p>`));
      }
      console.error('Authorize failed:', e?.message || 'unknown error');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(500).send(htmlPage('Authorization error', '<h1>Could not complete authorization. Try again.</h1>'));
    }
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).send('Use GET or POST.');
}

// MCP OAuth 2.1 Authorization Endpoint
//
// GET  /api/oauth/authorize - Renders consent page (requires authenticated Google session)
// POST /api/oauth/authorize - Processes consent decision (CSRF-protected)
import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import { google } from 'googleapis';
import { getUserId } from '../../lib/session.js';
import {
  canonicalBase,
  issuerIdentifier,
  resourceIdentifier,
  GOOGLE_SCOPES,
  fetchCimd,
  validateRedirectUri,
  normalizeMcpScopes,
  mintCsrfToken,
  verifyCsrfToken,
  saveAuthCode,
  issueAuthorizationCode,
  createSupabaseOAuthStore,
} from '../../lib/mcp-oauth.js';

const CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CSRF_TTL_MS = 15 * 60 * 1000; // 15 minutes
const STABLE_CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const CHATGPT_HOST = 'chatgpt.com';

function htmlPage(title, body) {
  return (
    '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">' +
    `<title>${escapeHtml(title)}</title></head>` +
    '<body style="font-family:system-ui;max-width:640px;margin:3rem auto;padding:0 1rem">' +
    body +
    '</body></html>'
  );
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => {
    if (c === '&') return '&';
    if (c === '<') return '<';
    if (c === '>') return '>';
    if (c === '"') return '"';
    if (c === "'") return '\'';
    return c;
  });
}

function loginRequired(res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res
    .status(401)
    .send(
      htmlPage(
        'Connect Google first',
        '<h1>Connect your Google account first</h1>' +
          '<p>Open <a href="/api/auth/google">/api/auth/google</a> to connect Google, then restart the authorization.</p>',
      ),
    );
}

function describeScope(scope) {
  if (scope === 'forms:read') return 'Read your Google Forms and their responses';
  if (scope === 'forms:write') return 'Create Google Forms in your account';
  if (scope === 'offline_access') return 'Stay connected (refresh access without asking each time)';
  return scope;
}

function errorRedirect(redirectUri, error, description, state, issuer) {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  url.searchParams.set('iss', issuer);
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

function successRedirect(redirectUri, code, state, issuer) {
  const url = new URL(redirectUri);
  url.searchParams.set('code', code);
  url.searchParams.set('iss', issuer);
  if (state !== undefined) url.searchParams.set('state', state);
  return url.toString();
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object') return req.body;
  const out = {};
  for (const [k, v] of new URLSearchParams(String(req.body))) out[k] = v;
  return out;
}

function consentPage({
  googleEmail,
  clientName,
  clientId,
  redirectHost,
  scopes,
  csrf,
  fields,
}) {
  const hidden = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('');
  const scopeItems = scopes.map((s) => `<li>${escapeHtml(describeScope(s))} <code>${escapeHtml(s)}</code></li>`).join('');
  return htmlPage(
    'Authorize Application',
    '<h1>Authorize Application?</h1>' +
      `<p><strong>${escapeHtml(clientName || 'Unknown Client')}</strong> (<code>${escapeHtml(clientId)}</code>) wants to access Google Forms Manager AI and will redirect back to <code>${escapeHtml(redirectHost)}</code>.</p>` +
      `<p>Signed in to Google as <strong>${escapeHtml(googleEmail || 'your account')}</strong>. The grant will be bound to this Google account only.</p>` +
      '<p>Permissions requested:</p><ul>' +
      scopeItems +
      '</ul>' +
      '<form method="POST">' +
      hidden +
      `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}">` +
      '<button type="submit" name="decision" value="allow">Allow</button> ' +
      '<button type="submit" name="decision" value="deny">Deny</button>' +
      '</form>',
  );
}

// Validates request parameters (except session). Returns validated params or throws.
// Exported for tests (fetchImpl injectable).
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

function oauthError(code, description, status = 400) {
  const err = new Error(description);
  err.code = code;
  err.status = status;
  return err;
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
    return { redirect: errorRedirect(validated.redirectUri, 'access_denied', 'The user denied the request.', validated.state, issuerIdentifier()) };
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

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const store = createSupabaseOAuthStore();

  if (req.method === 'GET') {
    const googleSub = getUserId(req);
    if (!googleSub) return loginRequired(res);
    let validated;
    try {
      validated = await validateRequest(req.query || {});
    } catch (e) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(e?.status || 400).send(htmlPage('Authorization error', `<h1>Cannot start authorization</h1><p>${escapeHtml(e?.message || 'Invalid request.')}</p>`));
    }
    let redirectHost = '';
    try {
      redirectHost = new URL(validated.redirectUri).host;
    } catch {
      redirectHost = validated.redirectUri;
    }
    // Best-effort display email; failure only hides the email line.
    let googleEmail = null;
    try {
      const oauth2 = new (await import('googleapis')).google.auth.OAuth2();
      oauth2.setCredentials({ access_token: 'dummy' }); // We'll use a different approach
      const conn = await getGoogleConnection(googleSub);
      googleEmail = conn?.google_email || null;
    } catch {
      googleEmail = null;
    }
    const csrf = mintCsrfToken(googleSub);
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
      const { redirect } = await processAuthorizeDecision({ body, googleSub, store: createSupabaseOAuthStore() });
      return res.redirect(302, redirect);
    } catch (e) {
      if (e?.code === 'CSRF') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(403).send(htmlPage('Forbidden', `<h1>${escapeHtml(e.message)}</h1>`));
      }
      if (e?.code && e?.status) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.status(e.status).send(htmlPage('Authorization error', `<h1>Cannot complete authorization</h1><p>${escapeHtml(e.message)}</p>`));
      }
      console.error('Authorize failed:', e?.message || 'unknown error');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(500).send(htmlPage('Authorization error', '<h1>Could not complete authorization. Try again.</h1>'));
    }
  }

  res.setHeader('Allow', 'GET, POST');
  return res.status(405).send('Use GET or POST.');
}

// Import at the end to avoid circular dependency
const { getGoogleConnection } = await import('../../lib/google-connections.js');
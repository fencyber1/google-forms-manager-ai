// Full OAuth grant flow with injected store + stubbed CIMD fetch:
// consent decision issues a code, token exchange mints a bound pair,
// refresh rotates, and every step is tied to the Google sub.

// Set environment variables BEFORE importing modules that depend on them
process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'https://mcp-test.example.com';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-at-least-32-chars!!';

const { describe, it } = await import('node:test');
const assert = (await import('node:assert/strict')).default;
const { createHash } = await import('node:crypto');

// Dynamic imports after setting environment variables
const { processAuthorizeDecision } = await import('../lib/oauth-authorize.js');
const { processTokenGrant } = await import('../lib/oauth-token.js');
const { createMemoryOAuthStore, mintCsrfToken, validateMcpAccessToken } = await import('../lib/mcp-oauth.js');

const ISSUER = process.env.APP_BASE_URL;
const RESOURCE = `${process.env.APP_BASE_URL}/api/mcp`;
const CLIENT = 'https://chatgpt.com/oauth/client.json';
const REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const SUB = 'google-sub-9';
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = createHash('sha256').update('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'utf8').digest('base64url');

const CIMD_DOC = {
  redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  token_endpoint_auth_methods_supported: ['none'],
  client_name: 'ChatGPT',
};
const stubFetch = async () => ({
  status: 200,
  headers: { get: (n) => (n.toLowerCase() === 'content-type' ? 'application/json' : null) },
  body: null,
  text: async () => JSON.stringify(CIMD_DOC),
});

function consentBody(overrides = {}) {
  return {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    scope: 'forms:read offline_access',
    state: 'xyz-state',
    code_challenge: CHALLENGE,
    resource: RESOURCE,
    csrf: mintCsrfToken(SUB),
    decision: 'allow',
    ...overrides,
  };
}

describe('oauth grant flow', () => {
  it('consent allow → code redirect with iss + state; deny → error redirect with iss', async () => {
    const store = createMemoryOAuthStore();
    const { redirect } = await processAuthorizeDecision({ body: consentBody(), googleSub: SUB, store, fetchImpl: stubFetch });
    const url = new URL(redirect);
    assert.equal(`${url.origin}${url.pathname}`, REDIRECT);
    assert.ok(url.searchParams.get('code').startsWith('mcp_code_'));
    assert.equal(url.searchParams.get('iss'), ISSUER);
    assert.equal(url.searchParams.get('state'), 'xyz-state');

    const denied = await processAuthorizeDecision({ body: consentBody({ decision: 'deny' }), googleSub: SUB, store, fetchImpl: stubFetch });
    const durl = new URL(denied.redirect);
    assert.equal(durl.searchParams.get('error'), 'access_denied');
    assert.equal(durl.searchParams.get('iss'), ISSUER);
  });

  it('rejects bad CSRF and ignores user-supplied identity', async () => {
    const store = createMemoryOAuthStore();
    await assert.rejects(
      processAuthorizeDecision({ body: consentBody({ csrf: 'bad' }), googleSub: SUB, store, fetchImpl: stubFetch }),
      /expired form|Invalid/,
    );
    // Extra identity fields in the body change nothing: the grant binds to googleSub.
    const { redirect } = await processAuthorizeDecision({
      body: { ...consentBody(), user_id: 'attacker-sub', email: 'a@evil.example' },
      googleSub: SUB,
      store,
      fetchImpl: stubFetch,
    });
    const code = new URL(redirect).searchParams.get('code');
    const grant = await processTokenGrant(
      {
        grant_type: 'authorization_code',
        client_id: CLIENT,
        code,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
        resource: RESOURCE,
      },
      store,
      stubFetch,
    );
    const id = await validateMcpAccessToken(store, grant.access_token, { issuer: ISSUER, resource: RESOURCE });
    assert.equal(id.googleSub, SUB);
  });

  it('exchanges a code for a bound pair, then rotates via refresh', async () => {
    const store = createMemoryOAuthStore();
    const { redirect } = await processAuthorizeDecision({ body: consentBody(), googleSub: SUB, store, fetchImpl: stubFetch });
    const code = new URL(redirect).searchParams.get('code');
    const grant = await processTokenGrant(
      { grant_type: 'authorization_code', client_id: CLIENT, code, redirect_uri: REDIRECT, code_verifier: VERIFIER, resource: RESOURCE },
      store,
      stubFetch,
    );
    assert.ok(grant.access_token.startsWith('mcp_at_'));
    assert.ok(grant.refresh_token.startsWith('mcp_rt_'));
    assert.notEqual(grant.refresh_token, 'initial-refresh-token');
    const rotated = await processTokenGrant(
      { grant_type: 'refresh_token', client_id: CLIENT, refresh_token: grant.refresh_token, resource: RESOURCE },
      store,
      stubFetch,
    );
    assert.notEqual(rotated.refresh_token, grant.refresh_token);
    const id = await validateMcpAccessToken(store, rotated.access_token, { issuer: ISSUER, resource: RESOURCE });
    assert.equal(id.googleSub, SUB);
  });

  it('token endpoint rejects client_secret, bad grant, and resource mismatch', async () => {
    const store = createMemoryOAuthStore();
    const { redirect } = await processAuthorizeDecision({ body: consentBody(), googleSub: SUB, store, fetchImpl: stubFetch });
    const code = new URL(redirect).searchParams.get('code');
    await assert.rejects(
      processTokenGrant({ grant_type: 'authorization_code', client_id: CLIENT, client_secret: 'x' }, store, stubFetch),
      /public clients only/,
    );
    await assert.rejects(processTokenGrant({ grant_type: 'client_credentials' }, store, stubFetch), /authorization_code and refresh_token/);
    await assert.rejects(
      processTokenGrant({ grant_type: 'refresh_token', client_id: CLIENT, refresh_token: 'mcp_rt_x', resource: 'https://evil.example' }, store, stubFetch),
      /Unknown resource/,
    );
  });
});
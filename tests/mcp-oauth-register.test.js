// DCR client registration + DCR-mode authorize/token flows.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Set environment variables BEFORE importing modules that depend on them
process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'https://mcp-test.example.com';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-at-least-32-chars!!';

// Dynamic imports after setting environment variables
const { processClientRegistration } = await import('../lib/oauth-register.js');
const { processAuthorizeDecision } = await import('../lib/oauth-authorize.js');
const { processTokenGrant } = await import('../lib/oauth-token.js');
const { createMemoryOAuthStore, mintCsrfToken, validateMcpAccessToken } = await import('../lib/mcp-oauth.js');

const ISSUER = process.env.APP_BASE_URL;
const RESOURCE = `${process.env.APP_BASE_URL}/api/mcp`;
const SUB = 'google-sub-dcr';
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = createHash('sha256').update(VERIFIER, 'utf8').digest('base64url');
const STABLE = 'https://chatgpt.com/connector_platform_oauth_redirect';
const CALLBACK = 'https://chatgpt.com/connector/oauth/cb_dcr_1';

describe('dcr registration', () => {
  it('issues an opaque client bound to exact redirect URIs', async () => {
    const store = createMemoryOAuthStore();
    const res = await processClientRegistration(
      { redirect_uris: [STABLE, CALLBACK], client_name: 'ChatGPT' },
      store,
    );
    assert.ok(res.client_id.startsWith('mcp_client_'));
    assert.deepEqual(res.redirect_uris, [STABLE, CALLBACK]);
    assert.equal(res.token_endpoint_auth_method, 'none');
    assert.deepEqual(res.grant_types, ['authorization_code', 'refresh_token']);
    assert.deepEqual(res.response_types, ['code']);
    assert.equal(typeof res.client_id_issued_at, 'number');
    const stored = await store.getOAuthClient(res.client_id);
    assert.deepEqual(stored.redirect_uris, [STABLE, CALLBACK]);
  });

  it('rejects missing, foreign-host, non-https, duplicate, and oversized lists', async () => {
    const store = createMemoryOAuthStore();
    await assert.rejects(processClientRegistration({}, store), /redirect_uris/);
    await assert.rejects(processClientRegistration({ redirect_uris: [] }, store), /redirect_uris/);
    await assert.rejects(processClientRegistration({ redirect_uris: ['https://evil.example/cb'] }, store), /ChatGPT host/);
    await assert.rejects(processClientRegistration({ redirect_uris: ['http://chatgpt.com/cb'] }, store), /https/);
    await assert.rejects(processClientRegistration({ redirect_uris: [STABLE, STABLE] }, store), /Duplicate/);
    await assert.rejects(
      processClientRegistration({ redirect_uris: Array.from({ length: 11 }, (_, i) => `https://chatgpt.com/cb/${i}`) }, store),
      /max 10/,
    );
  });

  it('ignores caller-supplied grant and auth-method fields', async () => {
    const store = createMemoryOAuthStore();
    const res = await processClientRegistration(
      { redirect_uris: [STABLE], grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic' },
      store,
    );
    assert.deepEqual(res.grant_types, ['authorization_code', 'refresh_token']);
    assert.equal(res.token_endpoint_auth_method, 'none');
  });
});

describe('dcr-mode authorize + token', () => {
  async function registeredClient(store) {
    const res = await processClientRegistration({ redirect_uris: [CALLBACK], client_name: 'ChatGPT' }, store);
    return res.client_id;
  }

  function consentBody(clientId, overrides = {}) {
    return {
      client_id: clientId,
      redirect_uri: CALLBACK,
      scope: 'forms:read offline_access',
      state: 'dcr-state',
      code_challenge: CHALLENGE,
      resource: RESOURCE,
      csrf: mintCsrfToken(SUB),
      decision: 'allow',
      ...overrides,
    };
  }

  it('completes authorize → token → validate for a DCR client', async () => {
    const store = createMemoryOAuthStore();
    const clientId = await registeredClient(store);
    const { redirect } = await processAuthorizeDecision({
      body: consentBody(clientId), googleSub: SUB, store, fetchImpl: async () => { throw new Error('must not fetch'); },
    });
    const url = new URL(redirect);
    assert.ok(url.searchParams.get('code').startsWith('mcp_code_'));
    assert.equal(url.searchParams.get('iss'), ISSUER);
    const grant = await processTokenGrant(
      {
        grant_type: 'authorization_code', client_id: clientId, code: url.searchParams.get('code'),
        redirect_uri: CALLBACK, code_verifier: VERIFIER, resource: RESOURCE,
      },
      store,
      async () => { throw new Error('must not fetch'); },
    );
    assert.ok(grant.access_token.startsWith('mcp_at_'));
    const id = await validateMcpAccessToken(store, grant.access_token, { issuer: ISSUER, resource: RESOURCE });
    assert.equal(id.googleSub, SUB);
    assert.equal(id.clientId, clientId);
  });

  it('rejects unknown opaque client ids without fetching', async () => {
    const store = createMemoryOAuthStore();
    let fetched = false;
    await assert.rejects(
      processAuthorizeDecision({
        body: consentBody('mcp_client_unknown'), googleSub: SUB, store,
        fetchImpl: async () => { fetched = true; throw new Error('must not fetch'); },
      }),
      /Unknown OAuth client/,
    );
    assert.equal(fetched, false);
  });

  it('rejects a redirect not registered to the DCR client', async () => {
    const store = createMemoryOAuthStore();
    const clientId = await registeredClient(store);
    await assert.rejects(
      processAuthorizeDecision({
        body: consentBody(clientId, { redirect_uri: 'https://chatgpt.com/connector/oauth/other' }),
        googleSub: SUB, store, fetchImpl: async () => { throw new Error('must not fetch'); },
      }),
      /not registered/,
    );
  });
});

// Authorization codes: issuance, exact-once atomic redemption, PKCE +
// client + redirect + resource binding, and replay rejection.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  createMemoryOAuthStore,
  issueAuthorizationCode,
  redeemAuthorizationCode,
} from '../lib/mcp-oauth.js';

const BASE = {
  clientId: 'https://chatgpt.com/oauth/client.json',
  redirectUri: 'https://chatgpt.com/connector_platform_oauth_redirect',
  resource: 'https://mcp.example.com/api/mcp',
  googleSub: 'google-sub-1',
  scopes: ['forms:read'],
};
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = createHash('sha256').update(VERIFIER, 'utf8').digest('base64url');

async function freshGrant(store, overrides = {}) {
  const code = await issueAuthorizationCode(store, { ...BASE, challenge: CHALLENGE, ...overrides });
  return code;
}

function redeemParams(code, overrides = {}) {
  return {
    code,
    clientId: BASE.clientId,
    redirectUri: BASE.redirectUri,
    verifier: VERIFIER,
    resource: BASE.resource,
    ...overrides,
  };
}

describe('authorization codes', () => {
  it('redeems once, then rejects replay', async () => {
    const store = createMemoryOAuthStore();
    const code = await freshGrant(store);
    const grant = await redeemAuthorizationCode(store, redeemParams(code));
    assert.equal(grant.googleSub, 'google-sub-1');
    assert.deepEqual(grant.scopes, ['forms:read']);
    await assert.rejects(redeemAuthorizationCode(store, redeemParams(code)), /already used/);
  });

  it('exactly one concurrent redeemer wins', async () => {
    const store = createMemoryOAuthStore();
    const code = await freshGrant(store);
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => redeemAuthorizationCode(store, redeemParams(code))),
    );
    const won = results.filter((r) => r.status === 'fulfilled');
    assert.equal(won.length, 1);
  });

  it('rejects wrong verifier, client, redirect, and resource', async () => {
    const store = createMemoryOAuthStore();
    await assert.rejects(
      redeemAuthorizationCode(store, redeemParams(await freshGrant(store), { verifier: 'x'.repeat(43) })),
      /PKCE/,
    );
    await assert.rejects(
      redeemAuthorizationCode(store, redeemParams(await freshGrant(store), { clientId: 'https://other.example/c.json' })),
      /different client/,
    );
    await assert.rejects(
      redeemAuthorizationCode(store, redeemParams(await freshGrant(store), { redirectUri: 'https://chatgpt.com/other' })),
      /Redirect URI/,
    );
    await assert.rejects(
      redeemAuthorizationCode(store, redeemParams(await freshGrant(store), { resource: 'https://evil.example/api/mcp' })),
      /Resource mismatch/,
    );
  });

  it('rejects unknown codes', async () => {
    const store = createMemoryOAuthStore();
    await assert.rejects(redeemAuthorizationCode(store, redeemParams('mcp_code_bogus')), /invalid/);
  });
});

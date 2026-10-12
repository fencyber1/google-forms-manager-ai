// Token lifecycle: minting, validation chain (issuer/audience/expiry/
// revocation/scopes), refresh rotation, reuse detection revoking the
// family, revocation, and cross-user isolation.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createMemoryOAuthStore,
  mintTokenPair,
  refreshGrant,
  revokeTokens,
  validateMcpAccessToken,
} from '../lib/mcp-oauth.js';

const ISSUER = 'https://mcp.example.com';
const RESOURCE = 'https://mcp.example.com/api/mcp';
const CLIENT = 'https://chatgpt.com/oauth/client.json';

async function pair(store, overrides = {}) {
  return mintTokenPair(store, {
    googleSub: 'google-sub-1',
    clientId: CLIENT,
    scopes: ['forms:read', 'forms:write', 'offline_access'],
    audience: RESOURCE,
    issuer: ISSUER,
    ...overrides,
  });
}

function check(store, token, overrides = {}) {
  return validateMcpAccessToken(store, token, { issuer: ISSUER, resource: RESOURCE, ...overrides });
}

describe('mcp token validation', () => {
  it('accepts a fresh token and resolves identity', async () => {
    const store = createMemoryOAuthStore();
    const { accessToken } = await pair(store);
    const id = await check(store, accessToken, { requiredScopes: ['forms:read'] });
    assert.equal(id.googleSub, 'google-sub-1');
    assert.equal(id.clientId, CLIENT);
  });

  it('never mints Google tokens as MCP tokens', async () => {
    const store = createMemoryOAuthStore();
    const { accessToken, refreshToken } = await pair(store);
    assert.ok(accessToken.startsWith('mcp_at_'));
    assert.ok(refreshToken.startsWith('mcp_rt_'));
  });

  it('rejects unknown, revoked, expired, wrong-audience, wrong-issuer tokens', async () => {
    const store = createMemoryOAuthStore();
    await assert.rejects(check(store, 'mcp_at_bogus'), /Unknown/);
    const { accessToken } = await pair(store);
    await assert.rejects(check(store, accessToken, { resource: 'https://evil.example/api/mcp' }), /audience/);
    await assert.rejects(check(store, accessToken, { issuer: 'https://evil.example' }), /issuer/);
    await assert.rejects(check(store, accessToken, { requiredScopes: ['admin'] }), /scope/i);
    const revoked = (await pair(store)).accessToken;
    await revokeTokens(store, revoked);
    await assert.rejects(check(store, revoked), /revoked/);
  });

  it('rejects expired tokens by clock', async () => {
    const store = createMemoryOAuthStore();
    const { accessToken } = await pair(store);
    await assert.rejects(
      check(store, accessToken, { now: Date.now() + 60 * 60 * 1000 }),
      /expired/,
    );
  });
});

describe('refresh rotation', () => {
  it('rotates refresh tokens and keeps the family usable once', async () => {
    const store = createMemoryOAuthStore();
    const first = await pair(store);
    const second = await refreshGrant(store, { refreshToken: first.refreshToken, clientId: CLIENT, issuer: ISSUER, resource: RESOURCE });
    assert.ok(second.accessToken.startsWith('mcp_at_'));
    assert.ok(second.refreshToken.startsWith('mcp_rt_'));
    assert.notEqual(second.refreshToken, first.refreshToken);
    const id = await check(store, second.accessToken, { requiredScopes: ['forms:write'] });
    assert.equal(id.googleSub, 'google-sub-1');
  });

  it('reusing a rotated refresh token revokes the whole family', async () => {
    const store = createMemoryOAuthStore();
    const first = await pair(store);
    const second = await refreshGrant(store, { refreshToken: first.refreshToken, clientId: CLIENT, issuer: ISSUER, resource: RESOURCE });
    await assert.rejects(
      refreshGrant(store, { refreshToken: first.refreshToken, clientId: CLIENT, issuer: ISSUER, resource: RESOURCE }),
      /already used/,
    );
    // Family revoked: the successor access AND refresh tokens are dead too.
    await assert.rejects(check(store, second.accessToken), /revoked/);
    await assert.rejects(
      refreshGrant(store, { refreshToken: second.refreshToken, clientId: CLIENT, issuer: ISSUER, resource: RESOURCE }),
      /already used|invalid/,
    );
  });

  it('rejects refresh bound to another client', async () => {
    const store = createMemoryOAuthStore();
    const first = await pair(store);
    await assert.rejects(
      refreshGrant(store, { refreshToken: first.refreshToken, clientId: 'https://other.example/c.json', issuer: ISSUER, resource: RESOURCE }),
      /different client/,
    );
  });
});

describe('cross-user isolation', () => {
  it("user A's token never resolves user B", async () => {
    const store = createMemoryOAuthStore();
    const a = await pair(store, { googleSub: 'google-sub-A' });
    await pair(store, { googleSub: 'google-sub-B' });
    const id = await check(store, a.accessToken);
    assert.equal(id.googleSub, 'google-sub-A');
  });
});

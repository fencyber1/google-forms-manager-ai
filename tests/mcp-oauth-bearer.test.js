// Bearer-first gate: a supplied-but-invalid Bearer token must ALWAYS be
// rejected, even when a valid cookie session is present. No cookie
// fallback on Bearer failure.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { authorizeMcpRequest } from '../api/mcp.js';
import { createMemoryOAuthStore, mintTokenPair } from '../lib/mcp-oauth.js';

process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'https://mcp-test.example.com';

const ISSUER = process.env.APP_BASE_URL;
const RESOURCE = `${process.env.APP_BASE_URL}/api/mcp`;
const CLIENT = 'https://chatgpt.com/oauth/client.json';

function mockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    setHeader(name, value) {
      res.headers[name.toLowerCase()] = value;
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(obj) {
      res.body = obj;
      return res;
    },
  };
  return res;
}

function reqWith({ bearer, cookie } = {}) {
  const headers = {};
  if (bearer !== undefined) headers.authorization = `Bearer ${bearer}`;
  if (cookie !== undefined) headers.cookie = cookie;
  return { method: 'POST', headers };
}

async function seededStore() {
  const store = createMemoryOAuthStore();
  const pair = await mintTokenPair(store, {
    googleSub: 'google-sub-1',
    clientId: CLIENT,
    scopes: ['forms:read', 'offline_access'],
    audience: RESOURCE,
    issuer: ISSUER,
  });
  return { store, pair };
}

describe('bearer-first gate (no cookie fallback)', () => {
  it('rejects a bogus Bearer token despite a valid cookie', async () => {
    const { store } = await seededStore();
    const req = reqWith({ bearer: 'mcp_at_bogus', cookie: 'gfm_session=valid-looking-cookie' });
    const res = mockRes();
    const cont = await authorizeMcpRequest(req, res, store);
    assert.equal(cont, false);
    assert.equal(res.statusCode, 401);
    assert.ok(String(res.headers['www-authenticate'] || '').includes('resource_metadata'));
    assert.equal(req.mcpAuth, undefined);
  });

  it('rejects an expired Bearer token despite a valid cookie', async () => {
    const { store, pair } = await seededStore();
    const { revokeTokens } = await import('../lib/mcp-oauth.js');
    // Revoke to simulate a dead token presented alongside a live cookie.
    await revokeTokens(store, pair.accessToken);
    const req = reqWith({ bearer: pair.accessToken, cookie: 'gfm_session=valid-looking-cookie' });
    const res = mockRes();
    const cont = await authorizeMcpRequest(req, res, store);
    assert.equal(cont, false);
    assert.equal(res.statusCode, 401);
    assert.equal(req.mcpAuth, undefined);
  });

  it('rejects a wrong-audience Bearer token', async () => {
    const { store } = await seededStore();
    const wrong = await mintTokenPair(store, {
      googleSub: 'google-sub-1',
      clientId: CLIENT,
      scopes: ['forms:read'],
      audience: 'https://evil.example/api/mcp',
      issuer: ISSUER,
    });
    const req = reqWith({ bearer: wrong.accessToken });
    const res = mockRes();
    const cont = await authorizeMcpRequest(req, res, store);
    assert.equal(cont, false);
    assert.equal(res.statusCode, 401);
  });

  it('accepts a valid Bearer token and attaches identity (no cookie needed)', async () => {
    const { store, pair } = await seededStore();
    const req = reqWith({ bearer: pair.accessToken });
    const res = mockRes();
    const cont = await authorizeMcpRequest(req, res, store);
    assert.equal(cont, true);
    assert.equal(req.mcpAuth.googleSub, 'google-sub-1');
    assert.deepEqual(req.mcpAuth.scopes, ['forms:read']);
  });

  it('passes through when no Bearer is present (cookie path preserved)', async () => {
    const { store } = await seededStore();
    const req = reqWith({ cookie: 'gfm_session=whatever' });
    const res = mockRes();
    const cont = await authorizeMcpRequest(req, res, store);
    assert.equal(cont, true);
    assert.equal(req.mcpAuth, undefined);
    assert.equal(res.statusCode, 200);
  });
});

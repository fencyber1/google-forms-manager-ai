// PKCE S256, CSRF binding, CIMD validation, and exact redirect matching.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  STABLE_CHATGPT_REDIRECT,
  fetchCimd,
  mintCsrfToken,
  normalizeMcpScopes,
  validateRedirectUri,
  verifyCsrfToken,
  verifyPkceS256,
} from '../lib/mcp-oauth.js';

process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret-at-least-32-chars!!';

function s256(verifier) {
  return createHash('sha256').update(verifier, 'utf8').digest('base64url');
}

const CIMD_DOC = {
  redirect_uris: ['https://chatgpt.com/connector/oauth/cb_123'],
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
  client_name: 'ChatGPT',
};

function stubFetch(doc = CIMD_DOC, status = 200) {
  return async () => ({
    status,
    headers: { get: (name) => (name.toLowerCase() === 'content-type' ? 'application/json' : null) },
    body: null,
    text: async () => JSON.stringify(doc),
  });
}

describe('pkce s256', () => {
  it('accepts a correct verifier', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    assert.equal(verifyPkceS256(verifier, s256(verifier)), true);
  });

  it('rejects wrong verifiers, short verifiers, and plain method bypass', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    assert.equal(verifyPkceS256('x'.repeat(43), s256(verifier)), false);
    assert.equal(verifyPkceS256('short', s256('short')), false);
    assert.equal(verifyPkceS256('', ''), false);
  });
});

describe('csrf binding', () => {
  it('validates tokens for the same sub and rejects others', () => {
    const token = mintCsrfToken('sub-A');
    assert.equal(verifyCsrfToken(token, 'sub-A'), true);
    assert.equal(verifyCsrfToken(token, 'sub-B'), false);
    assert.equal(verifyCsrfToken('garbage', 'sub-A'), false);
    assert.equal(verifyCsrfToken(`${Date.now() - 20 * 60 * 1000}.deadbeef`, 'sub-A'), false);
  });
});

describe('cimd validation', () => {
  it('accepts a valid ChatGPT metadata document', async () => {
    const cimd = await fetchCimd('https://chatgpt.com/oauth/client.json', stubFetch());
    assert.deepEqual(cimd.redirectUris, CIMD_DOC.redirect_uris);
    assert.equal(cimd.clientName, 'ChatGPT');
  });

  it('rejects non-HTTPS client IDs', async () => {
    await assert.rejects(fetchCimd('http://chatgpt.com/oauth/client.json', stubFetch()), /HTTPS/);
  });

  it('rejects documents without redirect_uris or without none auth', async () => {
    await assert.rejects(fetchCimd('https://chatgpt.com/oauth/client.json', stubFetch({})), /redirect_uris/);
    await assert.rejects(
      fetchCimd(
        'https://chatgpt.com/oauth/client.json',
        stubFetch({ ...CIMD_DOC, token_endpoint_auth_methods_supported: ['private_key_jwt'] }),
      ),
      /not supported/,
    );
  });

  it('rejects oversized documents', async () => {
    const big = async () => ({
      status: 200,
      headers: { get: () => 'application/json' },
      body: null,
      text: async () => 'x'.repeat(64 * 1024),
    });
    await assert.rejects(fetchCimd('https://chatgpt.com/oauth/client.json', big), /too large/);
  });
});

describe('redirect validation', () => {
  const cimd = { redirectUris: ['https://chatgpt.com/connector/oauth/cb_123'] };

  it('accepts the exact stable redirect without a CIMD document', () => {
    assert.equal(validateRedirectUri(STABLE_CHATGPT_REDIRECT, null), STABLE_CHATGPT_REDIRECT);
  });

  it('accepts an exact CIMD-listed callback URI', () => {
    assert.equal(
      validateRedirectUri('https://chatgpt.com/connector/oauth/cb_123', cimd),
      'https://chatgpt.com/connector/oauth/cb_123',
    );
  });

  it('rejects unlisted, foreign-host, and non-HTTPS URIs', () => {
    assert.throws(() => validateRedirectUri('https://chatgpt.com/connector/oauth/other', cimd), /not registered/);
    assert.throws(() => validateRedirectUri('https://evil.com/connector/oauth/cb_123', cimd), /not allowed/);
    assert.throws(() => validateRedirectUri('http://chatgpt.com/connector/oauth/cb_123', cimd), /not allowed/);
    assert.throws(() => validateRedirectUri('not-a-url', cimd), /invalid/);
  });
});

describe('scope normalization', () => {
  it('keeps known scopes and requires a forms scope', () => {
    assert.deepEqual(normalizeMcpScopes('forms:read offline_access'), ['forms:read', 'offline_access']);
    assert.throws(() => normalizeMcpScopes('offline_access'), /forms:read or forms:write/);
    assert.throws(() => normalizeMcpScopes(''), /forms:read or forms:write/);
  });
});

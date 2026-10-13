// OAuth metadata + routing: well-known documents have the exact shapes
// ChatGPT requires, and vercel.json rewrites map the public URLs.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { protectedResourceMetadata } from '../api/well-known/oauth-protected-resource.js';
import { authorizationServerMetadata } from '../api/well-known/oauth-authorization-server.js';

process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'https://mcp-test.example.com';

describe('oauth metadata', () => {
  it('protected resource metadata matches the authorization server', () => {
    const prm = protectedResourceMetadata();
    const asm = authorizationServerMetadata();
    assert.equal(prm.resource, `${process.env.APP_BASE_URL}/api/mcp`);
    assert.deepEqual(prm.authorization_servers, [asm.issuer]);
    assert.ok(prm.scopes_supported.includes('forms:read'));
    assert.ok(prm.scopes_supported.includes('forms:write'));
    assert.ok(!prm.scopes_supported.includes('offline_access'), 'offline_access is not a resource requirement');
  });

  it('authorization server metadata satisfies ChatGPT requirements', () => {
    const asm = authorizationServerMetadata();
    assert.equal(asm.issuer, process.env.APP_BASE_URL);
    assert.ok(asm.authorization_endpoint.startsWith(asm.issuer));
    assert.ok(asm.token_endpoint.startsWith(asm.issuer));
    assert.ok(asm.revocation_endpoint.startsWith(asm.issuer));
    assert.deepEqual(asm.response_types_supported, ['code']);
    assert.ok(asm.grant_types_supported.includes('authorization_code'));
    assert.ok(asm.grant_types_supported.includes('refresh_token'));
    assert.ok(asm.code_challenge_methods_supported.includes('S256'));
    assert.deepEqual(asm.token_endpoint_auth_methods_supported, ['none']);
    assert.equal(asm.client_id_metadata_document_supported, true);
    assert.equal(asm.authorization_response_iss_parameter_supported, true);
    assert.ok('registration_endpoint' in asm, 'DCR is now supported: registration endpoint advertised');
  });

  it('vercel.json rewrites serve both well-known URLs', () => {
    const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
    const map = Object.fromEntries((vercel.rewrites || []).map((r) => [r.source, r.destination]));
    assert.equal(map['/.well-known/oauth-protected-resource'], '/api/well-known/oauth-protected-resource');
    assert.equal(map['/.well-known/oauth-authorization-server'], '/api/well-known/oauth-authorization-server');
  });
});

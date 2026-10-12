// get_profile: stable opaque id (Google sub), display-only metadata,
// structuredContent + text mirror, auth-failure behavior.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { TOOL_DEFINITIONS, getProfileOperation, runAuthenticatedTool } from '../lib/mcp-tools.js';

const load = async (sub) => ({ google_email: sub === 'google-sub-1' ? 'alex@example.com' : null });

describe('get_profile', () => {
  it('is registered with the openai/profile marker and output schema', () => {
    const tool = TOOL_DEFINITIONS.find((t) => t.name === 'get_profile');
    assert.ok(tool);
    assert.equal(tool.meta?.['openai/profile'], true);
    assert.ok(tool.outputShape);
    assert.deepEqual(Object.keys(tool.shape), []);
  });

  it('returns the stable sub id with display metadata', async () => {
    const res = await getProfileOperation({}, {}, { googleSub: 'google-sub-1' }, load);
    assert.equal(res.isError, undefined);
    assert.equal(res.structuredContent.id, 'google-sub-1');
    assert.equal(res.structuredContent.email, 'alex@example.com');
    assert.equal(JSON.parse(res.content[0].text).id, 'google-sub-1');
  });

  it('keeps the same id across calls and omits missing display fields', async () => {
    const a = await getProfileOperation({}, {}, { googleSub: 'google-sub-2' }, load);
    const b = await getProfileOperation({}, {}, { googleSub: 'google-sub-2' }, load);
    assert.equal(a.structuredContent.id, b.structuredContent.id);
    assert.ok(!('email' in a.structuredContent));
  });

  it('fails safely without an identity (never another profile)', async () => {
    const res = await getProfileOperation({}, {}, { googleSub: null }, load);
    assert.equal(res.isError, true);
  });

  it('runs through the authenticated tool runner for the caller only', async () => {
    const tool = TOOL_DEFINITIONS.find((t) => t.name === 'get_profile');
    // Bearer-style request: identity from req.mcpAuth, client from resolver.
    const res = await runAuthenticatedTool(
      { headers: {}, mcpAuth: { googleSub: 'google-sub-1', scopes: [] } },
      tool.operation,
      {},
      async () => ({ marker: 'client' }),
    );
    assert.equal(res.isError, undefined);
    // getGoogleConnection has no Supabase env here, so only the stable id resolves.
    assert.equal(JSON.parse(res.content[0].text).id, 'google-sub-1');
    // No identity anywhere → safe auth error, never another profile.
    const anon = await runAuthenticatedTool({ headers: {} }, tool.operation, {}, async () => ({ marker: 'client' }));
    assert.equal(anon.isError, true);
  });
});

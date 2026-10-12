// Authentication failure: unauthenticated tool calls must fail safely —
// clear reconnect guidance, no tokens/secrets/keys in the output.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runAuthenticatedTool, TOOL_DEFINITIONS } from '../lib/mcp-tools.js';
import { toMcpAuthErrorContent } from '../lib/mcp-auth.js';

const SENSITIVE = ['ya29.', 'refresh_token', 'access_token', 'TOKEN_ENCRYPTION_KEY', 'SUPABASE_SECRET_KEY', 'SESSION_SECRET'];

function assertNoSecrets(text) {
  for (const marker of SENSITIVE) {
    assert.ok(!text.includes(marker), `leaked sensitive marker: ${marker}`);
  }
}

function unauthenticated() {
  const err = new Error('Google is not connected. Open /api/auth/google to connect first.');
  err.code = 'UNAUTHENTICATED';
  throw err;
}

function expired() {
  const err = new Error('Google connection expired. Open /api/auth/google to reconnect.');
  err.code = 'RECONNECT_REQUIRED';
  throw err;
}

describe('mcp authentication failure', () => {
  for (const tool of TOOL_DEFINITIONS) {
    it(`${tool.name}: rejects unauthenticated callers with guidance`, async () => {
      const args = tool.name === 'create_google_form' ? { title: 'T' } : { formId: 'abc' };
      const result = await runAuthenticatedTool({ headers: {} }, tool.operation, args, unauthenticated);
      assert.equal(result.isError, true);
      const text = result.content.map((c) => c.text).join('\n');
      assert.match(text, /connect/i);
      assertNoSecrets(text);
    });
  }

  it('maps expired grants to reconnect guidance', async () => {
    const tool = TOOL_DEFINITIONS.find((t) => t.name === 'get_google_form');
    const result = await runAuthenticatedTool({ headers: {} }, tool.operation, { formId: 'abc' }, expired);
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /reconnect/i);
    assertNoSecrets(result.content[0].text);
  });

  it('never exposes upstream error internals', async () => {
    const failing = async () => {
      throw new Error('supabase exploded with TOKEN_ENCRYPTION_KEY=abc ya29.secret');
    };
    const result = await runAuthenticatedTool(
      { headers: {} },
      failing,
      {},
      async () => ({ marker: 'auth-ok' }),
    );
    assert.equal(result.isError, true);
    assertNoSecrets(result.content.map((c) => c.text).join('\n'));
  });

  it('toMcpAuthErrorContent always returns isError content', () => {
    for (const code of ['UNAUTHENTICATED', 'RECONNECT_REQUIRED', 'UPSTREAM', undefined]) {
      const err = new Error('x');
      err.code = code;
      const out = toMcpAuthErrorContent(err);
      assert.equal(out.isError, true);
      assert.ok(out.content[0].text.length > 0);
    }
  });
});

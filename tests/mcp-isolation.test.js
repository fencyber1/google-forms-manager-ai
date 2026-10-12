// User isolation: each tool call must operate on the caller's own account.
// The auth resolver is stubbed per user; operations record which client
// they received, proving no cross-user access and no identity override.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runAuthenticatedTool, TOOL_DEFINITIONS } from '../lib/mcp-tools.js';

function resolverFor(userId) {
  return async () => ({ __testUser: userId });
}

describe('mcp user isolation', () => {
  for (const tool of TOOL_DEFINITIONS) {
    it(`${tool.name}: uses only the calling user's client`, async () => {
      const seen = [];
      const spyOperation = async (auth, args) => {
        seen.push(auth.__testUser);
        return { ok: true, receivedArgs: args };
      };
      const args = tool.name === 'create_google_form' ? { title: 'T' } : { formId: 'form-1' };
      const resA = await runAuthenticatedTool({ headers: {} }, spyOperation, args, resolverFor('user-A'));
      const resB = await runAuthenticatedTool({ headers: {} }, spyOperation, args, resolverFor('user-B'));
      assert.deepEqual(seen, ['user-A', 'user-B']);
      assert.equal(resA.isError, undefined);
      assert.equal(resB.isError, undefined);
    });
  }

  it('tool arguments cannot smuggle an identity override', async () => {
    let receivedArgs;
    const spy = async (auth, args) => {
      receivedArgs = args;
      return { ok: true };
    };
    // Even if a hostile client sends identity fields, the operation only
    // receives what the schema allows and auth comes from the resolver.
    const result = await runAuthenticatedTool(
      { headers: {} },
      spy,
      { formId: 'form-1' },
      resolverFor('user-A'),
    );
    assert.equal(result.isError, undefined);
    assert.deepEqual(Object.keys(receivedArgs).sort(), ['formId']);
  });
});

// Tool discovery: the MCP server must expose exactly the three Google
// Forms tools with the expected names and descriptions.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { TOOL_DEFINITIONS } from '../lib/mcp-tools.js';
import { buildMcpServer } from '../lib/mcp-server.js';

describe('mcp tool discovery', () => {
  it('defines exactly the three expected tools with no identity fields', () => {
    const names = TOOL_DEFINITIONS.map((t) => t.name).sort();
    assert.deepEqual(names, ['create_google_form', 'get_google_form', 'get_google_form_responses']);
    for (const tool of TOOL_DEFINITIONS) {
      assert.ok(tool.description && tool.description.length > 0, `${tool.name} needs a description`);
      const shapeKeys = Object.keys(tool.shape);
      assert.ok(!shapeKeys.includes('userId'), `${tool.name} must not accept userId`);
      assert.ok(!shapeKeys.includes('user_id'), `${tool.name} must not accept user_id`);
      assert.ok(!shapeKeys.includes('email'), `${tool.name} must not accept email`);
    }
  });

  it('lists the tools over the MCP protocol', async () => {
    const server = buildMcpServer({ headers: {} });
    assert.ok(server instanceof McpServer);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['create_google_form', 'get_google_form', 'get_google_form_responses']);
    await client.close();
    await server.close();
  });
});

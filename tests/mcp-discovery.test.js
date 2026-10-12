// Tool discovery: the MCP server must expose the Google Forms tools plus
// get_profile, with OAuth securitySchemes advertised per the official
// OpenAI requirements, and no identity fields in any input schema.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { TOOL_DEFINITIONS } from '../lib/mcp-tools.js';
import { buildMcpServer } from '../lib/mcp-server.js';

const EXPECTED = ['create_google_form', 'get_google_form', 'get_google_form_responses', 'get_profile'];

describe('mcp tool discovery', () => {
  it('defines exactly the expected tools with no identity fields', () => {
    const names = TOOL_DEFINITIONS.map((t) => t.name).sort();
    assert.deepEqual(names, [...EXPECTED].sort());
    for (const tool of TOOL_DEFINITIONS) {
      assert.ok(tool.description && tool.description.length > 0, `${tool.name} needs a description`);
      const shapeKeys = Object.keys(tool.shape);
      assert.ok(!shapeKeys.includes('userId'), `${tool.name} must not accept userId`);
      assert.ok(!shapeKeys.includes('user_id'), `${tool.name} must not accept user_id`);
      assert.ok(!shapeKeys.includes('email'), `${tool.name} must not accept email`);
      assert.ok(Array.isArray(tool.securitySchemes) && tool.securitySchemes.length > 0, `${tool.name} must declare securitySchemes`);
      assert.equal(tool.securitySchemes[0].type, 'oauth2');
    }
  });

  it('lists the tools over the MCP protocol with securitySchemes', async () => {
    const server = buildMcpServer({ headers: {} });
    assert.ok(server instanceof McpServer);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '0.0.0' });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, [...EXPECTED].sort());
    const profile = tools.find((t) => t.name === 'get_profile');
    assert.equal(profile._meta?.['openai/profile'], true);
    assert.ok(profile.outputSchema, 'get_profile must publish outputSchema');
    await client.close();
    await server.close();
  });

  it('emits securitySchemes on the wire (client SDK strips unknown keys when parsing)', async () => {
    // The installed SDK's ToolSchema has no securitySchemes field, so the
    // high-level client's parsed output cannot carry it. ChatGPT parses raw
    // JSON-RPC, so assert on the raw wire response instead.
    const server = buildMcpServer({ headers: {} });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await clientTransport.start();
    const pending = new Map();
    clientTransport.onmessage = (msg) => {
      if (msg && typeof msg === 'object' && 'id' in msg && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    };
    const request = (method, params, id) =>
      new Promise((resolve) => {
        pending.set(id, resolve);
        clientTransport.send({ jsonrpc: '2.0', id, method, params });
      });
    const init = await request('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } }, 'init');
    assert.ok(init.result, 'initialize must succeed');
    await clientTransport.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const listed = await request('tools/list', {}, 'list-1');
    const tools = listed.result.tools;
    assert.equal(tools.length, EXPECTED.length);
    for (const tool of tools) {
      assert.ok(Array.isArray(tool.securitySchemes), `${tool.name} must advertise securitySchemes on the wire`);
      assert.equal(tool.securitySchemes[0].type, 'oauth2');
    }
    await server.close();
  });
});

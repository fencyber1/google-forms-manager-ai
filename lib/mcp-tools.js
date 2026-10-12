// Server-only MCP tool definitions for Google Forms.
//
// Each tool is a pure function of (auth, args): the authenticated OAuth2
// client is always supplied by the MCP server from the current session
// (lib/mcp-auth.js) and tool schemas deliberately contain NO user ID or
// email fields, so a caller can never request another user's account.
// Tool results and errors never include tokens, secrets, or keys, and these
// tools never send messages, emails, or form replies.
import { z } from 'zod';
import { createForm, getForm, listFormResponses } from './forms-service.js';
import { resolveMcpClient, toMcpAuthErrorContent } from './mcp-auth.js';

const questionSchema = z
  .object({
    title: z.string().min(1).max(300),
    type: z.enum(['short', 'paragraph', 'multiple_choice', 'checkboxes', 'dropdown']).default('short'),
    required: z.boolean().default(false),
    options: z.array(z.string().min(1).max(500)).max(50).optional(),
  })
  .strict();

export const createGoogleFormShape = {
  title: z.string().min(1).max(300),
  questions: z.array(questionSchema).max(50).default([]),
};

// Strict object schema for direct validation (tests, reuse). The raw
// `*Shape` above is what gets registered with the MCP SDK.
export const createGoogleFormSchema = z.object(createGoogleFormShape).strict();

export const formIdShape = {
  formId: z.string().min(1).max(256),
};

export const formIdSchema = z.object(formIdShape).strict();

function textResult(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data) }] };
}

function toolError(message) {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function toToolError(err) {
  if (err?.code === 'VALIDATION' || err?.name === 'ZodError') {
    return toolError(`Invalid input: ${err.message}`);
  }
  // Never leak internals, tokens, or secrets.
  return toolError('The Google Forms operation failed. Confirm the inputs and that the connected Google account has access.');
}

// Runs a tool with the authenticated user's client. `req` is the incoming
// HTTP request (session cookie identifies the user); `operation` receives
// the authenticated client and validated args. `clientResolver` defaults to
// the real cookie-session resolver and is injectable for tests.
export async function runAuthenticatedTool(req, operation, args, clientResolver = resolveMcpClient) {
  let auth;
  try {
    auth = await clientResolver(req);
  } catch (authErr) {
    return toMcpAuthErrorContent(authErr);
  }
  try {
    return textResult(await operation(auth, args));
  } catch (e) {
    if (e?.code === 'RECONNECT_REQUIRED' || e?.code === 'UNAUTHENTICATED') {
      return toMcpAuthErrorContent(e);
    }
    return toToolError(e);
  }
}

export const TOOL_DEFINITIONS = [
  {
    name: 'create_google_form',
    description:
      'Create a Google Form in the connected Google account with a title and up to 50 questions. Read-only otherwise; never sends messages or emails.',
    shape: createGoogleFormShape,
    schema: createGoogleFormSchema,
    operation: (auth, args) => createForm(auth, args),
  },
  {
    name: 'get_google_form',
    description: "Retrieve a Google Form's details and questions from the connected Google account by form ID.",
    shape: formIdShape,
    schema: formIdSchema,
    operation: (auth, args) => getForm(auth, args),
  },
  {
    name: 'get_google_form_responses',
    description: 'Retrieve responses for a Google Form in the connected Google account by form ID.',
    shape: formIdShape,
    schema: formIdSchema,
    operation: (auth, args) => listFormResponses(auth, args),
  },
];

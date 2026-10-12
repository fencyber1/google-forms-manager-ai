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
import { getGoogleConnection } from './google-connections.js';
import { getUserId } from './session.js';
import { resolveMcpClient, toMcpAuthErrorContent } from './mcp-auth.js';
import { canonicalBase } from './mcp-oauth.js';

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

function isMcpResult(value) {
  return value && typeof value === 'object' && Array.isArray(value.content);
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

// Builds the tool-level OAuth challenge payload that tells ChatGPT to
// surface its linking UI. Contains error + error_description as required.
export function wwwAuthenticateMeta(error, errorDescription) {
  let metadataUrl = '';
  try {
    metadataUrl = `${canonicalBase()}/.well-known/oauth-protected-resource`;
  } catch {
    metadataUrl = '';
  }
  return {
    'mcp/www_authenticate': [
      `Bearer resource_metadata="${metadataUrl}", error="${error}", error_description="${errorDescription}"`,
    ],
  };
}

function authErrorResult(err) {
  const base = toMcpAuthErrorContent(err);
  return {
    ...base,
    _meta: wwwAuthenticateMeta('invalid_token', 'Connect your Google account to continue.'),
  };
}

// Runs a tool with the authenticated user's client. `req` is the incoming
// HTTP request (session cookie or validated Bearer identity in
// req.mcpAuth); `operation` receives (auth, args, ctx) where ctx carries
// { googleSub, scopes }. `clientResolver` defaults to the real cookie-session
// resolver and is injectable for tests. When `grantedScopes` is provided
// (Bearer path), the tool's requiredScopes are enforced; the cookie path
// passes null (full Google grant, existing behavior).
export async function runAuthenticatedTool(req, operation, args, clientResolver = resolveMcpClient, grantedScopes = null) {
  let auth;
  try {
    auth = await clientResolver(req);
  } catch (authErr) {
    return authErrorResult(authErr);
  }
  const ctx = {
    googleSub: req?.mcpAuth?.googleSub || getUserId(req) || null,
    scopes: grantedScopes,
  };
  const requiredScopes = operation.requiredScopes || [];
  if (grantedScopes && !requiredScopes.every((s) => grantedScopes.includes(s))) {
    return {
      content: [{ type: 'text', text: 'Insufficient scope for this operation. Reconnect with the required permissions.' }],
      _meta: wwwAuthenticateMeta('insufficient_scope', 'Additional permissions are required.'),
      isError: true,
    };
  }
  try {
    const out = await operation(auth, args, ctx);
    // Operations return raw data (auto-wrapped) or a complete MCP result
    // object (passed through, e.g. get_profile's structuredContent).
    return isMcpResult(out) ? out : textResult(out);
  } catch (e) {
    if (e?.code === 'RECONNECT_REQUIRED' || e?.code === 'UNAUTHENTICATED') {
      return authErrorResult(e);
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
    requiredScopes: ['forms:write'],
    securitySchemes: [{ type: 'oauth2', scopes: ['forms:write'] }],
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    operation: (auth, args) => createForm(auth, args),
  },
  {
    name: 'get_google_form',
    description: "Retrieve a Google Form's details and questions from the connected Google account by form ID.",
    shape: formIdShape,
    schema: formIdSchema,
    requiredScopes: ['forms:read'],
    securitySchemes: [{ type: 'oauth2', scopes: ['forms:read'] }],
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    operation: (auth, args) => getForm(auth, args),
  },
  {
    name: 'get_google_form_responses',
    description: 'Retrieve responses for a Google Form in the connected Google account by form ID.',
    shape: formIdShape,
    schema: formIdSchema,
    requiredScopes: ['forms:read'],
    securitySchemes: [{ type: 'oauth2', scopes: ['forms:read'] }],
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    operation: (auth, args) => listFormResponses(auth, args),
  },
  {
    name: 'get_profile',
    description:
      "Return the profile represented by this request's authenticated credentials. The opaque id is the stable Google account ID and never changes across token refresh, reconnection, or display-metadata changes.",
    shape: {},
    schema: z.object({}).strict(),
    requiredScopes: [],
    securitySchemes: [{ type: 'oauth2', scopes: [] }],
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    outputShape: {
      id: z.string().min(1),
      name: z.string().optional(),
      email: z.string().optional(),
      nickname: z.string().optional(),
    },
    meta: { 'openai/profile': true },
    operation: getProfileOperation,
  },
];

// Attach required scopes to the operation functions so the runner can
// enforce them without changing its call signature.
for (const tool of TOOL_DEFINITIONS) {
  tool.operation.requiredScopes = tool.requiredScopes;
}

async function getProfileOperation(auth, args, ctx, loadConnection = getGoogleConnection) {
  void auth;
  void args;
  if (!ctx?.googleSub) {
    return authErrorResult({ code: 'UNAUTHENTICATED', message: 'Google is not connected.' });
  }
  let email = null;
  try {
    email = (await loadConnection(ctx.googleSub))?.google_email || null;
  } catch {
    email = null;
  }
  const profile = { id: String(ctx.googleSub) };
  if (email) {
    profile.email = email;
    const local = email.split('@')[0];
    if (local) profile.nickname = local;
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(profile) }],
    structuredContent: profile,
  };
}

export { getProfileOperation };

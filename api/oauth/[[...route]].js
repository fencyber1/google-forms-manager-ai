// OAuth route dispatcher (single serverless function for the Hobby plan
// 12-function limit). Delegates /api/oauth/<authorize|token|revoke|register>
// to the implementations in lib/oauth-*.js. Endpoint behavior is unchanged:
// each delegated handler owns its methods, auth, and error responses.
import authorizeHandler from '../../lib/oauth-authorize.js';
import tokenHandler from '../../lib/oauth-token.js';
import revokeHandler from '../../lib/oauth-revoke.js';
import registerHandler from '../../lib/oauth-register.js';

const ROUTES = {
  authorize: authorizeHandler,
  token: tokenHandler,
  revoke: revokeHandler,
  register: registerHandler,
};

export default async function handler(req, res) {
  const segments = req.query?.all;
  const name = Array.isArray(segments) ? segments[0] : segments;
  const fn = typeof name === 'string' ? ROUTES[name] : undefined;
  if (!fn) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(404).json({ error: 'invalid_request', error_description: 'Unknown OAuth endpoint.' });
  }
  return fn(req, res);
}

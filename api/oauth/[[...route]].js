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

function extractRouteName(routeParam) {
  if (!routeParam) return null;
  // Handle both array and string formats
  if (Array.isArray(routeParam)) {
    return routeParam[0];
  }
  if (typeof routeParam === 'string') {
    // Handle cases where route might be a string like "authorize" or "authorize/"
    return routeParam.split('/')[0].split('?')[0];
  }
  return null;
}

export default async function handler(req, res) {
  const routeParam = req.query?.route;
  const routeName = extractRouteName(routeParam);
  
  if (!routeParam || !routeParam.length) {
    // If no route parameter, try to infer from URL path
    const pathMatch = req.url.match(/^\/api\/oauth\/([^/?]+)/);
    if (pathMatch && pathMatch[1]) {
      const routeName = pathMatch[1].split('?')[0].split('/')[0];
      if (ROUTES[routeName]) {
        return ROUTES[routeName](req, res);
      }
    }
  }
  
  const routeName = extractRouteName(routeParam);
  const fn = routeName ? ROUTES[routeName] : undefined;
  if (!fn) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(404).json({ error: 'invalid_request', error_description: 'Unknown OAuth endpoint.' });
  }
  return fn(req, res);
}
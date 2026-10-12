import { createHmac, createDecipheriv } from 'node:crypto';

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is missing');
  return createHmac('sha256', secret).update('gfm-cookie-key').digest();
}
function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}
export function getTokens(req) {
  const cookie = parseCookies(req.headers.cookie).gfm_session;
  if (!cookie) return null;
  try {
    const raw = Buffer.from(cookie, 'base64url');
    const iv = raw.subarray(0, 12), tag = raw.subarray(12, 28), body = raw.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', getKey(), iv);
    decipher.setAuthTag(tag);
    const decoded = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
    return JSON.parse(decoded).tokens;
  } catch { return null; }
}
export function requireMethod(req, res, method = 'POST') {
  if (req.method !== method) { res.status(405).json({ error: `Use ${method}.` }); return false; }
  return true;
}
export function requireSession(req, res) {
  const tokens = getTokens(req);
  if (!tokens) { res.status(401).json({ error: 'Google is not connected. Open /api/auth/google to connect first.' }); return null; }
  return tokens;
}
export function noCache(res) { res.setHeader('Cache-Control', 'no-store'); }

// Server-only AES-256-GCM helpers for Google OAuth tokens.
//
// Uses the 32-byte base64 key in TOKEN_ENCRYPTION_KEY. Plaintext tokens must
// never be stored, logged, or returned to the browser.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

function getTokenKey() {
  const raw = process.env.TOKEN_ENCRYPTION_KEY;
  if (!raw) throw new Error('TOKEN_ENCRYPTION_KEY is missing');
  let key = null;
  // Accept standard base64 and base64url encodings.
  for (const encoding of ['base64', 'base64url']) {
    try {
      const candidate = Buffer.from(raw.trim(), encoding);
      if (candidate.length === 32) {
        key = candidate;
        break;
      }
    } catch {
      // Try the next encoding.
    }
  }
  if (!key) throw new Error('TOKEN_ENCRYPTION_KEY must decode to 32 bytes (base64).');
  return key;
}

// Returns "iv.tag.data", each part base64url-encoded. Safe for a text column.
export function encryptToken(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext) {
    throw new Error('encryptToken requires a non-empty string.');
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getTokenKey(), iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${body.toString('base64url')}`;
}

export function decryptToken(payload) {
  if (typeof payload !== 'string' || !payload) {
    throw new Error('decryptToken requires a non-empty string.');
  }
  const parts = payload.split('.');
  if (parts.length !== 3) throw new Error('Encrypted token has an invalid format.');
  const iv = Buffer.from(parts[0], 'base64url');
  const tag = Buffer.from(parts[1], 'base64url');
  const body = Buffer.from(parts[2], 'base64url');
  if (iv.length !== 12 || tag.length !== 16 || body.length === 0) {
    throw new Error('Encrypted token has an invalid format.');
  }
  const decipher = createDecipheriv('aes-256-gcm', getTokenKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}

// Regression guard: no stale bare `validateRequest(` call sites may remain
// in api/lib/tests. (A past deploy called an undefined `validateRequest`
// in the OAuth authorize GET handler after it was renamed to
// `validateAuthorizeRequest`, which threw ReferenceError in production.)
// Allowed lookalikes: `validateAuthorizeRequest` (ours) and the SDK's
// `validateRequestHeaders` (dependency code, not ours).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function jsFiles(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (entry === 'node_modules' || entry === '.git') continue;
    if (statSync(full).isDirectory()) jsFiles(full, out);
    // Skip this guard file itself: it necessarily names the pattern.
    else if (full.endsWith('.js') && !full.endsWith('no-stale-validate-request.test.js')) out.push(full);
  }
  return out;
}

describe('no stale validateRequest references', () => {
  it('has zero bare validateRequest callees outside node_modules', () => {
    const offenders = [];
    for (const file of jsFiles(ROOT)) {
      const src = readFileSync(file, 'utf8');
      const matches = [...src.matchAll(/(?<![A-Za-z])validateRequest\s*\(/g)];
      // Filter out the two legitimate lookalikes.
      const real = matches.filter((m) => {
        const line = src.slice(0, m.index).split('\n').pop() + src.slice(m.index).split('\n')[0];
        return !line.includes('validateAuthorizeRequest') && !line.includes('validateRequestHeaders');
      });
      if (real.length) offenders.push(`${file}: ${real.length} occurrence(s)`);
    }
    assert.deepEqual(offenders, []);
  });
});

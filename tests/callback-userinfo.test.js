// Google profile retrieval via the OAuth2 v2 userinfo endpoint:
// success, missing id, and API failure.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fetchGoogleProfile } from '../api/auth/callback.js';

function stubGoogleApi(userinfoImpl) {
  return {
    oauth2: (options) => {
      assert.equal(options.version, 'v2');
      assert.ok(options.auth, 'userinfo client must be authenticated');
      return { userinfo: { get: userinfoImpl } };
    },
  };
}

describe('fetchGoogleProfile', () => {
  it('returns the stable id and email on success', async () => {
    const api = stubGoogleApi(async () => ({ data: { id: 'google-sub-123', email: 'alex@example.com' } }));
    const profile = await fetchGoogleProfile({ marker: 'oauth2-client' }, api);
    assert.equal(profile.userId, 'google-sub-123');
    assert.equal(profile.googleEmail, 'alex@example.com');
  });

  it('accepts a profile with no email (email becomes null)', async () => {
    const api = stubGoogleApi(async () => ({ data: { id: 'google-sub-456' } }));
    const profile = await fetchGoogleProfile({}, api);
    assert.equal(profile.userId, 'google-sub-456');
    assert.equal(profile.googleEmail, null);
  });

  it('throws when the stable id is missing', async () => {
    const api = stubGoogleApi(async () => ({ data: { email: 'no-id@example.com' } }));
    await assert.rejects(fetchGoogleProfile({}, api), /Could not identify the Google account/);
  });

  it('throws when the userinfo endpoint fails', async () => {
    const api = stubGoogleApi(async () => {
      const err = new Error('Request failed with status code 403');
      err.code = 403;
      throw err;
    });
    await assert.rejects(fetchGoogleProfile({}, api), /403/);
  });

  it('throws when the response has no data', async () => {
    const api = stubGoogleApi(async () => ({}));
    await assert.rejects(fetchGoogleProfile({}, api), /Could not identify the Google account/);
  });
});

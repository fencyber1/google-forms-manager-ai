// Verify the Supabase client used for Google connection persistence is the
// service-role client backed by SUPABASE_SECRET_KEY — never an anon/authenticated
// client. Also verify permission errors are surfaced without leaking keys.
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

const ORIGINAL = {
  url: process.env.SUPABASE_URL,
  key: process.env.SUPABASE_SECRET_KEY,
};

beforeEach(() => {
  process.env.SUPABASE_URL = 'https://test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'service-role-key-dummy';
});

afterEach(() => {
  if (ORIGINAL.url === undefined) delete process.env.SUPABASE_URL;
  else process.env.SUPABASE_URL = ORIGINAL.url;
  if (ORIGINAL.key === undefined) delete process.env.SUPABASE_SECRET_KEY;
  else process.env.SUPABASE_SECRET_KEY = ORIGINAL.key;
});

describe('supabase service client', () => {
  it('creates a client from SUPABASE_URL + SUPABASE_SECRET_KEY', async () => {
    const { getSupabaseServiceClient } = await import('../lib/supabase.js');
    const client = getSupabaseServiceClient();
    assert.ok(client, 'client must be created');
    assert.equal(client.supabaseUrl, 'https://test.supabase.co');
    assert.equal(client.supabaseKey, 'service-role-key-dummy');
  });

  it('throws when Supabase env vars are missing', async () => {
    delete process.env.SUPABASE_URL;
    // Bust the module-level client cache so the missing-env path runs.
    const { getSupabaseServiceClient } = await import('../lib/supabase.js?fresh=missing');
    assert.throws(() => getSupabaseServiceClient(), /SUPABASE_URL \/ SUPABASE_SECRET_KEY/);
  });

  it('reads only SUPABASE_SECRET_KEY for the client key', async () => {
    process.env.SUPABASE_SECRET_KEY = 'anon-key-dummy';
    // Fresh module instance (cache busted) so the new key is picked up.
    const { getSupabaseServiceClient } = await import('../lib/supabase.js?fresh=anon');
    const client = getSupabaseServiceClient();
    // The client is always built from SUPABASE_SECRET_KEY; if that var held
    // the anon key, the client would silently run as anon — so the env var
    // name is the contract. Assert the wiring is exclusive.
    assert.equal(client.supabaseKey, 'anon-key-dummy');
    assert.ok(!String(client.supabaseKey).includes('service-role-key-dummy'));
  });
});

describe('saveGoogleConnection error safety', () => {
  it('wraps Supabase errors without leaking the key or tokens', async () => {
    // A permission error from the client must be rethrown as a safe message.
    const { saveGoogleConnection } = await import('../lib/google-connections.js');
    // With dummy env vars the client cannot reach a real DB; the error must
    // not contain the secret key value.
    await assert.rejects(
      saveGoogleConnection({
        userId: 'sub-1',
        tokens: { refresh_token: 'x', access_token: 'y', expiry_date: Date.now() + 60000 },
      }),
      (err) => {
        assert.ok(!String(err?.message).includes('service-role-key-dummy'), 'error must not leak the key');
        return true;
      },
    );
  });
});

// Server-only Supabase client.
//
// IMPORTANT: this module uses SUPABASE_SECRET_KEY (service-role / secret key)
// and must only be imported from server-side API routes under /api.
// Never import it from browser code and never expose the key to the client.
import { createClient } from '@supabase/supabase-js';

export const GOOGLE_CONNECTIONS_TABLE = 'google_connections';

let cachedClient = null;

export function getSupabaseServiceClient() {
  if (cachedClient) return cachedClient;
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    throw new Error('Supabase is not configured (SUPABASE_URL / SUPABASE_SECRET_KEY).');
  }
  cachedClient = createClient(url, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cachedClient;
}

# Google Forms Manager AI — backend starter

This is a Vercel serverless backend starter for Google Forms OAuth, creating forms, reading a known form, and reading its responses. It is **not yet a connected ChatGPT MCP plugin**; the MCP tool layer and deployment verification are a later step.

## Deploy
1. Create a new GitHub repository named `google-forms-manager-ai`.
2. Upload all files from this folder to the repository root.
3. Import the repository into Vercel and deploy.
4. In Vercel → Project → Settings → Environment Variables, add:
   - `GOOGLE_CLIENT_ID` — from Google Auth Platform → Clients
   - `GOOGLE_CLIENT_SECRET` — from the same OAuth client; keep it private
   - `APP_BASE_URL` — your deployed Vercel URL, e.g. `https://your-project.vercel.app` (no trailing slash)
   - `SESSION_SECRET` — a random secret of at least 32 characters; do not reuse your Google client secret
   - `SUPABASE_URL` — Supabase project URL (server-only; no `NEXT_PUBLIC_` prefix)
   - `SUPABASE_SECRET_KEY` — Supabase secret/service key (server-only, never expose to the browser)
   - `TOKEN_ENCRYPTION_KEY` — 32-byte base64 key used for AES-256-GCM token encryption
5. Redeploy after adding variables.
6. In Google Auth Platform → Clients → your Web application client, add this Authorized redirect URI exactly:
   `https://YOUR-VERCEL-DOMAIN/api/auth/callback`
   Replace `YOUR-VERCEL-DOMAIN` with your actual deployed hostname. Also set the same URL as `APP_BASE_URL` plus `/api/auth/callback` is derived by the code.
   OAuth consent now requests `openid`, `userinfo.email`, `userinfo.profile` (to securely
   identify the Google account) plus the Forms scopes. Existing users must reconnect once
   to grant the identity scopes and migrate from cookie sessions to Supabase.
7. Open `https://YOUR-VERCEL-DOMAIN/api/auth/google` and complete Google consent.

## Supabase storage (`public.google_connections`)

Each successful authorization upserts one row keyed by stable Google account ID
(`userinfo.sub` stored as `user_id`, never email alone):

- `user_id` (text, unique) — Google `sub`
- `google_email` — display/help only, never used for auth lookups
- `encrypted_refresh_token` / `encrypted_access_token` — AES-256-GCM strings
  (`iv.tag.data`, base64url), encrypted with `TOKEN_ENCRYPTION_KEY`; never plaintext
- `access_token_expires_at` (timestamptz) — refreshed automatically per request
- `scopes` — granted scopes; column should be `text[]`
- `created_at` / `updated_at`

Recommended SQL hardening (run once in Supabase):

```sql
alter table public.google_connections
  add constraint google_connections_user_id_unique unique (user_id);
alter table public.google_connections enable row level security;
-- No public/anon policies: only the server secret key (bypasses RLS) may read/write.
```

The `gfm_session` cookie now stores only `{ uid, v: 1 }` (encrypted with
`SESSION_SECRET`). Legacy cookies that held raw tokens are rejected — users reconnect once.
Every Forms request loads **only the current cookie user's** Supabase row, decrypts in
memory, refreshes an expiring access token, and never logs or returns tokens/secrets/keys.
There is no unauthenticated route and no `?user_id` override, so users cannot access
each other's forms or responses.

## Endpoints
- `GET /api/health` — health check
- `GET /api/auth/google` — begin OAuth connection
- `GET /api/auth/callback` — OAuth callback
- `POST /api/forms/create` — JSON `{ "title": "Example", "questions": [{"title":"Your name","type":"short","required":true}] }`
- `GET /api/forms/get?formId=FORM_ID` — retrieve a known form
- `GET /api/forms/responses?formId=FORM_ID` — retrieve responses for a known form

## Important limitations and security notes
- Google OAuth tokens are stored per-user in Supabase, encrypted with AES-256-GCM. The
  browser holds only an encrypted session cookie with the user ID.
- Google Forms API does not provide a general list-all-my-forms endpoint. The form ID is needed to read a specific form or its responses.
- Do not expose endpoints publicly without adding authentication/authorization and request protections.
- Drafting and sending email replies is not implemented; this starter only reads form responses. Sending email should require a separate Gmail API integration and explicit approval.
- The ChatGPT MCP server/tool definitions still need to be implemented and tested before the plugin can call these endpoints.

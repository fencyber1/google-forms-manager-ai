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
5. Redeploy after adding variables.
6. In Google Auth Platform → Clients → your Web application client, add this Authorized redirect URI exactly:
   `https://YOUR-VERCEL-DOMAIN/api/auth/callback`
   Replace `YOUR-VERCEL-DOMAIN` with your actual deployed hostname. Also set the same URL as `APP_BASE_URL` plus `/api/auth/callback` is derived by the code.
7. Open `https://YOUR-VERCEL-DOMAIN/api/auth/google` and complete Google consent.

## Endpoints
- `GET /api/health` — health check
- `GET /api/auth/google` — begin OAuth connection
- `GET /api/auth/callback` — OAuth callback
- `POST /api/forms/create` — JSON `{ "title": "Example", "questions": [{"title":"Your name","type":"short","required":true}] }`
- `GET /api/forms/get?formId=FORM_ID` — retrieve a known form
- `GET /api/forms/responses?formId=FORM_ID` — retrieve responses for a known form

## Important limitations and security notes
- This starter stores the OAuth session in an encrypted, HTTP-only cookie. It is suitable for a small prototype, not a multi-user production system; production should use a proper server-side encrypted session store and user identity/access controls.
- Google Forms API does not provide a general list-all-my-forms endpoint. The form ID is needed to read a specific form or its responses.
- Do not expose endpoints publicly without adding authentication/authorization and request protections.
- Drafting and sending email replies is not implemented; this starter only reads form responses. Sending email should require a separate Gmail API integration and explicit approval.
- The ChatGPT MCP server/tool definitions still need to be implemented and tested before the plugin can call these endpoints.

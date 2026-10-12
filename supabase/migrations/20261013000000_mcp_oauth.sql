-- Phase 2 MCP OAuth: authorization codes and opaque MCP tokens.
--
-- Design notes:
-- * Access/refresh values are random 256-bit strings. Only SHA-256 hashes
--   are stored; raw values are shown once (token response) and never logged.
-- * Every field read by token validation lives in mcp_tokens: issuer,
--   audience, expiry, not-before, family_id, rotation links, revocation
--   state + timestamps. Google identity is the stable google_sub.
-- * Code redemption is a single conditional UPDATE (atomic). Refresh
--   rotation runs inside rotate_mcp_refresh() in one transaction with
--   SELECT ... FOR UPDATE; refresh-token reuse revokes the whole family.
-- * Enable RLS with no public policies: only the server secret key may
--   read/write (same pattern as google_connections).

create table if not exists public.mcp_auth_codes (
  code_hash text primary key,
  client_id text not null,
  redirect_uri text not null,
  code_challenge text not null,
  code_challenge_method text not null default 'S256',
  resource text not null,
  google_sub text not null,
  scopes text[] not null default '{}',
  expires_at timestamptz not null,
  used boolean not null default false,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.mcp_tokens (
  token_hash text primary key,
  kind text not null check (kind in ('access', 'refresh')),
  family_id text not null,
  issuer text not null,
  google_sub text not null,
  client_id text not null,
  audience text not null,
  scopes text[] not null default '{}',
  expires_at timestamptz not null,
  not_before timestamptz not null default now(),
  revoked boolean not null default false,
  revoked_at timestamptz,
  rotated_from text,
  created_at timestamptz not null default now()
);

create index if not exists mcp_auth_codes_sub_idx on public.mcp_auth_codes (google_sub);
create index if not exists mcp_auth_codes_expires_idx on public.mcp_auth_codes (expires_at);
create index if not exists mcp_tokens_sub_idx on public.mcp_tokens (google_sub);
create index if not exists mcp_tokens_family_idx on public.mcp_tokens (family_id);
create index if not exists mcp_tokens_expires_idx on public.mcp_tokens (expires_at);

alter table public.mcp_auth_codes enable row level security;
alter table public.mcp_tokens enable row level security;
-- Intentionally no policies: the Supabase secret key bypasses RLS
-- server-side, while anon/authenticated roles get nothing.

-- Atomic refresh rotation with reuse detection.
-- Returns jsonb: { ok: true, reused: false } on success,
-- { ok: false, reused: true } when a rotated/revoked token is replayed
-- (the whole family is revoked), { ok: false, expired: true } on expiry,
-- { ok: false, missing: true } when unknown.
create or replace function public.rotate_mcp_refresh(
  p_old_hash text,
  p_new_hash text,
  p_new_expires timestamptz,
  p_scopes text[]
) returns jsonb
language plpgsql
security definer
as $$
declare
  v_old public.mcp_tokens%rowtype;
begin
  select * into v_old from public.mcp_tokens
    where token_hash = p_old_hash and kind = 'refresh'
    for update;
  if not found then
    return jsonb_build_object('ok', false, 'missing', true);
  end if;
  -- Reuse: already revoked, or already rotated (a successor row exists).
  -- FOR UPDATE serializes concurrent rotations: the loser re-reads the
  -- committed revocation and lands here too.
  if v_old.revoked or exists (
    select 1 from public.mcp_tokens
    where rotated_from = v_old.token_hash
  ) then
    update public.mcp_tokens
      set revoked = true, revoked_at = now()
      where family_id = v_old.family_id and revoked = false;
    return jsonb_build_object('ok', false, 'reused', true);
  end if;
  if v_old.expires_at <= now() then
    return jsonb_build_object('ok', false, 'expired', true);
  end if;
  update public.mcp_tokens
    set revoked = true, revoked_at = now()
    where token_hash = v_old.token_hash;
  insert into public.mcp_tokens (
    token_hash, kind, family_id, issuer, google_sub, client_id,
    audience, scopes, expires_at, rotated_from
  ) values (
    p_new_hash, 'refresh', v_old.family_id, v_old.issuer, v_old.google_sub,
    v_old.client_id, v_old.audience, coalesce(p_scopes, v_old.scopes),
    p_new_expires, v_old.token_hash
  );
  return jsonb_build_object('ok', true, 'reused', false);
end;
$$;

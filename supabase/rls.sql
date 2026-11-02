-- Indexed FP&A: row-level security for the portal's Supabase tables
--
-- Why: the portal's anon key is public (it is in index.html, served from a public GitHub repo). Until this runs,
-- anyone who has that key can read the whole forecast_data row (cash, P&L, receivables) and overwrite it, and the
-- admin / accountant / viewer roles only exist in the browser. After it runs:
--   forecast_data  read: signed-in users who have a row in user_roles.  change: admin and accountant only.
--                  The anon key can do nothing.
--   comments       read and add: signed-in users with a role (a new comment must carry their own email).
--                  Resolve or reopen: the comment's author, or an admin or accountant. Only the resolved,
--                  resolved_by and resolved_at columns can be changed, and nobody can delete a comment.
--   user_roles     each user can read only their own role. Roles are changed from the dashboard or with the
--                  service key.
--
-- How to apply (an admin does this once):
--   1. Deploy the portal version that sends each user's own token (branch fix/audit-security) and reload any tabs
--      that are open. Older tabs still sync with the anon key, which this script revokes.
--   2. The MCP server (indexed-fpa-mcp) must use the service-role key from then on. Set SUPABASE_SERVICE_KEY on its
--      host (Railway). The key is under Supabase dashboard > Project Settings > API > service_role. Then restart the
--      server. Without the key it falls back to the anon key it reads from index.html, and that key will no longer
--      read or write forecast_data. Keep the service key secret: it bypasses every policy below.
--   3. In the Supabase dashboard, open the SQL Editor, paste this file and click Run. It is idempotent, so running it
--      again is safe. It replaces any existing policies on forecast_data and comments.
--   4. Sign in once with each role. Check that the portal loads, that an admin or accountant can save, that a viewer
--      can't save, and that comments work.
-- Rollback (back to how things were before, including the anon key that the MCP falls back to and that older tabs use):
--   alter table public.forecast_data disable row level security;
--   alter table public.comments disable row level security;
--   grant all on public.forecast_data, public.comments to anon, authenticated;
-- If only the MCP stopped working, you don't need to roll back: set SUPABASE_SERVICE_KEY on its host and restart it.
-- The new portal keeps working either way (it sends the signed-in user's token).

begin;

-- The caller's role. SECURITY DEFINER lets the policies read user_roles without depending on user_roles' own
-- policies. It only ever returns the caller's own role, or null.
create or replace function public.fpa_role()
returns text language sql stable security definer set search_path = public as $$
  select role::text from public.user_roles where user_id::text = auth.uid()::text limit 1
$$;
revoke all on function public.fpa_role() from public, anon;
grant execute on function public.fpa_role() to authenticated;

-- Start from a clean slate on the two data tables. Any older permissive policy, such as "anon can do anything",
-- would otherwise still apply alongside the new ones.
do $$ declare p record; begin
  for p in select policyname, tablename from pg_policies
           where schemaname = 'public' and tablename in ('forecast_data', 'comments') loop
    execute format('drop policy %I on public.%I', p.policyname, p.tablename);
  end loop;
end $$;

-- ── forecast_data (the single shared row, id = 1) ──
alter table public.forecast_data enable row level security;
revoke all on public.forecast_data from anon;
revoke insert, delete, truncate on public.forecast_data from authenticated; -- the portal only ever updates row 1
grant select, update on public.forecast_data to authenticated;
create policy "fpa: role holders read" on public.forecast_data
  for select to authenticated
  using ((select public.fpa_role()) is not null);
create policy "fpa: admin and accountant write" on public.forecast_data
  for update to authenticated
  using ((select public.fpa_role()) in ('admin', 'accountant'))
  with check ((select public.fpa_role()) in ('admin', 'accountant'));

-- ── comments ──
alter table public.comments enable row level security;
revoke all on public.comments from anon;
revoke update, delete, truncate on public.comments from authenticated;
grant select, insert on public.comments to authenticated;
grant update (resolved, resolved_by, resolved_at) on public.comments to authenticated; -- resolve/reopen only
create policy "fpa: role holders read comments" on public.comments
  for select to authenticated
  using ((select public.fpa_role()) is not null);
create policy "fpa: role holders add their own comments" on public.comments
  for insert to authenticated
  with check ((select public.fpa_role()) is not null
              and lower(author_email) = lower(coalesce(auth.jwt() ->> 'email', '')));
-- Resolve/reopen: your own comments, or any comment if you are an admin or accountant. Accountants are included
-- because today they resolve the threads they answer. To limit this to admins, remove 'accountant' below.
create policy "fpa: author, admin or accountant resolve" on public.comments
  for update to authenticated
  using ((select public.fpa_role()) is not null
         and (lower(author_email) = lower(coalesce(auth.jwt() ->> 'email', ''))
              or (select public.fpa_role()) in ('admin', 'accountant')))
  with check ((select public.fpa_role()) is not null);

-- ── user_roles ──
-- Without this, any signed-in user, and the anon key if it still has its default grants, could add a row that
-- makes themselves admin.
alter table public.user_roles enable row level security;
revoke all on public.user_roles from anon;
revoke insert, update, delete, truncate on public.user_roles from authenticated;
grant select on public.user_roles to authenticated;
drop policy if exists "fpa: read own role" on public.user_roles;
create policy "fpa: read own role" on public.user_roles
  for select to authenticated
  using (user_id::text = auth.uid()::text);

commit;

-- Check what is in force:
--   select tablename, policyname, cmd, roles from pg_policies
--   where schemaname = 'public' and tablename in ('forecast_data', 'comments', 'user_roles') order by 1, 2;

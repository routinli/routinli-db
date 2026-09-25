-- MyDownloads SELECT is member-scoped (user_id = auth.uid() — a member only
-- sees their own downloads), so a partner's own session querying it for
-- their program's routine_package_id silently gets 0 rows back via RLS, not
-- an error. That made the "has this program been downloaded" check used to
-- block risky edits (delete routine/step, shorten end_day) always read 0.
-- This RPC runs as the table owner (bypassing RLS) but re-checks ownership
-- itself before counting, so a partner can only ever learn the download
-- count for a program they actually own (or staff, for anything).

create or replace function public.get_program_download_count(p_program_id uuid)
returns integer
language sql stable security definer set search_path = public
as $$
  select case
    when public.owns_routine_package(p_program_id) or public.is_staff()
      then (
        select count(*)::integer
        from public."MyDownloads"
        where routine_package_id = p_program_id
      )
    else 0
  end;
$$;

revoke all on function public.get_program_download_count(uuid) from public;
grant execute on function public.get_program_download_count(uuid) to authenticated;

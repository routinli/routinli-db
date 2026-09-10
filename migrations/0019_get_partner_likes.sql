-- Raw like rows for the caller's own programs, for the dashboard Analytics
-- page (engagement trend over time). Same shape/reasoning as
-- get_partner_ratings() (migration 0018): SECURITY DEFINER because
-- RoutinePackageLikes RLS is scoped to the liker, not the program creator;
-- deliberately excludes user_id (no member identity to partners).

create or replace function public.get_partner_likes()
returns table (
  id                  uuid,
  routine_package_id  uuid,
  created_at          timestamptz
)
language sql stable security definer set search_path = public
as $$
  select
    l.id,
    l.routine_package_id,
    l.created_at
  from public."RoutinePackageLikes" l
  join public."RoutinePackages" p on p.id = l.routine_package_id
  where p.creator_id = auth.uid()
  order by l.created_at desc nulls last;
$$;

revoke all on function public.get_partner_likes() from public;
grant execute on function public.get_partner_likes() to authenticated;

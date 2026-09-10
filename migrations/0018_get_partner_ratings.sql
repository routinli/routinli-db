-- Raw rating rows for the caller's own programs, for the dashboard Reviews
-- page (distribution, recent feed, per-program breakdown). RoutinePackageRatings
-- RLS is scoped to the rating's own author (mobile), not the program's
-- creator, so this needs SECURITY DEFINER — same reason get_partner_programs()
-- needs it to compute rating_avg/rating_count.
--
-- Deliberately excludes the rater's user_id: partners see aggregate/anonymous
-- rating data only, never who left it (docs/DECISIONS.md — member privacy).

create or replace function public.get_partner_ratings()
returns table (
  id                  uuid,
  routine_package_id  uuid,
  program_title       text,
  program_emoji       varchar,
  rating              smallint,
  created_at          timestamptz
)
language sql stable security definer set search_path = public
as $$
  select
    r.id,
    r.routine_package_id,
    p.title,
    p.emoji,
    r.rating,
    r.created_at
  from public."RoutinePackageRatings" r
  join public."RoutinePackages" p on p.id = r.routine_package_id
  where p.creator_id = auth.uid()
  order by r.created_at desc nulls last;
$$;

revoke all on function public.get_partner_ratings() from public;
grant execute on function public.get_partner_ratings() to authenticated;

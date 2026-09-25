-- "My programs" on routinli.com/account: every program in the signed-in
-- member's Library — downloaded in the app, claimed free on the web, or bought.
--
-- Members can read their own MyDownloads rows but not RoutinePackages (that
-- table is creator-only), so the account page needs this to show titles and
-- covers. It only ever returns the CALLER's own programs (auth.uid()); there is
-- no user id parameter to misuse.
--
-- Includes programs the member still owns even if they've since been taken
-- down (is_listed = false) — they keep them in the app. Personal packages are
-- ignored entirely.
--
-- ADDITIVE ONLY: one new function; nothing existing is changed.

create or replace function public.get_my_programs()
returns table (
  id            uuid,
  title         text,
  category_name text,
  square_url    text,
  emoji         text,
  theme_color   text,
  partner_name  text,
  added_at      timestamptz,
  is_listed     boolean,   -- still publicly listed (so /programs/<id> works)
  is_started    boolean    -- any of its routines started in the app
)
language sql stable security definer set search_path = public
as $$
  with mine as (
    -- one row per program, even if the app ever wrote duplicates
    select distinct on (d.routine_package_id) d.routine_package_id, d.downloads_date
    from public."MyDownloads" d
    where d.user_id = auth.uid()
    order by d.routine_package_id, d.downloads_date desc
  ),
  listed as (
    select c.id from public._public_program_cards() c
  )
  select
    p.id,
    p.title,
    c.text::text,
    coalesce(p.theme_pic_url, p.theme_cover_pic_url, c.default_picture_url, c.default_cover_url)::text,
    p.emoji,
    coalesce(p.theme_color, c.theme_color)::text,
    coalesce(nullif(btrim(up.brand_name), ''), up.display_name)::text,
    m.downloads_date,
    p.id in (select l.id from listed l),
    exists (
      select 1
      from public."MyRoutines" mr
      join public."Routines" r on r.id = mr.downloaded_routine_id
      where mr.user_id = auth.uid()
        and r.routine_package_id = p.id
        and mr.is_started
    )
  from mine m
  join public."RoutinePackages" p on p.id = m.routine_package_id
  left join public."UserProfiles" up on up.id = p.creator_id
  left join public."EnumCategories" c on c.id = p.category_id
  where p.is_personal = false
  order by m.downloads_date desc;
$$;

revoke all on function public.get_my_programs() from public, anon;
grant execute on function public.get_my_programs() to authenticated;

notify pgrst, 'reload schema';

-- Public program catalog for routinli.com (the member-facing web app).
--
-- RoutinePackages is readable only by its creator and UserProfiles only by its
-- owner (or staff), so anonymous visitors to routinli.com can't read either
-- table directly — which is correct and stays that way. These functions are the
-- one deliberately public window onto them, and return ONLY what a shop window
-- should show:
--
--   * programs that are live (status_id = 7 "active") and not personal
--   * from partners who aren't suspended/rejected (verification_status <> 3)
--   * aggregate ratings only (average + count) — never who rated what
--   * routine TITLES only — never step content (that is the paid part)
--   * partner display name, photo, bio, socials — never verification_status,
--     requested_deletion, names beyond the chosen display, or email
--
-- The live/non-personal/not-suspended rule is defined ONCE, in
-- _public_program_cards(); every public function reads through it, so no
-- public function can forget the filter.
--
-- ADDITIVE ONLY: no table, column, policy or existing function is changed.
-- Nothing here is used by the mobile app, and get_explore_paginated_programs
-- is untouched.


-- ─── internal: every publicly listable program, as a card ────────────────────
-- Not callable by anon/authenticated (execute revoked below). The public
-- functions run as the owner, so they can call it; clients can't.

create or replace function public._public_program_cards()
returns table (
  id              uuid,
  title           text,
  goal            text,
  description     text,
  category_id     smallint,
  category_name   text,
  square_url      text,
  cover_url       text,
  emoji           text,
  theme_color     text,
  price           double precision,
  end_day         smallint,
  rating_avg      numeric,
  rating_count    integer,
  routine_count   integer,
  partner_id      uuid,
  partner_name    text,
  partner_photo_url text,
  created_at      timestamptz,
  modified_at     timestamptz
)
language sql stable security definer set search_path = public
as $$
  select
    p.id,
    p.title,
    p.goal,
    p.description,
    p.category_id,
    c.text::text,
    -- square tile for cards, wide cover for the detail hero; each falls back to
    -- the other, then to the category's default art
    coalesce(p.theme_pic_url, p.theme_cover_pic_url, c.default_picture_url, c.default_cover_url)::text,
    coalesce(p.theme_cover_pic_url, p.theme_pic_url, c.default_cover_url, c.default_picture_url)::text,
    p.emoji,
    coalesce(p.theme_color, c.theme_color)::text,
    p.price,
    p.end_day,
    r.rating_avg,
    coalesce(r.rating_count, 0)::integer,
    (select count(*)::integer from public."Routines" rt where rt.routine_package_id = p.id),
    p.creator_id,
    coalesce(nullif(btrim(up.brand_name), ''), up.display_name)::text,
    up.photo_url::text,
    p.created_at,
    coalesce(p.modified_at, p.created_at)
  from public."RoutinePackages" p
  join public."UserProfiles" up on up.id = p.creator_id
  left join public."EnumCategories" c on c.id = p.category_id
  left join lateral (
    select round(avg(rt.rating)::numeric, 1) as rating_avg,
           count(*)                          as rating_count
    from public."RoutinePackageRatings" rt
    where rt.routine_package_id = p.id
  ) r on true
  where p.status_id = 7
    and p.is_personal = false
    and up.verification_status is distinct from 3;
$$;

revoke all on function public._public_program_cards() from public, anon, authenticated;


-- ─── catalog list: search + category filter + paging ─────────────────────────

create or replace function public.get_public_catalog(
  p_search      text    default null,
  p_category_id integer default null,
  p_limit       integer default 24,
  p_offset      integer default 0
)
returns table (
  id                uuid,
  title             text,
  goal              text,
  category_id       smallint,
  category_name     text,
  square_url        text,
  emoji             text,
  theme_color       text,
  price             double precision,
  end_day           smallint,
  rating_avg        numeric,
  rating_count      integer,
  routine_count     integer,
  partner_id        uuid,
  partner_name      text,
  partner_photo_url text,
  modified_at       timestamptz,
  total_count       bigint
)
language sql stable security definer set search_path = public
as $$
  with term as (
    -- escape LIKE wildcards so a search for "50%" means the text "50%"
    select '%' || replace(replace(replace(nullif(btrim(p_search), ''), '\', '\\'), '%', '\%'), '_', '\_') || '%' as pattern
  )
  select
    c.id, c.title, c.goal, c.category_id, c.category_name, c.square_url,
    c.emoji, c.theme_color, c.price, c.end_day, c.rating_avg, c.rating_count,
    c.routine_count, c.partner_id, c.partner_name, c.partner_photo_url,
    c.modified_at,
    count(*) over ()
  from public._public_program_cards() c
  cross join term
  where (p_category_id is null or c.category_id = p_category_id)
    and (term.pattern is null
         or c.title       ilike term.pattern
         or c.goal        ilike term.pattern
         or c.description ilike term.pattern)
  order by c.created_at desc, c.id
  limit  least(greatest(coalesce(p_limit, 24), 1), 48)
  offset greatest(coalesce(p_offset, 0), 0);
$$;

revoke all on function public.get_public_catalog(text, integer, integer, integer) from public;
grant execute on function public.get_public_catalog(text, integer, integer, integer) to anon, authenticated;


-- ─── one program's public page ───────────────────────────────────────────────
-- Returns NULL for anything not publicly listable (draft, in review, rejected,
-- personal, taken down, suspended partner, or simply not found) — the page
-- can't tell those apart, which is the point.

create or replace function public.get_public_program(p_program_id uuid)
returns json
language sql stable security definer set search_path = public
as $$
  select json_build_object(
    'id',            c.id,
    'title',         c.title,
    'goal',          c.goal,
    'description',   c.description,
    'category_id',   c.category_id,
    'category_name', c.category_name,
    'square_url',    c.square_url,
    'cover_url',     c.cover_url,
    'emoji',         c.emoji,
    'theme_color',   c.theme_color,
    'price',         c.price,
    'end_day',       c.end_day,
    'rating_avg',    c.rating_avg,
    'rating_count',  c.rating_count,
    'modified_at',   c.modified_at,
    -- "what's inside": titles in order, and nothing else from the routine
    'routines', (
      select coalesce(json_agg(json_build_object('title', rt.title)
                               order by rt.order_number nulls last, rt.created_at), '[]'::json)
      from public."Routines" rt
      where rt.routine_package_id = c.id
    ),
    'partner', json_build_object(
      'id',        c.partner_id,
      'name',      c.partner_name,
      'photo_url', c.partner_photo_url
    )
  )
  from public._public_program_cards() c
  where c.id = p_program_id;
$$;

revoke all on function public.get_public_program(uuid) from public;
grant execute on function public.get_public_program(uuid) to anon, authenticated;


-- ─── a partner's public profile + their live programs ────────────────────────
-- Only returns a profile for someone with at least one publicly listable
-- program. A member (who never has one) can't be looked up through this — it
-- returns NULL exactly as for an unknown id.

create or replace function public.get_public_partner(p_partner_id uuid)
returns json
language sql stable security definer set search_path = public
as $$
  select json_build_object(
    'id',              up.id,
    'name',            coalesce(nullif(btrim(up.brand_name), ''), up.display_name),
    'photo_url',       up.photo_url,
    'cover_photo_url', up.cover_photo_url,
    'bio',             up.bio,
    'follower_count',  up.follower_count,
    'instagram_url',   up.instagram_url,
    'tiktok_url',      up.tiktok_url,
    'youtube_url',     up.youtube_url,
    'linkedin_url',    up.linkedin_url,
    'website_url',     up.website_url,
    'programs', (
      select coalesce(json_agg(json_build_object(
               'id',            c.id,
               'title',         c.title,
               'goal',          c.goal,
               'category_id',   c.category_id,
               'category_name', c.category_name,
               'square_url',    c.square_url,
               'emoji',         c.emoji,
               'theme_color',   c.theme_color,
               'price',         c.price,
               'end_day',       c.end_day,
               'rating_avg',    c.rating_avg,
               'rating_count',  c.rating_count,
               'routine_count', c.routine_count
             ) order by c.created_at desc), '[]'::json)
      from public._public_program_cards() c
      where c.partner_id = up.id
    )
  )
  from public."UserProfiles" up
  where up.id = p_partner_id
    and exists (select 1 from public._public_program_cards() c where c.partner_id = up.id);
$$;

revoke all on function public.get_public_partner(uuid) from public;
grant execute on function public.get_public_partner(uuid) to anon, authenticated;


-- Make the new functions callable through the API immediately.
notify pgrst, 'reload schema';

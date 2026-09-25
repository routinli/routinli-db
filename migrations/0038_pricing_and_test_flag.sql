-- 1. `is_test` — lets a program be built and fully test-purchased (real Stripe
--    test-mode checkout, real webhook, real MyDownloads row) without ever
--    showing up in the public catalog or, once get_explore_paginated_programs
--    is updated to match, the mobile Explore feed. Off by default; there is no
--    partner-facing UI to set it — flip it by hand in the SQL editor for
--    whichever program you're using to test the pricing/payout rebuild.
--
-- 2. A hard floor on price: free (0) or at least $2.00, nothing in between.
--    Matches the new fee model — a paid program under $2 would net the partner
--    almost nothing once the flat $1 floor applies. This is the SECOND guard
--    (the first is client-side in the builder); enforced here so it can't be
--    bypassed by any other write path, present or future.

alter table public."RoutinePackages" add column if not exists is_test boolean not null default false;

alter table public."RoutinePackages" drop constraint if exists "RoutinePackages_price_floor";
alter table public."RoutinePackages" add constraint "RoutinePackages_price_floor"
  check (price is null or price = 0 or price >= 2.00);

-- Exclude test programs from the public catalog. One place to change, per the
-- comment in 0033_public_catalog.sql: every public function reads through
-- _public_program_cards(), so this covers get_public_catalog, get_public_program
-- and get_public_partner in one edit. NOT applied to get_explore_paginated_programs
-- (mobile) — that function lives only in the live DB, in no migration file; it
-- needs the same "and coalesce(is_test, false) = false" added by hand.

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
    and p.is_test = false
    and up.verification_status is distinct from 3;
$$;

revoke all on function public._public_program_cards() from public, anon, authenticated;

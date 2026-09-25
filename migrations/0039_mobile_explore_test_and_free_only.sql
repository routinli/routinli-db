-- Mobile Explore functions, brought in line with two decisions:
--   1. Only free (price = 0) programs show in the app's Explore for this
--      version — in-app purchase is stashed for a later version, one platform
--      at a time (see NEXT.md §1, 2026-09-25).
--   2. Test programs (is_test = true, migration 0038) never show in any public
--      discovery surface.
--
-- These three functions existed only in the live database until now, created
-- directly rather than through a migration — this is the first time they're
-- tracked. Definitions below were pulled from the live DB (via
-- pg_get_functiondef) on 2026-09-25, then had the two filters added.
--
-- get_paginated_routine_packages and get_explore_programs_newest's 1-argument
-- overload are NOT touched here — pending confirmation of whether either is
-- still called by anything before deciding to fix or drop them.

-- ─── Explore hero card ─────────────────────────────────────────────────────

create or replace function public.get_explore_programs_hero()
 returns json
 language plpgsql
 stable security definer
as $function$
declare
  result json;
begin
  with latest_packages as (
    select *
    from "RoutinePackages"
    where status_id = 7
      and is_personal = false
      and is_test = false
      and price = 0
    order by created_at desc
    limit 10
  ),
  like_counts as (
    select
      lp.*,
      coalesce(l.like_count, 0) as like_count
    from latest_packages lp
    left join (
      select routine_package_id, count(*) as like_count
      from "RoutinePackageLikes"
      where routine_package_id in (select id from latest_packages)
      group by routine_package_id
    ) l on l.routine_package_id = lp.id
  ),
  winner as (
    select *
    from like_counts
    order by like_count desc, created_at desc
    limit 1
  )
  select json_build_object(
    'id', w.id,
    'title', w.title,
    'description', w.description,
    'goal', w.goal,
    'category_id', w.category_id,
    'theme_cover_pic_url', w.theme_cover_pic_url,
    'theme_pic_url', w.theme_pic_url,
    'price', w.price,
    'like_count', w.like_count,
    'emoji', w.emoji
  )
  into result
  from winner w;

  return result;
end;
$function$;

-- ─── Explore "newest" rail (2-argument overload: p_user_id, exclude id) ────
-- The overload that includes is_liked and SECURITY DEFINER — the one that
-- looks live. The 1-argument overload (no p_user_id, no is_liked) is left
-- untouched pending confirmation it's actually unused.

create or replace function public.get_explore_programs_newest(p_user_id uuid, p_routine_package_id_to_exclude uuid)
 returns json
 language plpgsql
 stable security definer
as $function$
declare
  result json;
begin
  select coalesce(json_agg(
    json_build_object(
      'id', rp.id,
      'title', rp.title,
      'description', rp.description,
      'goal', rp.goal,
      'category_id', rp.category_id,
      'theme_cover_pic_url', rp.theme_cover_pic_url,
      'theme_pic_url', rp.theme_pic_url,
      'price', rp.price,
      'emoji', rp.emoji,
      'is_liked', exists (
        select 1
        from public."RoutinePackageLikes" rpl
        where rpl.routine_package_id = rp.id
          and rpl.user_id = p_user_id
      )
    )
  ), '[]'::json)
  into result
  from (
    select *
    from "RoutinePackages"
    where status_id = 7
      and is_personal = false
      and is_test = false
      and price = 0
      and id != p_routine_package_id_to_exclude
    order by created_at desc
    limit 8
  ) rp;

  return result;
end;
$function$;

-- ─── Program detail page ───────────────────────────────────────────────────
-- Deliberately surgical: the free/non-test rule only applies to the "live and
-- public" access path. The other three paths (creator previewing their own
-- program, a member who already owns it — even if since taken down — and
-- staff) are untouched, since none of them should be gated by this rule.

create or replace function public.get_routine_package_details(p_user_id uuid, p_routine_package_id uuid)
 returns json
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null or p_user_id is distinct from v_uid then
    return json_build_object('routinePackage', null, 'routines', null);
  end if;

  if not exists (
    select 1
    from public."RoutinePackages" rp
    where rp.id = p_routine_package_id
      and (
        (rp.status_id = 7 and rp.is_personal = false and rp.is_test = false and rp.price = 0)
        or rp.creator_id = v_uid
        or exists (
          select 1 from public."MyDownloads" md
          where md.routine_package_id = rp.id and md.user_id = v_uid
        )
        or public.is_staff()
      )
  ) then
    return json_build_object('routinePackage', null, 'routines', null);
  end if;

  return (
    select json_build_object(
      'routinePackage', (
        select (to_jsonb(rp) - 'last_review_note' - 'last_reviewer_id')::json
        from (
          select
            rp.*,
            usp.display_name as creator_display_name,
            usp.photo_url as creator_photo_url,
            null::varchar as creator_first_name,
            null::varchar as creator_last_name,
            nullif(btrim(usp.brand_name), '') as creator_brand_name,
            (
              select coalesce(avg(rpr.rating), 0)
              from public."RoutinePackageRatings" rpr
              where rpr.routine_package_id = rp.id
            ) as avg_rating,
            (
              select count(*)
              from public."RoutinePackageRatings" rpr
              where rpr.routine_package_id = rp.id
            ) as ratings_count,
            (
              select rpr.rating
              from public."RoutinePackageRatings" rpr
              where rpr.user_id = p_user_id
                and rpr.routine_package_id = rp.id
            ) as user_rating,
            (
              select count(*)
              from public."RoutinePackageLikes" rpl
              where rpl.routine_package_id = rp.id
            ) as likes_count,
            (
              select count(*)
              from public."MyDownloads" md
              where md.routine_package_id = rp.id
            ) as downloads_count,
            (
              select md.downloads_date
              from public."MyDownloads" md
              where md.routine_package_id = rp.id and md.user_id = p_user_id
            ) as downloaded_date,
            exists (
              select 1
              from public."RoutinePackageLikes" rpl
              where rpl.routine_package_id = rp.id
                and rpl.user_id = p_user_id
            ) as is_liked
          from public."RoutinePackages" rp
          left join public."UserProfiles" usp on usp.id = rp.creator_id
          where rp.id = p_routine_package_id
        ) rp
      ),

      'routines', (
        select json_agg(r order by r.order_number)
        from (
          select
            r.*,
            (
              select count(*)
              from public."RoutineSteps" s
              where s.routine_id = r.id
            ) as steps_count,
            (
              select json_agg(s)
              from (
                  select rs.*
                  from public."RoutineSchedules" rs
                  where rs.routine_id = r.id
              ) as s
            ) as schedules
          from public."Routines" r
          where r.routine_package_id = p_routine_package_id
          order by r.created_at desc
        ) r
      )
    )
  );
end;
$function$;

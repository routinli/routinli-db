-- Close two privacy holes in functions the MOBILE APP calls. Found while
-- auditing what reads RoutineSteps (for the paid-content lock).
--
-- Both functions are SECURITY DEFINER (they bypass RLS) and both took the
-- user to answer for from the caller (p_user_id) without checking it — and
-- both were executable WITHOUT LOGGING IN (anon). So anyone holding a user's
-- id could read:
--   get_routines_for_daily(id)             → that person's started routines,
--                                            including their PERSONAL ones
--   get_routine_package_details(id, pkg)   → whether that person downloaded /
--                                            rated / liked a program; plus the
--                                            full row of ANY program (drafts,
--                                            review notes) and its creator's
--                                            first and last name
--
-- What changes (behaviour for the app, used normally, is identical):
--   1. p_user_id is only honoured when it IS the logged-in caller. The app
--      always passes its own id, so it sees exactly what it saw before.
--      Anything else gets the same empty answer as "not found".
--   2. Not callable without logging in (the app requires login — confirmed).
--   3. get_routine_package_details only returns a program the caller may see:
--      live & public, or they created it, or they have it, or they're staff.
--   4. creator_first_name / creator_last_name are now always null (keys kept,
--      so nothing reading them breaks). The app never displays them — a
--      partner's public identity is their brand name. New additive key
--      creator_brand_name is there if the app wants it.
--   5. last_review_note / last_reviewer_id (internal staff review data) are
--      no longer in the program payload.
--
-- Everything else — every other key, the routines/schedules payload, counts,
-- ordering — is unchanged. Neither function ever returned step content (only
-- step counts), so this is independent of the paid-content lock.
--
-- NOT additive in the strict sense: it replaces two live function bodies. Test
-- in the app afterwards: Today tab, Explore → a program's detail sheet,
-- downloading a program, Library.


-- ─── get_routines_for_daily ──────────────────────────────────────────────────

create or replace function public.get_routines_for_daily(p_user_id uuid)
returns json
language plpgsql
security definer
set search_path = public
as $function$
BEGIN
  -- Only ever answer for the caller themselves.
  IF p_user_id IS NULL OR p_user_id IS DISTINCT FROM auth.uid() THEN
    RETURN '[]'::json;
  END IF;

  RETURN (
    SELECT COALESCE(json_agg(routine_data), '[]'::json)
    FROM (
      SELECT
        -- MyRoutine Fields
        mr.id AS my_routine_id,
        mr.title AS my_routine_title,
        mr.description AS my_routine_description,
        mr.goal AS my_routine_goal,
        mr.start_date,
        mr.category_id AS my_routine_category_id,
        mr.downloaded_routine_id,
        mr.order_number AS my_routine_order_number,
        mr.time_ats AS my_routine_time_ats,
        mr.emoji AS my_routine_emoji,
        mr.specific_time_at AS my_routine_specific_time_at,
        mr.is_personal AS my_routine_is_personal,
        mr.created_at AS my_routine_created_at,
        mr.modified_at AS my_routine_modified_at,

        -- Routine Fields
        r.id AS routine_id,
        r.title AS routine_title,
        r.description AS routine_description,
        r.order_number AS routine_order_number,
        r.category_id AS routine_category_id,
        r.time_ats AS routine_time_ats,
        r.emoji AS routine_emoji,
        r.specific_time_at AS routine_specific_time_at,
        r.created_at AS routine_created_at,
        r.modified_at AS routine_modified_at,

        -- Routine Package Fields
        rp.id AS routine_package_id,
        rp.category_id AS routine_package_category,
        rp.title AS routine_package_title,
        rp.theme_cover_pic_url AS program_cover_url,
        rp.theme_pic_url AS program_pic_url,

        COALESCE((
          SELECT json_agg(rs ORDER BY rs.day)
          FROM public."RoutineSchedules" rs
          WHERE rs.my_routine_id = mr.id
             OR rs.routine_id = r.id
        ), '[]'::json) AS schedules,

        (
          SELECT COUNT(*)
          FROM public."RoutineSteps" rst
          WHERE rst.my_routine_id = mr.id
          OR rst.routine_id = r.id
        ) AS steps_count
      FROM public."MyRoutines" mr
      LEFT JOIN public."Routines" r ON mr.downloaded_routine_id = r.id
      LEFT JOIN public."RoutinePackages" rp ON r.routine_package_id = rp.id

      WHERE mr.user_id = p_user_id
        AND mr.is_started = TRUE

      ORDER BY mr.modified_at DESC
      LIMIT 100
    ) routine_data
  );
END;
$function$;

revoke all on function public.get_routines_for_daily(uuid) from public, anon;
grant execute on function public.get_routines_for_daily(uuid) to authenticated, service_role;


-- ─── get_routine_package_details ─────────────────────────────────────────────

create or replace function public.get_routine_package_details(p_user_id uuid, p_routine_package_id uuid)
returns json
language plpgsql
security definer
set search_path = public
as $function$
DECLARE
  v_uid uuid := auth.uid();
BEGIN
  -- Only ever answer for the caller themselves. Same shape as "not found".
  IF v_uid IS NULL OR p_user_id IS DISTINCT FROM v_uid THEN
    RETURN json_build_object('routinePackage', null, 'routines', null);
  END IF;

  -- Only programs this caller is allowed to see: live & public, their own,
  -- one they already have (even if since taken down), or staff.
  IF NOT EXISTS (
    SELECT 1
    FROM public."RoutinePackages" rp
    WHERE rp.id = p_routine_package_id
      AND (
        (rp.status_id = 7 AND rp.is_personal = false)
        OR rp.creator_id = v_uid
        OR EXISTS (
          SELECT 1 FROM public."MyDownloads" md
          WHERE md.routine_package_id = rp.id AND md.user_id = v_uid
        )
        OR public.is_staff()
      )
  ) THEN
    RETURN json_build_object('routinePackage', null, 'routines', null);
  END IF;

  RETURN (
    SELECT json_build_object(
      -- RoutinePackage details
      'routinePackage', (
        -- Internal review fields dropped; every other package column kept.
        SELECT (to_jsonb(rp) - 'last_review_note' - 'last_reviewer_id')::json
        FROM (
          SELECT
            rp.*,
            usp.display_name AS creator_display_name,
            usp.photo_url AS creator_photo_url,
            -- Kept as keys so nothing reading them breaks, but never a real
            -- person's name: a partner's public identity is their brand.
            NULL::varchar AS creator_first_name,
            NULL::varchar AS creator_last_name,
            NULLIF(btrim(usp.brand_name), '') AS creator_brand_name,
            (
              SELECT COALESCE(AVG(rpr.rating), 0)
              FROM public."RoutinePackageRatings" rpr
              WHERE rpr.routine_package_id = rp.id
            ) AS avg_rating,
            (
              SELECT COUNT(*)
              FROM public."RoutinePackageRatings" rpr
              WHERE rpr.routine_package_id = rp.id
            ) AS ratings_count,
            (
              SELECT rpr.rating
              FROM public."RoutinePackageRatings" rpr
              WHERE rpr.user_id = p_user_id
                AND rpr.routine_package_id = rp.id
            ) AS user_rating,
            (
              SELECT COUNT(*)
              FROM public."RoutinePackageLikes" rpl
              WHERE rpl.routine_package_id = rp.id
            ) AS likes_count,
            (
              SELECT COUNT(*)
              FROM public."MyDownloads" md
              WHERE md.routine_package_id = rp.id
            ) AS downloads_count,
            (
              SELECT md.downloads_date
              FROM public."MyDownloads" md
              WHERE md.routine_package_id = rp.id AND md.user_id = p_user_id
            ) AS downloaded_date,
            EXISTS (
              SELECT 1
              FROM public."RoutinePackageLikes" rpl
              WHERE rpl.routine_package_id = rp.id
                AND rpl.user_id = p_user_id
            ) AS is_liked
          FROM public."RoutinePackages" rp
          LEFT JOIN public."UserProfiles" usp ON usp.id = rp.creator_id
          WHERE rp.id = p_routine_package_id
        ) rp
      ),

      -- Routines with their schedules (unchanged)
      'routines', (
        SELECT json_agg(r ORDER BY r.order_number)
        FROM (
          SELECT
            r.*,
            (
              SELECT COUNT(*)
              FROM public."RoutineSteps" s
              WHERE s.routine_id = r.id
            ) AS steps_count,
            (
              SELECT json_agg(s)
              FROM (
                  SELECT rs.*
                  FROM public."RoutineSchedules" rs
                  WHERE rs.routine_id = r.id
              ) AS s
            ) AS schedules
          FROM public."Routines" r
          WHERE r.routine_package_id = p_routine_package_id
          ORDER BY r.created_at DESC
        ) r
      )
    )
  );
END;
$function$;

revoke all on function public.get_routine_package_details(uuid, uuid) from public, anon;
grant execute on function public.get_routine_package_details(uuid, uuid) to authenticated, service_role;

notify pgrst, 'reload schema';

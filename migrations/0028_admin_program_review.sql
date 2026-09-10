-- admin.routinli.com — the program review queue.
--
-- Numbering: routinli-partners is at 0027, so this takes 0028. (See the note
-- at the end of README — the two repos share one sequence and have collided
-- twice already.)
--
-- Why every read here is a SECURITY DEFINER function rather than an
-- is_staff() SELECT policy: the SELECT policies on RoutinePackages / Routines
-- / RoutineSteps predate both web apps (they came from the FlutterFlow mobile
-- app) and are not described by any migration in either repo. Reviewing means
-- reading a program that is NOT yet published, by someone who does not own it
-- — exactly what those policies are least likely to allow. A definer function
-- sidesteps them entirely and keeps the access rule in one readable place.
--
-- Writes are definer for the same reason: "Creator can edit their package"
-- (partners 0012) is creator-only, so a staff UPDATE over the anon key would
-- be filtered out by RLS even though guard_routine_package_columns() would
-- happily allow it.
--
-- Status ids (public."EnumRoutinePackageStatuses"):
--   1 new · 2 requested review · 3 in review · 4 approved
--   5 rejected ("needs changes" to the partner) · 6 not for sale · 7 active
--
-- IMPORTANT: the mobile Explore feed filters on status_id = 7 ONLY (not the
-- `IN (4, 7)` that routinli-partners' docs/DECISIONS.md claims). So approving
-- to 4 would publish nothing — a program would pass review and stay invisible.
-- Approval therefore sets 7 directly, and 4 is not staff-settable at all.

/* ------------------------------------------------------------------ */
/* 1. queue counts, for the filter tabs                                */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_program_review_counts();

create or replace function public.admin_program_review_counts()
returns table (status_id smallint, status_label text, program_count bigint)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  select e.id::smallint, e.text::text, count(p.id)::bigint
  from public."EnumRoutinePackageStatuses" e
  left join public."RoutinePackages" p
    on p.status_id = e.id and coalesce(p.is_personal, false) = false
  group by e.id, e.text
  order by e.id;
end;
$$;

revoke all on function public.admin_program_review_counts() from public;
grant execute on function public.admin_program_review_counts() to authenticated;

/* ------------------------------------------------------------------ */
/* 2. the queue                                                        */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_list_program_reviews(smallint[], text, integer, integer);

create or replace function public.admin_list_program_reviews(
  p_statuses smallint[] default array[2, 3]::smallint[],
  p_search   text       default null,
  p_limit    integer    default 25,
  p_offset   integer    default 0
)
returns table (
  id                  uuid,
  title               text,
  description         text,
  thumb_url           varchar,
  emoji               text,
  price               double precision,
  end_day             integer,
  status_id           smallint,
  status_label        text,
  category_label      varchar,
  created_at          timestamptz,
  modified_at         timestamptz,
  last_review_note    text,
  last_review_date    timestamptz,
  creator_id          uuid,
  creator_name        text,
  creator_brand       text,
  creator_verified    boolean,
  routine_count       bigint,
  step_count          bigint,
  total_count         bigint
)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  with matched as (
    -- Every column is cast to exactly the type declared in RETURNS TABLE
    -- above. plpgsql matches the two positionally AND by exact type, and a
    -- single mismatch rejects the whole result set with the unhelpful
    -- "structure of query does not match function result type" — naming no
    -- column. The casts make that failure impossible regardless of what the
    -- underlying columns happen to be (title/description are text here but
    -- varchar on Routines, end_day is smallint, last_review_note is varchar).
    select
      p.id::uuid                                            as id,
      p.title::text                                         as title,
      p.description::text                                   as description,
      coalesce(p.theme_pic_url, p.theme_cover_pic_url)::varchar
                                                            as thumb_url,
      p.emoji::text                                         as emoji,
      p.price::double precision                             as price,
      p.end_day::integer                                    as end_day,
      p.status_id::smallint                                 as status_id,
      s.text::text                                          as status_label,
      c.text::varchar                                       as category_label,
      p.created_at::timestamptz                             as created_at,
      p.modified_at::timestamptz                            as modified_at,
      p.last_review_note::text                              as last_review_note,
      p.last_review_date::timestamptz                       as last_review_date,
      p.creator_id::uuid                                    as creator_id,
      coalesce(
        up.display_name,
        nullif(concat_ws(' ', up.first_name, up.last_name), ''),
        'Unknown'
      )::text                                               as creator_name,
      up.brand_name::text                                   as creator_brand,
      (up.verification_status = 2)::boolean                 as creator_verified
    from public."RoutinePackages" p
    left join public."EnumRoutinePackageStatuses" s on s.id = p.status_id
    left join public."EnumCategories"             c on c.id = p.category_id
    left join public."UserProfiles"              up on up.id = p.creator_id
    where coalesce(p.is_personal, false) = false
      and (p_statuses is null or p.status_id = any (p_statuses))
      and (
        p_search is null or btrim(p_search) = ''
        or p.title        ilike '%' || btrim(p_search) || '%'
        or up.brand_name  ilike '%' || btrim(p_search) || '%'
        or up.display_name ilike '%' || btrim(p_search) || '%'
      )
  )
  select
    m.*,
    (select count(*) from public."Routines" r
       where r.routine_package_id = m.id)::bigint            as routine_count,
    (select count(*) from public."RoutineSteps" st
       join public."Routines" r on r.id = st.routine_id
       where r.routine_package_id = m.id)::bigint            as step_count,
    (count(*) over ())::bigint                               as total_count
  from matched m
  -- oldest submission first: a review queue, worked front to back.
  order by m.modified_at asc nulls last, m.created_at asc
  limit  greatest(coalesce(p_limit, 25), 1)
  offset greatest(coalesce(p_offset, 0), 0);
end;
$$;

revoke all on function public.admin_list_program_reviews(smallint[], text, integer, integer) from public;
grant execute on function public.admin_list_program_reviews(smallint[], text, integer, integer) to authenticated;

/* ------------------------------------------------------------------ */
/* 3. the whole program, as the reviewer needs to read it              */
/* ------------------------------------------------------------------ */

-- Program + partner + every routine with its steps, in author order. One call:
-- a reviewer reads top to bottom and decides, so paging the tree would only
-- add round trips.

drop function if exists public.admin_get_program_detail(uuid);

create or replace function public.admin_get_program_detail(p_program_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  p  public."RoutinePackages";
  up public."UserProfiles";
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  select * into p from public."RoutinePackages" where id = p_program_id;
  if p.id is null then
    raise exception 'no program %', p_program_id using errcode = 'P0002';
  end if;

  select * into up from public."UserProfiles" where id = p.creator_id;

  return jsonb_build_object(
    'program', jsonb_build_object(
      'id',                   p.id,
      'title',                p.title,
      'description',          p.description,
      'goal',                 p.goal,
      'emoji',                p.emoji,
      'price',                p.price,
      'end_day',              p.end_day,
      'suggestions',          p.suggestions,
      'tags',                 to_jsonb(p) -> 'tags',
      'is_personal',          coalesce(p.is_personal, false),
      'status_id',            p.status_id,
      'status_label',         (select e.text from public."EnumRoutinePackageStatuses" e
                                 where e.id = p.status_id),
      'category_label',       (select c.text from public."EnumCategories" c
                                 where c.id = p.category_id),
      'theme_cover_pic_url',  p.theme_cover_pic_url,
      'theme_pic_url',        p.theme_pic_url,
      'created_at',           p.created_at,
      'modified_at',          p.modified_at,
      'last_review_note',     p.last_review_note,
      'last_review_date',     p.last_review_date,
      'last_reviewer',        (select coalesce(rp.display_name,
                                        nullif(concat_ws(' ', rp.first_name, rp.last_name), ''))
                                 from public."UserProfiles" rp where rp.id = p.last_reviewer_id)
    ),

    'partner', jsonb_build_object(
      'id',                  up.id,
      'display_name',        up.display_name,
      'brand_name',          up.brand_name,
      'photo_url',           up.photo_url,
      'verification_status', up.verification_status,
      'verified',            (up.verification_status = 2),
      'program_count',       (select count(*) from public."RoutinePackages" o
                                where o.creator_id = p.creator_id
                                  and coalesce(o.is_personal, false) = false),
      -- "published" = actually in the Explore feed, which is status 7 only
      'published_count',     (select count(*) from public."RoutinePackages" o
                                where o.creator_id = p.creator_id
                                  and coalesce(o.is_personal, false) = false
                                  and o.status_id = 7)
    ),

    'routines', coalesce((
      select jsonb_agg(x order by (x ->> 'order_number')::numeric nulls last)
      from (
        select jsonb_build_object(
          'id',              r.id,
          'title',           r.title,
          'description',     r.description,
          'emoji',           r.emoji,
          'order_number',    r.order_number,
          'cover_pic_url',   r.cover_pic_url,
          'show_in_preview', r.show_in_preview,
          'specific_time_at', r.specific_time_at,
          'time_at_labels',  coalesce((
                               select jsonb_agg(t.name order by t."order")
                               from public."EnumRoutineTimeAts" t
                               where to_jsonb(r) -> 'time_ats' @> to_jsonb(t.id)
                             ), '[]'::jsonb),
          'steps',           coalesce((
                               select jsonb_agg(y order by (y ->> 'order_number')::numeric nulls last)
                               from (
                                 select jsonb_build_object(
                                   'id',             st.id,
                                   'title',          st.title,
                                   'description',    st.description,
                                   'duration_value', st.duration_value,
                                   'duration_type',  st.duration_type,
                                   'order_number',   st.order_number,
                                   'media_url',      st.media_url
                                 ) as y
                                 from public."RoutineSteps" st
                                 where st.routine_id = r.id
                                   and st.my_routine_id is null
                                 order by st.order_number
                               ) sy
                             ), '[]'::jsonb)
        ) as x
        from public."Routines" r
        where r.routine_package_id = p_program_id
        order by r.order_number
      ) rx
    ), '[]'::jsonb),

    'history', coalesce((
      select jsonb_agg(z order by z ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'created_at', l.created_at,
                 'from_value', l.from_value,
                 'to_value',   l.to_value,
                 'note',       l.note,
                 'actor',      coalesce(ap.display_name,
                                        nullif(concat_ws(' ', ap.first_name, ap.last_name), ''),
                                        'Unknown')
               ) as z
        from public."StaffAuditLog" l
        left join public."UserProfiles" ap on ap.id = l.actor_id
        where l.action = 'program.review' and l.target_id = p_program_id
        order by l.created_at desc
        limit 20
      ) hz
    ), '[]'::jsonb)
  );
end;
$$;

revoke all on function public.admin_get_program_detail(uuid) from public;
grant execute on function public.admin_get_program_detail(uuid) to authenticated;

/* ------------------------------------------------------------------ */
/* 4. the decision                                                     */
/* ------------------------------------------------------------------ */

-- Writes status_id + the last_review_* trio, appends the audit row, and sends
-- the partner the notification their dashboard already renders — atomically.
-- partners 0009 made last_review_* read-only to partners, so these columns are
-- staff-written only, which is what makes them trustworthy on the portal side.

drop function if exists public.admin_review_program(uuid, smallint, text, boolean);

create or replace function public.admin_review_program(
  p_program_id uuid,
  p_status     smallint,
  p_note       text    default null,
  p_notify     boolean default true
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_actor    uuid := auth.uid();
  v_old      smallint;
  v_creator  uuid;
  v_title    text;
  v_personal boolean;
  v_note     text := nullif(btrim(coalesce(p_note, '')), '');
  n_title    text;
  n_body     text;
  n_color    text;
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  -- 2 back to the queue · 3 claim it · 5 send back for changes · 7 approve
  -- (= live in Explore). 1 and 6 stay the partner's own states; 4 is excluded
  -- because nothing renders it.
  if p_status not in (2, 3, 5, 7) then
    raise exception 'invalid review status: %', p_status using errcode = '22023';
  end if;

  select status_id, creator_id, title, coalesce(is_personal, false)
    into v_old, v_creator, v_title, v_personal
  from public."RoutinePackages"
  where id = p_program_id
  for update;

  if not found then
    raise exception 'no program %', p_program_id using errcode = 'P0002';
  end if;

  -- personal packages are a member's private routines, not marketplace content
  if v_personal then
    raise exception 'personal routines are not reviewable' using errcode = '22023';
  end if;

  -- the partner is shown this note verbatim; sending back without one is useless
  if p_status = 5 and v_note is null then
    raise exception 'a note is required when sending a program back for changes'
      using errcode = '22023';
  end if;

  update public."RoutinePackages"
    set status_id        = p_status,
        last_review_note = case when v_note is not null then v_note else last_review_note end,
        last_review_date = now(),
        last_reviewer_id = v_actor
    where id = p_program_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'program.review', 'RoutinePackages', p_program_id,
     v_old::text, p_status::text, v_note);

  if p_notify then
    case p_status
      when 7 then
        n_title := 'Your program is approved';
        n_body  := coalesce(v_note,
                     concat('“', v_title, '” passed review and is live in Explore.'));
        n_color := 'FF2E5D4B';
      when 5 then
        n_title := 'Changes needed on your program';
        n_body  := concat('“', v_title, '”: ', v_note);
        n_color := 'FFC0392B';
      when 3 then
        n_title := 'Your program is being reviewed';
        n_body  := concat('“', v_title, '” is with our team now. We''ll be in touch shortly.');
        n_color := 'FF2E5D4B';
      else
        n_title := null;  -- back to 2 is a staff bookkeeping move, not news
    end case;

    if n_title is not null then
      insert into public."Notifications"
        (targeted_user_id, title, description, type, color, is_new, send_push,
         link_url, link_label)
      values
        (v_creator, n_title, n_body, 1, n_color, true, true,
         '/dashboard/programs', 'View program');
    end if;
  end if;

  return jsonb_build_object(
    'id', p_program_id,
    'status_id', p_status,
    'status_label', (select e.text from public."EnumRoutinePackageStatuses" e where e.id = p_status)
  );
end;
$$;

revoke all on function public.admin_review_program(uuid, smallint, text, boolean) from public;
grant execute on function public.admin_review_program(uuid, smallint, text, boolean) to authenticated;

-- admin.routinli.com — RoutinePackageReports triage (the mobile app's
-- "Report program" sheet on a program detail screen).
--
-- Numbering: routinli-partners is at 0027; this repo has 0026/0028/0029.
--
-- This is a SECOND, separate report stream from PartnerReports (0029): that
-- one is "this partner is a problem", this one is "this program is a problem".
-- They stay separate because the outcomes differ — a program report is
-- resolved by taking the program down, not by touching the partner's account.
--
-- The table is created and written by the MOBILE app. Everything here is
-- additive and nothing changes how mobile inserts work:
--   * new columns are nullable or defaulted, so an insert that omits them
--     still succeeds exactly as before;
--   * RLS on the table is deliberately NOT touched — enabling or re-policying
--     it could break the mobile insert path, and the definer functions below
--     bypass RLS anyway.

/* ------------------------------------------------------------------ */
/* 1. triage columns                                                   */
/* ------------------------------------------------------------------ */

-- The mobile table records only the accusation (type/type_id/notes/user_id),
-- with nowhere to record what staff did about it. These four columns mirror
-- PartnerReports (0007) so both queues behave the same way.
--
-- The status vocabulary is reused from PartnerReportStatusEnum rather than
-- duplicated (1 Open · 2 Reviewing · 3 Actioned · 4 Dismissed). The name says
-- "Partner", but the four states are generic and a second identical enum
-- table would be worse.
alter table public."RoutinePackageReports"
  add column if not exists status      smallint not null default 1
                                       references public."PartnerReportStatusEnum" (id),
  add column if not exists handled_by  uuid references auth.users (id),
  add column if not exists handled_at  timestamptz,
  add column if not exists staff_notes text;

create index if not exists routinepackagereports_status_idx
  on public."RoutinePackageReports" (status, created_at);
create index if not exists routinepackagereports_package_idx
  on public."RoutinePackageReports" (routine_package_id);

/* ------------------------------------------------------------------ */
/* 2. counts                                                           */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_program_report_counts();

create or replace function public.admin_program_report_counts()
returns table (status smallint, status_label text, report_count bigint)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  select e.id::smallint, e.label::text, count(r.id)::bigint
  from public."PartnerReportStatusEnum" e
  left join public."RoutinePackageReports" r on r.status = e.id
  group by e.id, e.label
  order by e.id;
end;
$$;

revoke all on function public.admin_program_report_counts() from public;
grant execute on function public.admin_program_report_counts() to authenticated;

/* ------------------------------------------------------------------ */
/* 3. the queue                                                        */
/* ------------------------------------------------------------------ */

-- On the reason label: mobile writes both `type` (text) and `type_id`
-- (smallint) and there is no enum table backing type_id, so its meaning is
-- defined only inside FlutterFlow. We therefore show mobile's own `type`
-- string and fall back to "Reason #<id>" — inventing a mapping here would
-- silently mislabel reports the day mobile's dropdown changes.

drop function if exists public.admin_list_program_reports(smallint[], text, integer, integer);

create or replace function public.admin_list_program_reports(
  p_statuses smallint[] default array[1, 2]::smallint[],
  p_search   text       default null,
  p_limit    integer    default 25,
  p_offset   integer    default 0
)
returns table (
  id                   uuid,
  created_at           timestamptz,
  reason_label         text,
  notes                text,
  status               smallint,
  status_label         text,
  staff_notes          text,
  handled_at           timestamptz,
  handled_by_name      text,
  program_id           uuid,
  program_title        text,
  program_status_id    smallint,
  program_thumb_url    text,
  partner_id           uuid,
  partner_name         text,
  reporter_id          uuid,
  reporter_name        text,
  program_open_reports bigint,
  program_total_reports bigint,
  total_count          bigint
)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  with matched as (
    select
      r.id::uuid                                            as id,
      r.created_at::timestamptz                             as created_at,
      coalesce(nullif(btrim(r.type), ''),
               'Reason #' || coalesce(r.type_id::text, '?'))::text
                                                            as reason_label,
      r.notes::text                                         as notes,
      r.status::smallint                                    as status,
      rs.label::text                                        as status_label,
      r.staff_notes::text                                   as staff_notes,
      r.handled_at::timestamptz                             as handled_at,
      coalesce(hp.display_name,
               nullif(concat_ws(' ', hp.first_name, hp.last_name), ''))::text
                                                            as handled_by_name,
      p.id::uuid                                            as program_id,
      p.title::text                                         as program_title,
      p.status_id::smallint                                 as program_status_id,
      coalesce(p.theme_pic_url, p.theme_cover_pic_url)::text
                                                            as program_thumb_url,
      p.creator_id::uuid                                    as partner_id,
      coalesce(pp.brand_name, pp.display_name,
               nullif(concat_ws(' ', pp.first_name, pp.last_name), ''),
               'Unknown')::text                             as partner_name,
      r.user_id::uuid                                       as reporter_id,
      coalesce(rp.display_name,
               nullif(concat_ws(' ', rp.first_name, rp.last_name), ''),
               'A member')::text                            as reporter_name
    from public."RoutinePackageReports" r
    left join public."PartnerReportStatusEnum" rs on rs.id = r.status
    left join public."RoutinePackages" p          on p.id  = r.routine_package_id
    left join public."UserProfiles" pp on pp.id = p.creator_id
    left join public."UserProfiles" rp on rp.id = r.user_id
    left join public."UserProfiles" hp on hp.id = r.handled_by
    where (p_statuses is null or r.status = any (p_statuses))
      and (
        p_search is null or btrim(p_search) = ''
        or p.title       ilike '%' || btrim(p_search) || '%'
        or r.notes       ilike '%' || btrim(p_search) || '%'
        or pp.brand_name ilike '%' || btrim(p_search) || '%'
      )
  )
  select
    m.*,
    (select count(*) from public."RoutinePackageReports" o
       where o.routine_package_id = m.program_id and o.status = 1)::bigint
                                                            as program_open_reports,
    (select count(*) from public."RoutinePackageReports" o
       where o.routine_package_id = m.program_id)::bigint    as program_total_reports,
    (count(*) over ())::bigint                               as total_count
  from matched m
  order by m.created_at asc
  limit  greatest(coalesce(p_limit, 25), 1)
  offset greatest(coalesce(p_offset, 0), 0);
end;
$$;

revoke all on function public.admin_list_program_reports(smallint[], text, integer, integer) from public;
grant execute on function public.admin_list_program_reports(smallint[], text, integer, integer) to authenticated;

/* ------------------------------------------------------------------ */
/* 4. one report, with the program it is about                         */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_get_program_report_detail(uuid);

create or replace function public.admin_get_program_report_detail(p_report_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  r public."RoutinePackageReports";
  p public."RoutinePackages";
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  select * into r from public."RoutinePackageReports" where id = p_report_id;
  if r.id is null then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  select * into p from public."RoutinePackages" where id = r.routine_package_id;

  return jsonb_build_object(
    'report', jsonb_build_object(
      'id',           r.id,
      'created_at',   r.created_at,
      'reason_label', coalesce(nullif(btrim(r.type), ''),
                               'Reason #' || coalesce(r.type_id::text, '?')),
      'type_id',      r.type_id,
      'notes',        r.notes,
      'status',       r.status,
      'status_label', (select label from public."PartnerReportStatusEnum" where id = r.status),
      'staff_notes',  r.staff_notes,
      'handled_at',   r.handled_at,
      'handled_by',   (select coalesce(h.display_name,
                              nullif(concat_ws(' ', h.first_name, h.last_name), ''))
                         from public."UserProfiles" h where h.id = r.handled_by),
      'reporter_id',  r.user_id,
      'reporter_name', (select coalesce(rp.display_name,
                               nullif(concat_ws(' ', rp.first_name, rp.last_name), ''),
                               'A member')
                          from public."UserProfiles" rp where rp.id = r.user_id)
    ),

    'program', case when p.id is null then null else jsonb_build_object(
      'id',            p.id,
      'title',         p.title,
      'description',   p.description,
      'emoji',         p.emoji,
      'price',         p.price,
      'status_id',     p.status_id,
      'status_label',  (select e.text from public."EnumRoutinePackageStatuses" e
                          where e.id = p.status_id),
      'thumb_url',     coalesce(p.theme_pic_url, p.theme_cover_pic_url),
      'created_at',    p.created_at,
      'download_count', (select count(*) from public."MyDownloads" d
                           where d.routine_package_id = p.id),
      'routine_count', (select count(*) from public."Routines" rt
                          where rt.routine_package_id = p.id)
    ) end,

    'partner', case when p.creator_id is null then null else (
      select jsonb_build_object(
        'id',                  up.id,
        'display_name',        up.display_name,
        'brand_name',          up.brand_name,
        'photo_url',           up.photo_url,
        'verification_status', up.verification_status,
        'verified',            (up.verification_status = 2),
        'open_partner_reports', (select count(*) from public."PartnerReports" o
                                   where o.partner_user_id = up.id and o.status = 1)
      )
      from public."UserProfiles" up where up.id = p.creator_id
    ) end,

    'other_reports', coalesce((
      select jsonb_agg(x order by x ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'id',           o.id,
                 'created_at',   o.created_at,
                 'reason_label', coalesce(nullif(btrim(o.type), ''),
                                          'Reason #' || coalesce(o.type_id::text, '?')),
                 'status_label', (select label from public."PartnerReportStatusEnum" where id = o.status),
                 'notes',        o.notes
               ) as x
        from public."RoutinePackageReports" o
        where o.routine_package_id = r.routine_package_id and o.id <> p_report_id
        order by o.created_at desc
        limit 20
      ) t
    ), '[]'::jsonb),

    'history', coalesce((
      select jsonb_agg(z order by z ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'created_at', l.created_at,
                 'action',     l.action,
                 'from_value', l.from_value,
                 'to_value',   l.to_value,
                 'note',       l.note,
                 'actor',      coalesce(ap.display_name,
                                        nullif(concat_ws(' ', ap.first_name, ap.last_name), ''),
                                        'Unknown')
               ) as z
        from public."StaffAuditLog" l
        left join public."UserProfiles" ap on ap.id = l.actor_id
        where l.target_id = p_report_id
        order by l.created_at desc
        limit 20
      ) t
    ), '[]'::jsonb)
  );
end;
$$;

revoke all on function public.admin_get_program_report_detail(uuid) from public;
grant execute on function public.admin_get_program_report_detail(uuid) to authenticated;

/* ------------------------------------------------------------------ */
/* 5. outcomes                                                         */
/* ------------------------------------------------------------------ */

/* 5a. triage only — no effect on the program -------------------------- */

drop function if exists public.admin_set_program_report_status(uuid, smallint, text);

create or replace function public.admin_set_program_report_status(
  p_report_id uuid,
  p_status    smallint,
  p_notes     text default null
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_actor uuid := auth.uid();
  v_old   smallint;
  v_notes text := nullif(btrim(coalesce(p_notes, '')), '');
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if p_status not in (1, 2, 3, 4) then
    raise exception 'invalid report status: %', p_status using errcode = '22023';
  end if;

  select status into v_old from public."RoutinePackageReports"
  where id = p_report_id for update;

  if not found then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  if p_status = 4 and v_notes is null then
    raise exception 'a note is required when dismissing a report'
      using errcode = '22023';
  end if;

  update public."RoutinePackageReports"
    set status      = p_status,
        staff_notes = coalesce(v_notes, staff_notes),
        handled_by  = case when p_status in (3, 4) then v_actor else handled_by end,
        handled_at  = case when p_status in (3, 4) then now() else handled_at end
    where id = p_report_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'program_report.status', 'RoutinePackageReports', p_report_id,
     v_old::text, p_status::text, v_notes);

  -- The reporting member is never told the outcome, same as PartnerReports.
  return jsonb_build_object('id', p_report_id, 'status', p_status);
end;
$$;

revoke all on function public.admin_set_program_report_status(uuid, smallint, text) from public;
grant execute on function public.admin_set_program_report_status(uuid, smallint, text) to authenticated;

/* 5b. take the program down ------------------------------------------ */

-- Moves the program to 5 ("needs changes"), which pulls it out of the Explore
-- feed (status 7 only) and, unlike 6, is a state the partner cannot simply
-- flip back — from 5 they may only resubmit for review. The reason lands in
-- last_review_note, which the partner portal already surfaces, so this reuses
-- the exact channel a normal review rejection uses.
--
-- Members who already downloaded it keep their copy: MyDownloads is untouched.

drop function if exists public.admin_takedown_reported_program(uuid, text);

create or replace function public.admin_takedown_reported_program(
  p_report_id uuid,
  p_reason    text
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_actor    uuid := auth.uid();
  v_old      smallint;
  v_program  uuid;
  v_title    text;
  v_creator  uuid;
  v_pstatus  smallint;
  v_reason   text := nullif(btrim(coalesce(p_reason, '')), '');
  v_changed  boolean := false;
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if v_reason is null then
    raise exception 'a takedown needs a reason — the partner is shown it verbatim'
      using errcode = '22023';
  end if;

  select status, routine_package_id into v_old, v_program
  from public."RoutinePackageReports" where id = p_report_id for update;

  if not found then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  if v_program is null then
    raise exception 'this report is not linked to a program' using errcode = '22023';
  end if;

  select title, creator_id, status_id into v_title, v_creator, v_pstatus
  from public."RoutinePackages" where id = v_program for update;

  if not found then
    raise exception 'the reported program no longer exists' using errcode = 'P0002';
  end if;

  -- only pull it if it is actually published; otherwise just record the outcome
  if v_pstatus in (4, 7) then
    update public."RoutinePackages"
      set status_id        = 5,
          last_review_note = v_reason,
          last_review_date = now(),
          last_reviewer_id = v_actor
      where id = v_program;
    v_changed := true;
  end if;

  update public."RoutinePackageReports"
    set status = 3, staff_notes = v_reason, handled_by = v_actor, handled_at = now()
    where id = p_report_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'program_report.takedown', 'RoutinePackageReports', p_report_id,
     v_old::text, '3', v_reason),
    (v_actor, 'program_report.takedown', 'RoutinePackages', v_program,
     v_pstatus::text, case when v_changed then '5' else v_pstatus::text end, v_reason);

  if v_creator is not null then
    insert into public."Notifications"
      (targeted_user_id, title, description, type, color, is_new, send_push,
       link_url, link_label)
    values
      (v_creator,
       'Your program was taken down',
       concat('“', coalesce(v_title, 'Untitled'), '”: ', v_reason),
       1, 'FFC0392B', true, true, '/dashboard/programs', 'View program');
  end if;

  return jsonb_build_object(
    'id', p_report_id,
    'status', 3,
    'program_taken_down', v_changed
  );
end;
$$;

revoke all on function public.admin_takedown_reported_program(uuid, text) from public;
grant execute on function public.admin_takedown_reported_program(uuid, text) to authenticated;

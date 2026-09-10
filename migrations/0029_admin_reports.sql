-- admin.routinli.com — PartnerReports triage.
--
-- Numbering: routinli-partners is at 0027, this repo has 0026/0028, so 0029.
--
-- The table, both enum tables and the is_staff() RLS policies already exist
-- (routinli-partners 0007) — staff can already SELECT and UPDATE PartnerReports
-- directly. The definer functions here exist for two reasons the policies
-- can't cover:
--   * reporter/partner names come from UserProfiles with no FK PostgREST can
--     embed across (both columns point at auth.users), and
--   * "warn" and "suspend" touch several tables at once and must be atomic.
--
-- PartnerReportStatusEnum: 1 Open · 2 Reviewing · 3 Actioned · 4 Dismissed.

/* ------------------------------------------------------------------ */
/* 1. counts for the filter tabs                                       */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_report_counts();

create or replace function public.admin_report_counts()
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
  left join public."PartnerReports" r on r.status = e.id
  group by e.id, e.label
  order by e.id;
end;
$$;

revoke all on function public.admin_report_counts() from public;
grant execute on function public.admin_report_counts() to authenticated;

/* ------------------------------------------------------------------ */
/* 2. the queue                                                        */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_list_partner_reports(smallint[], text, integer, integer);

create or replace function public.admin_list_partner_reports(
  p_statuses smallint[] default array[1, 2]::smallint[],
  p_search   text       default null,
  p_limit    integer    default 25,
  p_offset   integer    default 0
)
returns table (
  id                  uuid,
  created_at          timestamptz,
  reason_label        text,
  comment             text,
  status              smallint,
  status_label        text,
  staff_notes         text,
  handled_at          timestamptz,
  handled_by_name     text,
  partner_id          uuid,
  partner_name        text,
  partner_brand       text,
  partner_photo_url   text,
  partner_verified    boolean,
  reporter_id         uuid,
  reporter_name       text,
  partner_open_reports bigint,
  partner_total_reports bigint,
  total_count         bigint
)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  -- Every column is cast to exactly its declared type: plpgsql matches
  -- RETURNS TABLE positionally AND by type, and one mismatch rejects the whole
  -- result with a message that names no column.
  return query
  with matched as (
    select
      r.id::uuid                                             as id,
      r.created_at::timestamptz                              as created_at,
      rr.label::text                                         as reason_label,
      r.comment::text                                        as comment,
      r.status::smallint                                     as status,
      rs.label::text                                         as status_label,
      r.staff_notes::text                                    as staff_notes,
      r.handled_at::timestamptz                              as handled_at,
      coalesce(hp.display_name,
               nullif(concat_ws(' ', hp.first_name, hp.last_name), ''))::text
                                                             as handled_by_name,
      r.partner_user_id::uuid                                as partner_id,
      coalesce(pp.display_name,
               nullif(concat_ws(' ', pp.first_name, pp.last_name), ''),
               'Unknown')::text                              as partner_name,
      pp.brand_name::text                                    as partner_brand,
      pp.photo_url::text                                     as partner_photo_url,
      (pp.verification_status = 2)::boolean                  as partner_verified,
      r.reporter_user_id::uuid                               as reporter_id,
      coalesce(rp.display_name,
               nullif(concat_ws(' ', rp.first_name, rp.last_name), ''),
               'A member')::text                             as reporter_name
    from public."PartnerReports" r
    left join public."PartnerReportReasonEnum" rr on rr.id = r.reason
    left join public."PartnerReportStatusEnum" rs on rs.id = r.status
    left join public."UserProfiles" pp on pp.id = r.partner_user_id
    left join public."UserProfiles" rp on rp.id = r.reporter_user_id
    left join public."UserProfiles" hp on hp.id = r.handled_by
    where (p_statuses is null or r.status = any (p_statuses))
      and (
        p_search is null or btrim(p_search) = ''
        or r.comment       ilike '%' || btrim(p_search) || '%'
        or pp.brand_name   ilike '%' || btrim(p_search) || '%'
        or pp.display_name ilike '%' || btrim(p_search) || '%'
      )
  )
  select
    m.*,
    -- repeat offenders are the signal that matters most in triage
    (select count(*) from public."PartnerReports" o
       where o.partner_user_id = m.partner_id and o.status = 1)::bigint
                                                             as partner_open_reports,
    (select count(*) from public."PartnerReports" o
       where o.partner_user_id = m.partner_id)::bigint        as partner_total_reports,
    (count(*) over ())::bigint                                as total_count
  from matched m
  order by m.created_at asc
  limit  greatest(coalesce(p_limit, 25), 1)
  offset greatest(coalesce(p_offset, 0), 0);
end;
$$;

revoke all on function public.admin_list_partner_reports(smallint[], text, integer, integer) from public;
grant execute on function public.admin_list_partner_reports(smallint[], text, integer, integer) to authenticated;

/* ------------------------------------------------------------------ */
/* 3. one report, with everything about the accused partner            */
/* ------------------------------------------------------------------ */

drop function if exists public.admin_get_report_detail(uuid);

create or replace function public.admin_get_report_detail(p_report_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  r  public."PartnerReports";
  pp public."UserProfiles";
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  select * into r from public."PartnerReports" where id = p_report_id;
  if r.id is null then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  select * into pp from public."UserProfiles" where id = r.partner_user_id;

  return jsonb_build_object(
    'report', jsonb_build_object(
      'id',           r.id,
      'created_at',   r.created_at,
      'reason_label', (select label from public."PartnerReportReasonEnum" where id = r.reason),
      'comment',      r.comment,
      'status',       r.status,
      'status_label', (select label from public."PartnerReportStatusEnum" where id = r.status),
      'staff_notes',  r.staff_notes,
      'handled_at',   r.handled_at,
      'handled_by',   (select coalesce(h.display_name,
                              nullif(concat_ws(' ', h.first_name, h.last_name), ''))
                         from public."UserProfiles" h where h.id = r.handled_by),
      'reporter_id',  r.reporter_user_id,
      'reporter_name', (select coalesce(rp.display_name,
                               nullif(concat_ws(' ', rp.first_name, rp.last_name), ''),
                               'A member')
                          from public."UserProfiles" rp where rp.id = r.reporter_user_id)
    ),

    'partner', jsonb_build_object(
      'id',                  pp.id,
      'display_name',        pp.display_name,
      'brand_name',          pp.brand_name,
      'photo_url',           pp.photo_url,
      'bio',                 pp.bio,
      'verification_status', pp.verification_status,
      'verified',            (pp.verification_status = 2),
      'follower_count',      pp.follower_count,
      'created_date_time',   pp.created_date_time,
      -- what a suspension would actually pull down
      'live_program_count',  (select count(*) from public."RoutinePackages" o
                                where o.creator_id = r.partner_user_id
                                  and coalesce(o.is_personal, false) = false
                                  and o.status_id = 7),
      'program_count',       (select count(*) from public."RoutinePackages" o
                                where o.creator_id = r.partner_user_id
                                  and coalesce(o.is_personal, false) = false),
      'block_count',         (select count(*) from public."PartnerBlocks" b
                                where b.partner_user_id = r.partner_user_id)
    ),

    -- every other report against the same partner: the pattern, not the incident
    'other_reports', coalesce((
      select jsonb_agg(x order by x ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'id',           o.id,
                 'created_at',   o.created_at,
                 'reason_label', (select label from public."PartnerReportReasonEnum" where id = o.reason),
                 'status_label', (select label from public."PartnerReportStatusEnum" where id = o.status),
                 'comment',      o.comment
               ) as x
        from public."PartnerReports" o
        where o.partner_user_id = r.partner_user_id and o.id <> p_report_id
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
        where l.target_id in (p_report_id, r.partner_user_id)
          and l.action like 'report.%'
        order by l.created_at desc
        limit 20
      ) t
    ), '[]'::jsonb)
  );
end;
$$;

revoke all on function public.admin_get_report_detail(uuid) from public;
grant execute on function public.admin_get_report_detail(uuid) to authenticated;

/* ------------------------------------------------------------------ */
/* 4. outcomes                                                         */
/* ------------------------------------------------------------------ */

-- Three separate functions rather than one with a mode flag: "note it",
-- "warn them" and "suspend them" have very different blast radii, and keeping
-- them apart means the dangerous one can't be reached by passing the wrong
-- argument to the harmless one.

/* 4a. plain triage — status + notes, no effect on the partner ------- */

drop function if exists public.admin_set_report_status(uuid, smallint, text);

create or replace function public.admin_set_report_status(
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

  select status into v_old from public."PartnerReports"
  where id = p_report_id for update;

  if not found then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  -- dismissing without saying why leaves the next reviewer nothing to go on
  if p_status = 4 and v_notes is null then
    raise exception 'a note is required when dismissing a report'
      using errcode = '22023';
  end if;

  update public."PartnerReports"
    set status      = p_status,
        staff_notes = coalesce(v_notes, staff_notes),
        handled_by  = case when p_status in (3, 4) then v_actor else handled_by end,
        handled_at  = case when p_status in (3, 4) then now() else handled_at end
    where id = p_report_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'report.status', 'PartnerReports', p_report_id,
     v_old::text, p_status::text, v_notes);

  -- The reporter is deliberately NOT notified: telling a member what happened
  -- to the partner they reported leaks a moderation outcome about someone else.
  return jsonb_build_object('id', p_report_id, 'status', p_status);
end;
$$;

revoke all on function public.admin_set_report_status(uuid, smallint, text) from public;
grant execute on function public.admin_set_report_status(uuid, smallint, text) to authenticated;

/* 4b. warn the partner — actions the report and tells them why ------ */

drop function if exists public.admin_warn_partner(uuid, text);

create or replace function public.admin_warn_partner(
  p_report_id uuid,
  p_message   text
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_actor   uuid := auth.uid();
  v_old     smallint;
  v_partner uuid;
  v_msg     text := nullif(btrim(coalesce(p_message, '')), '');
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if v_msg is null then
    raise exception 'a warning needs a message — the partner is shown it verbatim'
      using errcode = '22023';
  end if;

  select status, partner_user_id into v_old, v_partner
  from public."PartnerReports" where id = p_report_id for update;

  if not found then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  update public."PartnerReports"
    set status = 3, staff_notes = v_msg, handled_by = v_actor, handled_at = now()
    where id = p_report_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'report.warn', 'PartnerReports', p_report_id,
     v_old::text, '3', v_msg);

  insert into public."Notifications"
    (targeted_user_id, title, description, type, color, is_new, send_push,
     link_url, link_label)
  values
    (v_partner, 'A warning about your Routinli account', v_msg, 2,
     'FFC0392B', true, true, '/partner-agreement', 'Read the agreement');

  return jsonb_build_object('id', p_report_id, 'status', 3);
end;
$$;

revoke all on function public.admin_warn_partner(uuid, text) from public;
grant execute on function public.admin_warn_partner(uuid, text) to authenticated;

/* 4c. suspend the partner ------------------------------------------ */

-- Suspension is two real consequences, applied together:
--   1. verification_status -> 3 (rejected), which the submit gate in
--      guard_routine_package_columns() reads: they can no longer send anything
--      for review.
--   2. every live program (status 7) -> 5 "needs changes", with the reason in
--      last_review_note.
--
-- Why 5 and not 6 ("not for sale"): a partner may move their own programs
-- 4/6/7 -> 6/7, so unlisting to 6 is something they could simply undo. From 5
-- they can only resubmit (5 -> 1/2), which puts it back through review. This
-- is the only status that takes content down and keeps it down.
--
-- Reversible by staff: re-verify the partner, then approve their programs.

drop function if exists public.admin_suspend_partner(uuid, text);

create or replace function public.admin_suspend_partner(
  p_report_id uuid,
  p_reason    text
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare
  v_actor    uuid := auth.uid();
  v_old      smallint;
  v_partner  uuid;
  v_reason   text := nullif(btrim(coalesce(p_reason, '')), '');
  v_unlisted integer := 0;
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if v_reason is null then
    raise exception 'a suspension needs a reason — the partner is shown it verbatim'
      using errcode = '22023';
  end if;

  select status, partner_user_id into v_old, v_partner
  from public."PartnerReports" where id = p_report_id for update;

  if not found then
    raise exception 'no report %', p_report_id using errcode = 'P0002';
  end if;

  -- 1. block further submissions
  update public."UserProfiles"
    set verification_status = 3
    where id = v_partner;

  -- 2. pull their live programs out of Explore
  with pulled as (
    update public."RoutinePackages"
      set status_id        = 5,
          last_review_note = v_reason,
          last_review_date = now(),
          last_reviewer_id = v_actor
      where creator_id = v_partner
        and coalesce(is_personal, false) = false
        and status_id = 7
      returning 1
  )
  select count(*) into v_unlisted from pulled;

  -- 3. close the report
  update public."PartnerReports"
    set status = 3, staff_notes = v_reason, handled_by = v_actor, handled_at = now()
    where id = p_report_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'report.suspend', 'PartnerReports', p_report_id,
     v_old::text, '3', v_reason),
    (v_actor, 'report.suspend', 'UserProfiles', v_partner,
     'verified', 'suspended',
     concat(v_reason, ' (', v_unlisted, ' program(s) taken down)'));

  insert into public."Notifications"
    (targeted_user_id, title, description, type, color, is_new, send_push,
     link_url, link_label)
  values
    (v_partner, 'Your partner account has been suspended', v_reason, 2,
     'FFC0392B', true, true, '/support', 'Contact support');

  return jsonb_build_object(
    'id', p_report_id,
    'status', 3,
    'programs_taken_down', v_unlisted
  );
end;
$$;

revoke all on function public.admin_suspend_partner(uuid, text) from public;
grant execute on function public.admin_suspend_partner(uuid, text) to authenticated;

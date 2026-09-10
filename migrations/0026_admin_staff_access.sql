-- admin.routinli.com — staff read access + the partner verification queue.
--
-- Numbering continues routinli-partners' sequence (…0025) on purpose: both
-- repos ship migrations to the SAME Supabase project (yyrckzllckuhiwityuac),
-- so the numbers must not collide. Apply in global order across both repos.
--
-- History: everything below except admin_get_partner_detail() was applied to
-- the database while this file was still numbered 0022 — before routinli-
-- partners claimed 0022–0025. Renumbered to 0026 to end the collision. The
-- whole file is idempotent, so re-running it is safe and is how you pick up
-- admin_get_partner_detail().
--
-- Access model (unchanged from routinli-partners):
--   public.is_staff()  -> true for UserProfiles.user_type IN (1 Super User, 4 Admin)
-- Everything here is gated on it. No service-role key is involved; the admin
-- app talks to Postgres as the logged-in staff user and RLS/definer functions
-- decide what that user may see and do.
--
-- Note on `user_type`: this migration deliberately gives staff NO write path
-- to user_type. Staff accounts stay provisioned by hand in the Supabase SQL
-- editor — the admin tool cannot mint or demote admins.

-- Prerequisite: routinli-partners 0022 (bio + social/website columns), 0024
-- (socials in the submit gate) and 0025 (the partner_agreement_version column
-- that 0021 forgot). admin_get_partner_detail() reads all of them. Fail here
-- with a readable message rather than at runtime inside the admin app.
do $$
declare
  missing text;
begin
  select string_agg(c, ', ')
  into missing
  from unnest(array[
    'bio', 'linkedin_url', 'instagram_url', 'tiktok_url', 'youtube_url',
    'website_url', 'partner_agreement_version'
  ]) as c
  where not exists (
    select 1 from information_schema.columns
    where table_schema = 'public'
      and table_name   = 'UserProfiles'
      and column_name  = c
  );

  if missing is not null then
    raise exception
      'Apply routinli-partners migrations 0022/0024/0025 first — UserProfiles is missing: %', missing;
  end if;
end
$$;

/* ------------------------------------------------------------------ */
/* 1. staff can read every profile                                     */
/* ------------------------------------------------------------------ */

-- UserProfiles' only SELECT policy is "read own profile" (migration 0004),
-- so today staff cannot see anyone else's row. Permissive policies OR, so
-- this widens reads for staff only.
drop policy if exists "staff reads all profiles" on public."UserProfiles";
create policy "staff reads all profiles"
  on public."UserProfiles" for select to authenticated
  using (public.is_staff());

-- No matching UPDATE policy on purpose: profile mutations from the admin app
-- go through the narrow SECURITY DEFINER functions below, which touch exactly
-- one column and leave an audit row behind.

/* ------------------------------------------------------------------ */
/* 2. staff audit log                                                  */
/* ------------------------------------------------------------------ */

-- Verification/review decisions otherwise leave no trace of *who* decided.
-- Written only by the definer functions below; staff can read it.
create table if not exists public."StaffAuditLog" (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  actor_id    uuid references auth.users (id) on delete set null,
  action      text not null,          -- e.g. 'partner.verification'
  target_type text not null,          -- e.g. 'UserProfiles'
  target_id   uuid,
  from_value  text,
  to_value    text,
  note        text
);

create index if not exists staffauditlog_target_idx on public."StaffAuditLog" (target_type, target_id, created_at desc);
create index if not exists staffauditlog_actor_idx  on public."StaffAuditLog" (actor_id, created_at desc);

alter table public."StaffAuditLog" enable row level security;

drop policy if exists "staff reads audit log" on public."StaffAuditLog";
create policy "staff reads audit log"
  on public."StaffAuditLog" for select to authenticated
  using (public.is_staff());
-- no insert/update/delete policy: append-only, written by definer functions.

/* ------------------------------------------------------------------ */
/* 3. the verification queue                                           */
/* ------------------------------------------------------------------ */

-- Partner rows joined to auth.users for the email/last-sign-in columns staff
-- need to make a call. auth.users is unreachable over PostgREST, so this has
-- to be a definer function even though UserProfiles itself is now readable.
--
-- UserVerificationStatusEnum: 1 new · 2 verified · 3 rejected · 4 in_progress
-- · 5 incomplete.

drop function if exists public.admin_list_partner_verifications(smallint[], text, integer, integer);

create or replace function public.admin_list_partner_verifications(
  p_statuses smallint[] default null,   -- null = every status
  p_search   text       default null,
  p_limit    integer    default 50,
  p_offset   integer    default 0
)
returns table (
  id                      uuid,
  email                   text,
  first_name              varchar,
  last_name               varchar,
  display_name            varchar,
  brand_name              text,
  photo_url               varchar,
  verification_status     smallint,
  status_label            text,
  created_date_time       timestamptz,
  last_modified_date_time timestamptz,
  follower_count          integer,
  -- order below must track the SELECT list exactly (m.* first, then the
  -- computed columns) — plpgsql matches RETURNS TABLE positionally.
  email_confirmed_at      timestamptz,
  last_sign_in_at         timestamptz,
  program_count           bigint,
  last_decision_at        timestamptz,
  last_decision_note      text,
  total_count             bigint
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
      p.id,
      u.email::text                     as email,
      p.first_name,
      p.last_name,
      p.display_name,
      p.brand_name,
      p.photo_url,
      p.verification_status,
      e.status::text                    as status_label,
      p.created_date_time,
      p.last_modified_date_time,
      p.follower_count,
      u.email_confirmed_at,
      u.last_sign_in_at
    from public."UserProfiles" p
    join auth.users u on u.id = p.id
    left join public."UserVerificationStatusEnum" e on e.id = p.verification_status
    where p.user_type = 3
      and (p_statuses is null or p.verification_status = any (p_statuses))
      and (
        p_search is null or btrim(p_search) = ''
        or u.email        ilike '%' || btrim(p_search) || '%'
        or p.display_name ilike '%' || btrim(p_search) || '%'
        or p.brand_name   ilike '%' || btrim(p_search) || '%'
        or p.first_name   ilike '%' || btrim(p_search) || '%'
        or p.last_name    ilike '%' || btrim(p_search) || '%'
      )
  )
  select
    m.*,
    (select count(*) from public."RoutinePackages" rp
       where rp.creator_id = m.id
         and coalesce(rp.is_personal, false) = false)          as program_count,
    a.created_at                                               as last_decision_at,
    a.note                                                     as last_decision_note,
    count(*) over ()                                           as total_count
  from matched m
  left join lateral (
    select l.created_at, l.note
    from public."StaffAuditLog" l
    where l.action = 'partner.verification'
      and l.target_id = m.id
    order by l.created_at desc
    limit 1
  ) a on true
  -- oldest first: this is a queue, not a feed.
  order by m.created_date_time asc
  limit  greatest(coalesce(p_limit, 50), 1)
  offset greatest(coalesce(p_offset, 0), 0);
end;
$$;

revoke all on function public.admin_list_partner_verifications(smallint[], text, integer, integer) from public;
grant execute on function public.admin_list_partner_verifications(smallint[], text, integer, integer) to authenticated;

/* counts per status, for the filter tabs */
drop function if exists public.admin_partner_verification_counts();

create or replace function public.admin_partner_verification_counts()
returns table (verification_status smallint, status_label text, partner_count bigint)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  return query
  select e.id, e.status::text, count(p.id)
  from public."UserVerificationStatusEnum" e
  left join public."UserProfiles" p
    on p.verification_status = e.id and p.user_type = 3
  group by e.id, e.status
  order by e.id;
end;
$$;

revoke all on function public.admin_partner_verification_counts() from public;
grant execute on function public.admin_partner_verification_counts() to authenticated;

/* ------------------------------------------------------------------ */
/* 4. the decision                                                     */
/* ------------------------------------------------------------------ */

-- One column, one audit row, one notification — atomically.
--
-- The Notifications insert is what makes the decision visible to the partner:
-- routinli-partners already renders the bell + history page, including the
-- link_url / link_label buttons added in migration 0020. Those URLs are
-- app-relative paths on partners.routinli.com.

drop function if exists public.admin_set_partner_verification(uuid, smallint, text, boolean);

create or replace function public.admin_set_partner_verification(
  p_user_id uuid,
  p_status  smallint,
  p_note    text    default null,
  p_notify  boolean default true
)
returns table (id uuid, verification_status smallint, status_label text)
language plpgsql security definer set search_path = public
as $$
declare
  v_actor  uuid := auth.uid();
  v_old    smallint;
  v_note   text := nullif(btrim(coalesce(p_note, '')), '');
  v_title  text;
  v_body   text;
  v_color  text;
  v_link   text;
  v_label  text;
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if p_status not in (1, 2, 3, 4, 5) then
    raise exception 'invalid verification status: %', p_status using errcode = '22023';
  end if;

  select p.verification_status into v_old
  from public."UserProfiles" p
  where p.id = p_user_id and p.user_type = 3
  for update;

  if not found then
    raise exception 'no partner profile for %', p_user_id using errcode = 'P0002';
  end if;

  -- A rejection or an "incomplete" without a reason is useless to the partner
  -- (routinli-partners shows them the note verbatim).
  if p_status in (3, 5) and v_note is null then
    raise exception 'a note is required when rejecting or marking incomplete'
      using errcode = '22023';
  end if;

  update public."UserProfiles"
    set verification_status = p_status
    where "UserProfiles".id = p_user_id;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'partner.verification', 'UserProfiles', p_user_id,
     v_old::text, p_status::text, v_note);

  if p_notify then
    case p_status
      when 2 then
        v_title := 'Your partner account is verified';
        v_body  := coalesce(v_note, 'You''re all set — you can now submit programs for review and publish to the Routinli app.');
        v_color := 'FF2E5D4B';
        v_link  := '/dashboard/programs';
        v_label := 'Start a program';
      when 3 then
        v_title := 'We couldn''t verify your partner account';
        v_body  := v_note;
        v_color := 'FFC0392B';
        v_link  := '/support';
        v_label := 'Contact support';
      when 4 then
        v_title := 'We''re reviewing your partner account';
        v_body  := coalesce(v_note, 'Your details are with our team. We''ll let you know as soon as it''s done.');
        v_color := 'FF2E5D4B';
        v_link  := '/dashboard';
        v_label := 'Go to dashboard';
      when 5 then
        v_title := 'We need a bit more to verify you';
        v_body  := v_note;
        v_color := 'FFC0392B';
        v_link  := '/dashboard/settings';
        v_label := 'Update your details';
      else
        v_title := null;  -- status 1 (back to new) is a correction, not news
    end case;

    if v_title is not null then
      insert into public."Notifications"
        (targeted_user_id, title, description, type, color, is_new, send_push, link_url, link_label)
      values
        (p_user_id, v_title, v_body, 2, v_color, true, true, v_link, v_label);
    end if;
  end if;

  return query
    select p.id, p.verification_status, e.status::text
    from public."UserProfiles" p
    left join public."UserVerificationStatusEnum" e on e.id = p.verification_status
    where p.id = p_user_id;
end;
$$;

revoke all on function public.admin_set_partner_verification(uuid, smallint, text, boolean) from public;
grant execute on function public.admin_set_partner_verification(uuid, smallint, text, boolean) to authenticated;

/* ------------------------------------------------------------------ */
/* 5. one partner, everything staff need to make the call              */
/* ------------------------------------------------------------------ */

-- Returns jsonb rather than a wide RETURNS TABLE because the payload is
-- nested (profile + account + programs + reports + history) — same shape of
-- call as get_partner_dashboard_context() in routinli-partners.
--
-- auth.users columns are read via to_jsonb(u) and pulled out key by key. That
-- keeps the function working across Supabase's own auth-schema changes, and
-- the explicit key list means encrypted_password and the recovery/confirmation
-- token columns can never leak into the payload by accident.

drop function if exists public.admin_get_partner_detail(uuid);

create or replace function public.admin_get_partner_detail(p_user_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  p     public."UserProfiles";
  u     jsonb;
  v_out jsonb;
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  select * into p from public."UserProfiles" where id = p_user_id;
  if p.id is null then
    raise exception 'no profile for %', p_user_id using errcode = 'P0002';
  end if;

  select to_jsonb(au) into u from auth.users au where au.id = p_user_id;

  v_out := jsonb_build_object(
    'profile', jsonb_build_object(
      'id',                        p.id,
      'user_type',                 p.user_type,
      'first_name',                p.first_name,
      'middle_name',               p.middle_name,
      'last_name',                 p.last_name,
      'display_name',              p.display_name,
      'brand_name',                p.brand_name,
      'photo_url',                 p.photo_url,
      'cover_photo_url',           p.cover_photo_url,
      'bio',                       p.bio,
      'linkedin_url',              p.linkedin_url,
      'instagram_url',             p.instagram_url,
      'tiktok_url',                p.tiktok_url,
      'youtube_url',               p.youtube_url,
      'website_url',               p.website_url,
      'verification_status',       p.verification_status,
      'status_label',              (select e.status from public."UserVerificationStatusEnum" e
                                      where e.id = p.verification_status),
      'follower_count',            p.follower_count,
      'requested_deletion',        p.requested_deletion,
      'partner_agreement_version', p.partner_agreement_version,
      'created_date_time',         p.created_date_time,
      'last_modified_date_time',   p.last_modified_date_time
    ),

    'account', jsonb_build_object(
      'email',              u ->> 'email',
      'email_confirmed_at', u ->> 'email_confirmed_at',
      'phone',              nullif(u ->> 'phone', ''),
      'phone_confirmed_at', u ->> 'phone_confirmed_at',
      'created_at',         u ->> 'created_at',
      'last_sign_in_at',    u ->> 'last_sign_in_at',
      'banned_until',       u ->> 'banned_until',
      -- what they typed at signup, before any later profile edit
      'signup_metadata',    coalesce(u -> 'raw_user_meta_data', '{}'::jsonb),
      'providers',          coalesce(
                              (select jsonb_agg(distinct i.provider)
                                 from auth.identities i where i.user_id = p_user_id),
                              '[]'::jsonb)
    ),

    -- Mirrors the submit gate in guard_routine_package_columns()
    -- (routinli-partners 0024): what a partner needs before they can send a
    -- program for review. Staff see exactly which piece is missing.
    'completeness', jsonb_build_object(
      'name',      p.first_name is not null and p.last_name is not null,
      'brand',     p.brand_name is not null,
      'photo',     p.photo_url is not null,
      'bio',       p.bio is not null,
      'social',    (p.linkedin_url is not null or p.instagram_url is not null
                    or p.tiktok_url is not null or p.youtube_url is not null),
      'agreement', p.partner_agreement_version is not null,
      'verified',  p.verification_status = 2
    ),

    'stats', jsonb_build_object(
      'program_count',     (select count(*) from public."RoutinePackages" rp
                              where rp.creator_id = p_user_id
                                and coalesce(rp.is_personal, false) = false),
      -- "published" = in the Explore feed, which filters on status 7 only
      'published_count',   (select count(*) from public."RoutinePackages" rp
                              where rp.creator_id = p_user_id
                                and coalesce(rp.is_personal, false) = false
                                and rp.status_id = 7),
      'download_count',    (select count(*) from public."MyDownloads" d
                              join public."RoutinePackages" rp on rp.id = d.routine_package_id
                              where rp.creator_id = p_user_id),
      'rating_avg',        (select round(avg(r.rating)::numeric, 2)
                              from public."RoutinePackageRatings" r
                              join public."RoutinePackages" rp on rp.id = r.routine_package_id
                              where rp.creator_id = p_user_id),
      'rating_count',      (select count(*) from public."RoutinePackageRatings" r
                              join public."RoutinePackages" rp on rp.id = r.routine_package_id
                              where rp.creator_id = p_user_id),
      'open_report_count', (select count(*) from public."PartnerReports" pr
                              where pr.partner_user_id = p_user_id and pr.status = 1)
    ),

    'programs', coalesce((
      select jsonb_agg(x order by x ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'id',           rp.id,
                 'title',        rp.title,
                 'status_id',    rp.status_id,
                 'status_label', s.text,
                 'price',        rp.price,
                 'created_at',   rp.created_at,
                 'thumb_url',    coalesce(rp.theme_pic_url, rp.theme_cover_pic_url)
               ) as x
        from public."RoutinePackages" rp
        left join public."EnumRoutinePackageStatuses" s on s.id = rp.status_id
        where rp.creator_id = p_user_id
          and coalesce(rp.is_personal, false) = false
        order by rp.created_at desc
        limit 20
      ) t
    ), '[]'::jsonb),

    'reports', coalesce((
      select jsonb_agg(x order by x ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'id',           pr.id,
                 'created_at',   pr.created_at,
                 'reason_label', rr.label,
                 'status_label', rs.label,
                 'comment',      pr.comment
               ) as x
        from public."PartnerReports" pr
        left join public."PartnerReportReasonEnum" rr on rr.id = pr.reason
        left join public."PartnerReportStatusEnum" rs on rs.id = pr.status
        where pr.partner_user_id = p_user_id
        order by pr.created_at desc
        limit 10
      ) t
    ), '[]'::jsonb),

    'history', coalesce((
      select jsonb_agg(x order by x ->> 'created_at' desc)
      from (
        select jsonb_build_object(
                 'created_at', l.created_at,
                 'action',     l.action,
                 'from_value', l.from_value,
                 'to_value',   l.to_value,
                 'note',       l.note,
                 'actor',      coalesce(ap.display_name,
                                        concat_ws(' ', ap.first_name, ap.last_name),
                                        'Unknown')
               ) as x
        from public."StaffAuditLog" l
        left join public."UserProfiles" ap on ap.id = l.actor_id
        where l.target_id = p_user_id
        order by l.created_at desc
        limit 20
      ) t
    ), '[]'::jsonb)
  );

  return v_out;
end;
$$;

revoke all on function public.admin_get_partner_detail(uuid) from public;
grant execute on function public.admin_get_partner_detail(uuid) to authenticated;

-- Follow-up to 0041: that migration surfaced payout status per-*program* on
-- the admin program review screen (partner.payouts_connected). This adds the
-- same signal per-*partner*, on the partner detail page, so staff can see it
-- before any paid program exists to review.
--
-- Not folded into `completeness` (the existing submit-gate checklist mirror):
-- that list is "must all be true to submit anything", but payouts only
-- matter once a partner prices a program. A partner who only ever builds
-- free programs is never expected to connect Stripe, so showing it as a
-- missing/failed checklist item would be misleading. It's its own key
-- instead, informational rather than pass/fail.

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
    -- program for review. Staff see exactly which piece is missing. Payouts
    -- is deliberately NOT here — see 'payouts' below and the note at the top
    -- of this migration for why.
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

    -- Informational, not a gate: only relevant once/if this partner prices a
    -- program. `connected` mirrors PartnerPayoutAccounts.charges_enabled,
    -- the same field guard_routine_package_columns() (0041) requires before
    -- a paid submit, and the same field routinli.com's payeeFor() requires
    -- before a sale.
    'payouts', (
      select jsonb_build_object(
               'connected', coalesce(charges_enabled, false),
               'country',   country
             )
      from public."PartnerPayoutAccounts" where user_id = p_user_id
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

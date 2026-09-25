-- Closes a gap flagged 2026-09-25: a partner could submit and get approved on
-- a *paid* program while never having connected Stripe payouts. Nothing broke
-- (routinli.com's payeeFor()/sellable check already refuses to sell a program
-- with no working payout account, so checkout never calls Stripe in that
-- state) — but the program could sit approved and live, completely unbuyable,
-- with no signal to the partner or to staff that anything was wrong.
--
-- Two independent fixes, both extending existing, already-shipped mechanisms
-- rather than adding new ones:
--
-- 1. guard_routine_package_columns() (0009, last redefined 0024) already
--    hard-blocks a partner's own submit (status_id -> 2) unless verified,
--    profile-complete and agreement-accepted. Add a fourth condition, scoped
--    to paid programs only: PartnerPayoutAccounts.charges_enabled must be
--    true for the submitting partner. Free programs are untouched. This is
--    DB-level, so it can't be bypassed by calling the update directly.
--
-- 2. admin_get_program_detail() (0028) already returns partner.verified so
--    staff can see verification status while reviewing. Add
--    partner.payouts_connected the same way, so a paid program's review
--    screen shows whether it's actually sellable — useful even with (1) in
--    place, e.g. for programs submitted before this migration, or a partner
--    whose Stripe account later lapses after submission but before review.

create or replace function public.guard_routine_package_columns()
returns trigger language plpgsql set search_path = public
as $$
declare
  is_owner    boolean := (auth.uid() = old.creator_id);
  verified    boolean;
  complete    boolean;
  agreed      boolean;
  payouts_ok  boolean;
begin
  -- backend (service_role / SQL) and staff: unrestricted
  if auth.uid() is null or public.is_staff() then
    new.modified_at := now();
    return new;
  end if;

  -- personal packages are a member's own private routines, created and edited
  -- in the mobile app — the marketplace review rules do not apply to them.
  if coalesce(old.is_personal, false) then
    new.modified_at := now();
    return new;
  end if;

  if is_owner then
    if new.creator_id       is distinct from old.creator_id
    or new.last_review_note is distinct from old.last_review_note
    or new.last_review_date is distinct from old.last_review_date
    or new.last_reviewer_id is distinct from old.last_reviewer_id then
      raise exception 'creator_id and review fields are read-only for partners';
    end if;

    if new.status_id is distinct from old.status_id then
      if old.status_id in (1, 2, 5) and new.status_id in (1, 2) then
        null;  -- submit / withdraw / resubmit
      elsif old.status_id in (4, 6, 7) and new.status_id in (6, 7) then
        null;  -- pause / activate an already-approved program
      else
        raise exception
          'partners cannot change program status from % to %', old.status_id, new.status_id;
      end if;

      if new.status_id = 2 then
        select
          verification_status = 2,
          first_name is not null and last_name is not null and brand_name is not null
            and photo_url is not null and bio is not null
            and (linkedin_url is not null or instagram_url is not null
                 or tiktok_url is not null or youtube_url is not null),
          partner_agreement_version is not null
        into verified, complete, agreed
        from public."UserProfiles" where id = auth.uid();

        if not coalesce(verified, false) then
          raise exception
            'your partner account must be verified before submitting a program for review';
        end if;
        if not coalesce(complete, false) then
          raise exception
            'your profile must be complete (name, brand, photo, bio, and at least one social link) before submitting a program for review';
        end if;
        if not coalesce(agreed, false) then
          raise exception
            'you must accept the Partner Agreement before submitting a program for review';
        end if;

        -- Paid only: free programs need no payout account at all.
        if coalesce(new.price, 0) > 0 then
          select coalesce(charges_enabled, false) into payouts_ok
          from public."PartnerPayoutAccounts" where user_id = auth.uid();

          if not coalesce(payouts_ok, false) then
            raise exception
              'connect your bank for payouts before submitting a paid program for review — see the Earnings page';
          end if;
        end if;
      end if;
    end if;
  end if;

  new.modified_at := now();
  return new;
end;
$$;

-- admin_get_program_detail(): add partner.payouts_connected so staff reviewing
-- a paid program can see whether it's actually sellable, without needing a
-- separate lookup. Everything else in the function is unchanged from 0028.

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
      -- Only meaningful for paid programs — a free program needs no payout
      -- account, so the UI should not read anything into this being false.
      'payouts_connected',   coalesce((select charges_enabled from public."PartnerPayoutAccounts"
                                 where user_id = p.creator_id), false),
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

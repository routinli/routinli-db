-- Require at least one social link (LinkedIn/Instagram/TikTok/YouTube —
-- website/other explicitly excluded) as part of "complete profile", both in
-- the DB-level submit gate and in what Overview can see.

create or replace function public.guard_routine_package_columns()
returns trigger language plpgsql set search_path = public
as $$
declare
  is_owner  boolean := (auth.uid() = old.creator_id);
  verified  boolean;
  complete  boolean;
  agreed    boolean;
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
      end if;
    end if;
  end if;

  new.modified_at := now();
  return new;
end;
$$;

create or replace function public.get_partner_dashboard_context()
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  p public."UserProfiles";
  unread_notifications integer := 0;
begin
  select * into p from public."UserProfiles" where id = auth.uid();

  if p.id is null or p.user_type not in (1, 3, 4) then
    return jsonb_build_object('access', false);
  end if;

  select count(*) into unread_notifications
  from public."Notifications"
  where targeted_user_id = auth.uid() and is_new = true;

  return jsonb_build_object(
    'access', true,
    'profile', jsonb_build_object(
      'user_id',                   p.id,
      'user_type',                 p.user_type,
      'verification_status',       p.verification_status,
      'first_name',                p.first_name,
      'last_name',                 p.last_name,
      'display_name',              p.display_name,
      'brand_name',                p.brand_name,
      'photo_url',                 p.photo_url,
      'bio',                       p.bio,
      'linkedin_url',              p.linkedin_url,
      'instagram_url',             p.instagram_url,
      'tiktok_url',                p.tiktok_url,
      'youtube_url',               p.youtube_url,
      'follower_count',            p.follower_count,
      'partner_agreement_version', p.partner_agreement_version
    ),
    'counts', jsonb_build_object(
      'unread_notifications', unread_notifications
    )
  );
end;
$$;

revoke all on function public.get_partner_dashboard_context() from public;
grant execute on function public.get_partner_dashboard_context() to authenticated;

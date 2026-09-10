-- Partner profile fields: bio + social/website links, plus a hard DB-level
-- gate (alongside the existing verification gate) requiring a complete
-- profile and an accepted Partner Agreement before a program can be
-- submitted for review. All new columns are nullable/additive — mobile is
-- unaffected (it never sets or reads these).

alter table public."UserProfiles"
  add column if not exists bio text,
  add column if not exists linkedin_url text,
  add column if not exists instagram_url text,
  add column if not exists tiktok_url text,
  add column if not exists youtube_url text,
  add column if not exists website_url text;

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
            and photo_url is not null and bio is not null,
          partner_agreement_version is not null
        into verified, complete, agreed
        from public."UserProfiles" where id = auth.uid();

        if not coalesce(verified, false) then
          raise exception
            'your partner account must be verified before submitting a program for review';
        end if;
        if not coalesce(complete, false) then
          raise exception
            'your profile must be complete (name, brand, photo, bio) before submitting a program for review';
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

-- Track which version of the Partner Agreement a partner has accepted, so we
-- can prompt re-acceptance if it's ever updated (Agreement section 15).
-- NULL = never accepted (shouldn't happen for new signups going forward,
-- since the signup form now requires the checkbox — but stays nullable since
-- mobile-app member signups never touch this at all).

alter table public."UserProfiles"
  add column if not exists partner_agreement_version text;

-- 1. Signup trigger: also capture the accepted version from signup metadata.
create or replace function public.create_new_user_profile()
returns trigger as $$
declare
  md             jsonb   := coalesce(new.raw_user_meta_data, '{}'::jsonb);
  requested_type smallint;
  v_first        text;
  v_last         text;
  v_display      text;
  v_brand        text;
  v_agreement    text;
begin
  -- role: clamp to what a signup is allowed to self-assign
  begin
    requested_type := (md->>'user_type')::smallint;
  exception when others then
    requested_type := null;
  end;

  v_first     := nullif(trim(coalesce(md->>'first_name', md->>'firstName', md->>'firstname')), '');
  v_last      := nullif(trim(coalesce(md->>'last_name',  md->>'lastName',  md->>'lastname')), '');
  v_brand     := nullif(trim(coalesce(md->>'brand_name', md->>'brandName')), '');
  v_agreement := nullif(trim(coalesce(md->>'partner_agreement_version', md->>'partnerAgreementVersion')), '');

  v_display := nullif(trim(coalesce(
    md->>'display_name',
    md->>'displayName',
    md->>'full_name',
    md->>'fullName',
    md->>'name',
    concat_ws(' ', v_first, v_last)
  )), '');

  insert into public."UserProfiles"
    (id, user_type, first_name, last_name, display_name, brand_name, partner_agreement_version)
  values (
    new.id,
    case when requested_type = 3 then 3 else 2 end,
    v_first,
    v_last,
    v_display,
    v_brand,
    -- only a partner signup can set this; a mobile member signup never sends it
    case when requested_type = 3 then v_agreement else null end
  );

  return new;
end;
$$ language plpgsql security definer;

-- 2. Dashboard context RPC: expose it so Overview can compare against the
--    current PARTNER_AGREEMENT_VERSION constant and prompt re-acceptance.
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

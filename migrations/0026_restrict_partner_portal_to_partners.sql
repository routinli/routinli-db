-- Restrict partners.routinli.com to Partner accounts (user_type = 3) only.
-- Previously Super User (1) and Admin (4) could also log in — useful for
-- testing before an admin portal existed, but going forward that access
-- lives in routinli-admin instead. Staff DB privileges (is_staff(), used by
-- RLS policies and the RoutinePackages status trigger) are unaffected — this
-- only changes who can authenticate into this web app, not what a staff
-- account can do at the data layer once authenticated some other way.

create or replace function public.can_access_partner_portal()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (
      select p.user_type = 3   -- Partner only
      from public."UserProfiles" p
      where p.id = auth.uid()
    ),
    false
  );
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

  if p.id is null or p.user_type <> 3 then
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

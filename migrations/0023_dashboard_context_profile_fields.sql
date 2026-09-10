-- Expose bio on get_partner_dashboard_context() so Overview can compute
-- profile completeness (name/brand/photo already returned; bio was missing).

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

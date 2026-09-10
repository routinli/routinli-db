-- Gate for partners.routinli.com: only Partner / Admin / Super User accounts
-- may use the portal. Regular mobile users (user_type = 2) are refused at
-- login and at the dashboard.
--
-- This function is the single source of truth. The web app calls it right
-- after sign-in (rpc) and the dashboard layout checks user_type server-side;
-- as real tables get RLS, their policies should call this too so a stray
-- session still can't read partner data.

create or replace function public.can_access_partner_portal()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (
      select p.user_type in (1, 3, 4)   -- Super User, Partner, Admin
      from public."UserProfiles" p
      where p.id = auth.uid()
    ),
    false
  );
$$;

revoke all on function public.can_access_partner_portal() from public;
grant execute on function public.can_access_partner_portal() to anon, authenticated;

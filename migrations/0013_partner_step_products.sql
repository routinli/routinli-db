-- Let partners attach products to their template steps.
--
-- MyProducts already works for partners: INSERT/UPDATE/DELETE are gated to
-- (auth.uid() = user_id), SELECT is open. No change needed there.
--
-- RoutineStepProducts only has the *member* write path today
-- (RoutineSteps.my_routine_id IN MyRoutines of auth.uid()). A partner's
-- template step has my_routine_id = NULL, so that path never matches. Add a
-- partner path scoped through step -> routine -> package.creator_id.
--
-- These are ADDITIVE permissive policies — the member path is untouched, so
-- the mobile app keeps working (Postgres OR's permissive policies).

create or replace function public.owns_step(stp uuid)
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (
    select 1
    from public."RoutineSteps" s
    join public."Routines" r          on r.id = s.routine_id
    join public."RoutinePackages" p   on p.id = r.routine_package_id
    where s.id = stp and p.creator_id = auth.uid()
  );
$$;

revoke all on function public.owns_step(uuid) from public;
grant execute on function public.owns_step(uuid) to authenticated;

drop policy if exists "creator adds step products" on public."RoutineStepProducts";
create policy "creator adds step products" on public."RoutineStepProducts"
  for insert to authenticated
  with check (step_id is not null and public.owns_step(step_id));

drop policy if exists "creator updates step products" on public."RoutineStepProducts";
create policy "creator updates step products" on public."RoutineStepProducts"
  for update to authenticated
  using (step_id is not null and public.owns_step(step_id))
  with check (step_id is not null and public.owns_step(step_id));

drop policy if exists "creator deletes step products" on public."RoutineStepProducts";
create policy "creator deletes step products" on public."RoutineStepProducts"
  for delete to authenticated
  using (step_id is not null and public.owns_step(step_id));

-- Partner authoring rules for RoutinePackages + Routines / RoutineSteps /
-- RoutineSchedules.
--
-- Existing policies (set by the mobile app) already let a partner
-- INSERT/SELECT/UPDATE their own RoutinePackages (creator_id = auth.uid()),
-- but:
--   * the UPDATE has no column guard -> a partner can self-publish
--     (set status_id = 7) with no review, and could overwrite the
--     last_review_* fields.
--   * Routines / RoutineSteps / RoutineSchedules only have the *member*
--     write path (my_routine_id in MyRoutines of auth.uid()); there is no
--     partner path for editing a package's own content.
--
-- Status buckets (public."EnumRoutinePackageStatuses"):
--   1 new · 2 requested review · 3 in review · 4 approved
--   5 rejected · 6 not for sale · 7 active
-- Partner-settable transitions: 1/2/5 -> 1/2 (submit, withdraw, resubmit)
-- and 4/6/7 -> 6/7 (pause / activate an already-approved program).
-- Everything else is staff-only. Submitting for review (-> 2) requires a
-- verified partner (UserProfiles.verification_status = 2).

/* ---------------------------------------------------------------- */
/* ownership helpers                                                 */
/* ---------------------------------------------------------------- */

create or replace function public.owns_routine_package(pkg uuid)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public."RoutinePackages"
    where id = pkg and creator_id = auth.uid()
  );
$$;

create or replace function public.owns_routine(rtn uuid)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1
    from public."Routines" r
    join public."RoutinePackages" p on p.id = r.routine_package_id
    where r.id = rtn and p.creator_id = auth.uid()
  );
$$;

revoke all on function public.owns_routine_package(uuid) from public;
revoke all on function public.owns_routine(uuid) from public;
grant execute on function public.owns_routine_package(uuid) to authenticated;
grant execute on function public.owns_routine(uuid) to authenticated;

/* ---------------------------------------------------------------- */
/* 1. column + status guard on RoutinePackages                       */
/* ---------------------------------------------------------------- */

create or replace function public.guard_routine_package_columns()
returns trigger language plpgsql set search_path = public
as $$
declare
  is_owner  boolean := (auth.uid() = old.creator_id);
  verified  boolean;
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
        select verification_status = 2 into verified
        from public."UserProfiles" where id = auth.uid();
        if not coalesce(verified, false) then
          raise exception
            'your partner account must be verified before submitting a program for review';
        end if;
      end if;
    end if;
  end if;

  new.modified_at := now();
  return new;
end;
$$;

drop trigger if exists guard_routine_package_columns on public."RoutinePackages";
create trigger guard_routine_package_columns
  before update on public."RoutinePackages"
  for each row execute function public.guard_routine_package_columns();

/* ---------------------------------------------------------------- */
/* 2. partner DELETE — pristine drafts only, never if downloaded     */
/* ---------------------------------------------------------------- */

drop policy if exists "creator deletes unpublished draft" on public."RoutinePackages";
create policy "creator deletes unpublished draft" on public."RoutinePackages"
  for delete to authenticated
  using (
    creator_id = auth.uid()
    and status_id in (1, 5)
    and not exists (
      select 1 from public."MyDownloads" d
      where d.routine_package_id = "RoutinePackages".id
    )
  );

/* ---------------------------------------------------------------- */
/* 3. partner authoring of Routines                                  */
/* ---------------------------------------------------------------- */

drop policy if exists "creator adds routines" on public."Routines";
create policy "creator adds routines" on public."Routines"
  for insert to authenticated
  with check (public.owns_routine_package(routine_package_id));

drop policy if exists "creator updates own routines" on public."Routines";
create policy "creator updates own routines" on public."Routines"
  for update to authenticated
  using (public.owns_routine_package(routine_package_id))
  with check (public.owns_routine_package(routine_package_id));

drop policy if exists "creator deletes own routines" on public."Routines";
create policy "creator deletes own routines" on public."Routines"
  for delete to authenticated
  using (public.owns_routine_package(routine_package_id));

/* ---------------------------------------------------------------- */
/* 4. partner authoring of RoutineSteps (template steps only)        */
/* ---------------------------------------------------------------- */

drop policy if exists "creator adds steps" on public."RoutineSteps";
create policy "creator adds steps" on public."RoutineSteps"
  for insert to authenticated
  with check (routine_id is not null and public.owns_routine(routine_id));

drop policy if exists "creator updates own steps" on public."RoutineSteps";
create policy "creator updates own steps" on public."RoutineSteps"
  for update to authenticated
  using (routine_id is not null and public.owns_routine(routine_id))
  with check (routine_id is not null and public.owns_routine(routine_id));

drop policy if exists "creator deletes own steps" on public."RoutineSteps";
create policy "creator deletes own steps" on public."RoutineSteps"
  for delete to authenticated
  using (routine_id is not null and public.owns_routine(routine_id));

/* ---------------------------------------------------------------- */
/* 5. partner authoring of RoutineSchedules                          */
/* ---------------------------------------------------------------- */

drop policy if exists "creator adds schedules" on public."RoutineSchedules";
create policy "creator adds schedules" on public."RoutineSchedules"
  for insert to authenticated
  with check (routine_id is not null and public.owns_routine(routine_id));

drop policy if exists "creator updates own schedules" on public."RoutineSchedules";
create policy "creator updates own schedules" on public."RoutineSchedules"
  for update to authenticated
  using (routine_id is not null and public.owns_routine(routine_id))
  with check (routine_id is not null and public.owns_routine(routine_id));

drop policy if exists "creator deletes own schedules" on public."RoutineSchedules";
create policy "creator deletes own schedules" on public."RoutineSchedules"
  for delete to authenticated
  using (routine_id is not null and public.owns_routine(routine_id));

-- NOTE: for a draft delete to cascade cleanly, either the app deletes
-- children first (steps -> schedules -> routines -> package, each covered
-- above) or you add ON DELETE CASCADE to Routines.routine_package_id,
-- RoutineSteps.routine_id, RoutineSchedules.routine_id. Confirm before altering.

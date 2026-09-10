-- Lock down UserProfiles so a signed-in user can edit their own profile data
-- (names, photos, deletion request) but NOT their role or verification.
--
-- Background: the only policy today is
--     "UserProfiles"  FOR ALL  USING (auth.uid() = id)
-- FOR ALL + no WITH CHECK means a user can UPDATE every column on their own row
-- (user_type -> 4 = Admin, verification_status -> verified) and can DELETE the
-- row then re-INSERT it with any values. This closes all three paths.
--
-- Postgres RLS cannot restrict *columns*, so column protection is done with a
-- BEFORE UPDATE trigger; INSERT/DELETE are removed from users entirely.

-- 1. Replace the permissive catch-all -------------------------------------------
drop policy if exists "UserProfiles" on public."UserProfiles";

-- read your own profile
create policy "read own profile"
  on public."UserProfiles" for select
  using (auth.uid() = id);

-- update your own profile (columns are gated by the trigger below)
create policy "update own profile"
  on public."UserProfiles" for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- No INSERT policy: rows are created by create_new_user_profile(), which is
--   SECURITY DEFINER and bypasses RLS. Users never insert directly.
-- No DELETE policy: account removal goes through requested_deletion +
--   the UserDeletion flow, not a direct delete.

-- 2. Block privileged-column changes by the row owner --------------------------
create or replace function public.protect_userprofiles_privileged_columns()
returns trigger as $$
begin
  -- auth.uid() is NULL for service_role / SQL console (backend + admin tooling);
  -- an admin editing someone else's row also skips this check.
  if auth.uid() is not null and auth.uid() = old.id then
    if new.user_type          is distinct from old.user_type
    or new.verification_status is distinct from old.verification_status
    or new.id                  is distinct from old.id
    or new.created_date_time   is distinct from old.created_date_time then
      raise exception
        'user_type, verification_status, id and created_date_time cannot be changed here';
    end if;
  end if;

  new.last_modified_date_time := now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists protect_userprofiles_privileged_columns on public."UserProfiles";
create trigger protect_userprofiles_privileged_columns
  before update on public."UserProfiles"
  for each row execute function public.protect_userprofiles_privileged_columns();

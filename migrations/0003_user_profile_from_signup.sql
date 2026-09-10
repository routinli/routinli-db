-- Extend the auth.users -> UserProfiles trigger so it also copies the name and
-- role that the partners web app collects at signup, while staying safe for the
-- mobile app (which sends no extra metadata, so it keeps getting NULL names and
-- user_type = 2 exactly as before).
--
-- Only the FUNCTION body changes. The existing trigger on auth.users keeps
-- pointing at it by name, so there is nothing else to run.
--
-- What the partners web app sends in options.data:
--   first_name, last_name, full_name, user_type: 3
--
-- Safety rules baked in here:
--   * user_type from a client is honoured only for 2 (User) or 3 (Partner).
--     Super User (1) and Admin (4) can never come from a signup.
--   * name keys are read defensively (snake_case or camelCase) so whatever the
--     mobile app happens to send later also lands correctly.

create or replace function public.create_new_user_profile()
returns trigger as $$
declare
  md             jsonb   := coalesce(new.raw_user_meta_data, '{}'::jsonb);
  requested_type smallint;
  v_first        text;
  v_last         text;
  v_display      text;
begin
  -- role: clamp to what a signup is allowed to self-assign
  begin
    requested_type := (md->>'user_type')::smallint;
  exception when others then
    requested_type := null;
  end;

  v_first := nullif(trim(coalesce(md->>'first_name', md->>'firstName', md->>'firstname')), '');
  v_last  := nullif(trim(coalesce(md->>'last_name',  md->>'lastName',  md->>'lastname')), '');

  v_display := nullif(trim(coalesce(
    md->>'display_name',
    md->>'displayName',
    md->>'full_name',
    md->>'fullName',
    md->>'name',
    concat_ws(' ', v_first, v_last)
  )), '');

  insert into public."UserProfiles" (id, user_type, first_name, last_name, display_name)
  values (
    new.id,
    case when requested_type = 3 then 3 else 2 end,
    v_first,
    v_last,
    v_display
  );

  return new;
end;
$$ language plpgsql security definer;

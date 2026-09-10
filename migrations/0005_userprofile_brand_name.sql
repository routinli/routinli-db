-- Adds brand_name to the signup -> UserProfiles trigger.
-- The partners web app now collects a Brand / Business name and sends it as
-- brand_name in options.data. Only the function body changes; the trigger on
-- auth.users still points here by name.
--
-- Assumes the column already exists:
--   alter table public."UserProfiles" add column if not exists brand_name text;
--
-- brand_name is partner-only. The mobile app sends no brand_name, so its
-- profiles get NULL exactly as before.

create or replace function public.create_new_user_profile()
returns trigger as $$
declare
  md             jsonb   := coalesce(new.raw_user_meta_data, '{}'::jsonb);
  requested_type smallint;
  v_first        text;
  v_last         text;
  v_display      text;
  v_brand        text;
begin
  -- role: clamp to what a signup is allowed to self-assign
  begin
    requested_type := (md->>'user_type')::smallint;
  exception when others then
    requested_type := null;
  end;

  v_first := nullif(trim(coalesce(md->>'first_name', md->>'firstName', md->>'firstname')), '');
  v_last  := nullif(trim(coalesce(md->>'last_name',  md->>'lastName',  md->>'lastname')), '');
  v_brand := nullif(trim(coalesce(md->>'brand_name', md->>'brandName')), '');

  v_display := nullif(trim(coalesce(
    md->>'display_name',
    md->>'displayName',
    md->>'full_name',
    md->>'fullName',
    md->>'name',
    concat_ws(' ', v_first, v_last)
  )), '');

  insert into public."UserProfiles" (id, user_type, first_name, last_name, display_name, brand_name)
  values (
    new.id,
    case when requested_type = 3 then 3 else 2 end,
    v_first,
    v_last,
    v_display,
    v_brand
  );

  return new;
end;
$$ language plpgsql security definer;

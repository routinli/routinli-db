-- admin.routinli.com — orphaned media cleanup for the `images` bucket.
--
-- Numbering: routinli-partners is at 0027; this repo has 0026/0028/0029/0030.
--
-- WHY THIS IS A DEFINER FUNCTION AND NOT A SERVICE-KEY QUERY
-- ---------------------------------------------------------
-- Deleting a file because we failed to see the row that references it is the
-- worst outcome this tool can produce, and that failure is not hypothetical:
-- `service_role` currently has NO SELECT grant on public."RoutineSteps"
--     permission denied for table RoutineSteps (42501)
-- so a service-key scan silently returns zero step-media references and every
-- step image in the bucket looks orphaned. Measured against the real bucket
-- that was 27 files / 53 MB of live content offered up for deletion.
--
-- A SECURITY DEFINER function runs as its owner (postgres), which owns the
-- tables, so neither RLS nor a missing grant can quietly hide a reference.
-- The service-role key is still needed for the Storage API (listing and
-- deleting objects has no SQL equivalent) but never for deciding what is
-- referenced.
--
-- Separately: that missing grant is worth fixing on its own —
--     grant select on public."RoutineSteps" to service_role;
-- any other server-side code using the service key on that table is broken.

drop function if exists public.admin_referenced_media_paths();

create or replace function public.admin_referenced_media_paths()
returns table (path text, source text)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  -- Every column anywhere in the schema that can hold a storage URL. If a new
  -- one is added and not listed here, its files will look orphaned — so this
  -- list is the safety-critical part of the whole feature.
  return query
  with raw as (
    select p.theme_cover_pic_url::text as url,
           'RoutinePackages.theme_cover_pic_url'::text as src
      from public."RoutinePackages" p
    union all
    select p.theme_pic_url::text, 'RoutinePackages.theme_pic_url'
      from public."RoutinePackages" p
    union all
    select r.cover_pic_url::text, 'Routines.cover_pic_url'
      from public."Routines" r
    union all
    -- includes members' personal routines (my_routine_id is not null):
    -- those media files are just as live as a partner's.
    select s.media_url::text, 'RoutineSteps.media_url'
      from public."RoutineSteps" s
    union all
    select u.photo_url::text, 'UserProfiles.photo_url'
      from public."UserProfiles" u
    union all
    select u.cover_photo_url::text, 'UserProfiles.cover_photo_url'
      from public."UserProfiles" u
    union all
    select n.photo_url::text, 'Notifications.photo_url'
      from public."Notifications" n
    union all
    select c.default_cover_url::text, 'EnumCategories.default_cover_url'
      from public."EnumCategories" c
    union all
    select c.default_picture_url::text, 'EnumCategories.default_picture_url'
      from public."EnumCategories" c
    union all
    select c.step_image_url::text, 'EnumCategories.step_image_url'
      from public."EnumCategories" c
  ),
  cleaned as (
    select
      -- drop any query string, then take everything after the bucket segment.
      -- Still percent-encoded here; the caller decodes, because Postgres has
      -- no built-in URL decode and Storage returns decoded names.
      substring(split_part(raw.url, '?', 1)
                from position('/images/' in split_part(raw.url, '?', 1)) + 8) as p,
      raw.src
    from raw
    where raw.url is not null
      and position('/images/' in split_part(raw.url, '?', 1)) > 0
  )
  select distinct
    btrim(cleaned.p, '/')::text,
    cleaned.src::text
  from cleaned
  where btrim(cleaned.p, '/') <> '';
end;
$$;

revoke all on function public.admin_referenced_media_paths() from public;
grant execute on function public.admin_referenced_media_paths() to authenticated;

/* ------------------------------------------------------------------ */
/* audit: record every deletion                                        */
/* ------------------------------------------------------------------ */

-- Storage deletes happen over the Storage API, not in SQL, so the app calls
-- this to leave the audit trail. Object paths are not recoverable once gone;
-- this is the only record that they existed.

drop function if exists public.admin_log_media_deletion(text[], bigint);

create or replace function public.admin_log_media_deletion(
  p_paths text[],
  p_bytes bigint default null
)
returns void
language plpgsql security definer set search_path = public
as $$
declare
  v_actor uuid := auth.uid();
begin
  if not public.is_staff() then
    raise exception 'not authorized' using errcode = '42501';
  end if;

  if p_paths is null or array_length(p_paths, 1) is null then
    return;
  end if;

  insert into public."StaffAuditLog"
    (actor_id, action, target_type, target_id, from_value, to_value, note)
  values
    (v_actor, 'media.delete', 'storage.images', null,
     array_length(p_paths, 1)::text,
     coalesce(p_bytes, 0)::text,
     array_to_string(p_paths, E'\n'));
end;
$$;

revoke all on function public.admin_log_media_deletion(text[], bigint) from public;
grant execute on function public.admin_log_media_deletion(text[], bigint) to authenticated;

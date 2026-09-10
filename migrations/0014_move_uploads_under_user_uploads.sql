-- Move partner uploads from  images/<user_id>/programs/...
-- to                         images/user_uploads/<user_id>/programs/...
--
-- ORDER OF OPERATIONS:
--   1. Deploy the code change (uploadMedia now writes under user_uploads/).
--   2. In the Storage console, move the existing <user_id> folder into
--      user_uploads/.
--   3. Run this migration to (a) rewrite the stored URLs and (b) widen the
--      DELETE policy so the new path is still owner-deletable.
--
-- The URL rewrite only touches URLs shaped
--   .../object/public/images/<uuid>/...   (the old portal convention)
-- so it is a no-op on already-migrated URLs and on anything else.

/* ------------------------------------------------------------------ */
/* 1. rewrite stored image / media URLs                               */
/* ------------------------------------------------------------------ */

update public."RoutinePackages"
set theme_cover_pic_url = regexp_replace(
      theme_cover_pic_url,
      '/public/images/([0-9a-f-]{36})/',
      '/public/images/user_uploads/\1/'
    )
where theme_cover_pic_url ~ '/public/images/[0-9a-f-]{36}/';

update public."RoutinePackages"
set theme_pic_url = regexp_replace(
      theme_pic_url,
      '/public/images/([0-9a-f-]{36})/',
      '/public/images/user_uploads/\1/'
    )
where theme_pic_url ~ '/public/images/[0-9a-f-]{36}/';

update public."Routines"
set cover_pic_url = regexp_replace(
      cover_pic_url,
      '/public/images/([0-9a-f-]{36})/',
      '/public/images/user_uploads/\1/'
    )
where cover_pic_url ~ '/public/images/[0-9a-f-]{36}/';

update public."RoutineSteps"
set media_url = regexp_replace(
      media_url,
      '/public/images/([0-9a-f-]{36})/',
      '/public/images/user_uploads/\1/'
    )
where media_url ~ '/public/images/[0-9a-f-]{36}/';

/* ------------------------------------------------------------------ */
/* 2. widen the storage DELETE policy                                 */
/*    (additive OR branch — cannot break existing deletes)            */
/* ------------------------------------------------------------------ */

drop policy if exists "Users can delete their own images" on storage.objects;
create policy "Users can delete their own images" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'images'
    and (
      (storage.foldername(name))[1] = auth.uid()::text
      or (
        (storage.foldername(name))[1] = 'user_uploads'
        and (storage.foldername(name))[2] = auth.uid()::text
      )
    )
  );

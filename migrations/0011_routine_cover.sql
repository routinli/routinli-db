-- Routines need a landscape cover image (16:9), like RoutinePackages has.
alter table public."Routines"
  add column if not exists cover_pic_url varchar;

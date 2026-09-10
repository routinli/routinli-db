-- Add an optional action target to Notifications so the partner dashboard can
-- render a "View"/"Reply"/etc. button. Nullable, additive — mobile's existing
-- inserts/reads are unaffected either way.

alter table public."Notifications"
  add column if not exists link_url varchar,
  add column if not exists link_label varchar;

-- Recovery migration: 0021 added partner_agreement_version to the
-- create_new_user_profile() trigger and get_partner_dashboard_context()
-- RPC, but the column itself was apparently never added (0022/0023/0024
-- all assumed it existed, which is why get_partner_dashboard_context()
-- has been erroring on every call — p.partner_agreement_version doesn't
-- exist on the row type). Just the missing column, nothing else — the
-- function definitions currently installed (from 0024) are already
-- correct and should NOT be re-run/rolled back.

alter table public."UserProfiles"
  add column if not exists partner_agreement_version text;

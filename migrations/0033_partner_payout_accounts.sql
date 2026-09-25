-- One row per partner: the link between a Routinli partner and their Stripe
-- Connect "connected account" (the acct_... ID checkout pays their 70% share to).
--
-- WHO WRITES THIS: only trusted server code (the partners app's Connect
-- onboarding + the Stripe webhook, both using the service-role key). There are
-- deliberately NO insert/update/delete policies for `authenticated`:
--   * stripe_account_id decides where money is sent — a partner must not be able
--     to point their own row at an arbitrary account.
--   * charges_enabled / payouts_enabled mirror what Stripe says about the
--     account; they must come from Stripe's webhook, never from the client.
-- Partners may READ their own row (the Earnings page shows onboarding status);
-- staff may read all rows. Checkout (server-side, service role) reads a
-- program creator's row to fill transfer_data.destination — members never
-- need direct access to this table.
--
-- Additive only: new table, nothing the mobile app touches.

create table if not exists public."PartnerPayoutAccounts" (
  user_id            uuid primary key references auth.users (id) on delete cascade,
  stripe_account_id  text not null unique,
  charges_enabled    boolean not null default false,
  payouts_enabled    boolean not null default false,
  details_submitted  boolean not null default false,
  country            text,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

alter table public."PartnerPayoutAccounts" enable row level security;

drop policy if exists "partner reads own payout account" on public."PartnerPayoutAccounts";
create policy "partner reads own payout account" on public."PartnerPayoutAccounts"
  for select to authenticated
  using (user_id = auth.uid());

drop policy if exists "staff reads payout accounts" on public."PartnerPayoutAccounts";
create policy "staff reads payout accounts" on public."PartnerPayoutAccounts"
  for select to authenticated
  using (public.is_staff());

-- Explicit grants: this database has had tables where service_role lacked a
-- grant, so don't rely on defaults. No anon access; writes are service-role only.
revoke all on public."PartnerPayoutAccounts" from anon, authenticated;
grant select on public."PartnerPayoutAccounts" to authenticated;
grant all on public."PartnerPayoutAccounts" to service_role;

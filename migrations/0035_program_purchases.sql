-- Web purchases & free claims for routinli.com (the member-facing web app).
--
-- ADDITIVE ONLY: one new table and new functions. No existing table, column,
-- policy or function is changed. (0034 is the separate, reviewed-first fix to
-- get_routines_for_daily / get_routine_package_details.)
--
-- ── How a program gets into a member's Library from the web ─────────────────
-- Exactly what the mobile app writes when it downloads a program — one
-- MyDownloads row + one MyRoutines row per routine (steps/schedules are never
-- copied; the app reads them from the source routine) — with ONE deliberate
-- difference: web grants are NOT STARTED (is_started = false). The member
-- starts the program from the app (same as restarting a stopped program).
-- Note MyRoutines.is_started and .is_personal both DEFAULT TO TRUE, so both
-- are set to false explicitly below.
--
-- ── Money ───────────────────────────────────────────────────────────────────
-- Stripe Checkout, destination charges, Routinli = merchant of record.
-- transfer_data.amount = 70% of the PRE-TAX price goes to the partner; Routinli
-- keeps 30% + all collected tax (which it remits), and pays Stripe's fees.
-- Programs by Routinli's own account keep 100% (no transfer).
--
-- ProgramPurchases records paid web purchases only (free claims are just a
-- Library grant). Partners must never read it — it names buyers. Partner
-- earnings will come through an aggregate function later.


-- ─── purchases ───────────────────────────────────────────────────────────────

create table if not exists public."ProgramPurchases" (
  id                          uuid primary key default gen_random_uuid(),

  -- Kept (set null) if the account or program is later deleted: purchase
  -- records are retained for tax purposes, as the Privacy Policy says.
  user_id                     uuid references auth.users (id) on delete set null,
  routine_package_id          uuid references public."RoutinePackages" (id) on delete set null,
  program_title               text not null,        -- as sold, for history even if renamed/removed
  partner_id                  uuid,                 -- creator at time of sale (no FK: history survives)

  stripe_checkout_session_id  text not null unique, -- idempotency key: one row per paid session
  stripe_payment_intent_id    text unique,
  stripe_charge_id            text,
  stripe_receipt_url          text,

  currency                    text not null,
  amount_subtotal             integer not null,     -- cents, pre-tax (the program price)
  amount_tax                  integer not null default 0,
  amount_total                integer not null,
  partner_amount              integer not null default 0,  -- transfer_data.amount; 0 for Routinli's own
  stripe_destination_account  text,                 -- acct_… the partner share went to; null for Routinli's own
  stripe_transfer_id          text,

  ref                         text,                 -- optional ?ref= from the checkout link: recorded, NEVER trusted

  -- 'already_owned' = paid, but the member already had the program (e.g. two
  -- checkout tabs). Needs a refund — flagged here for staff.
  status                      text not null default 'completed'
                                check (status in ('completed', 'already_owned')),

  -- Refunds / transfer reversals are a later phase; the columns are here now.
  refund_status               text not null default 'none'
                                check (refund_status in ('none', 'partial', 'full')),
  amount_refunded             integer not null default 0,
  stripe_transfer_reversal_id text,
  refunded_at                 timestamptz,

  created_at                  timestamptz not null default now(),
  updated_at                  timestamptz not null default now()
);

create index if not exists "ProgramPurchases_user_created_idx"
  on public."ProgramPurchases" (user_id, created_at desc);

alter table public."ProgramPurchases" enable row level security;

drop policy if exists "member reads own purchases" on public."ProgramPurchases";
create policy "member reads own purchases" on public."ProgramPurchases"
  for select to authenticated
  using (user_id = auth.uid());

drop policy if exists "staff reads purchases" on public."ProgramPurchases";
create policy "staff reads purchases" on public."ProgramPurchases"
  for select to authenticated
  using (public.is_staff());

-- No client writes at all: rows come only from the Stripe webhook (service
-- role). Explicit grants — don't rely on defaults in this database.
revoke all on public."ProgramPurchases" from anon, authenticated;
grant select on public."ProgramPurchases" to authenticated;
grant all on public."ProgramPurchases" to service_role;


-- ─── internal: put a program in a member's Library ───────────────────────────
-- Returns true if newly granted, false if they already had it. Serialised per
-- (member, program) so a webhook retry racing a success-page load, or a
-- double-clicked free claim, can never write two copies.

create or replace function public._grant_program(p_user_id uuid, p_program_id uuid, p_price double precision)
returns boolean
language plpgsql security definer set search_path = public
as $$
declare
  v_category smallint;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text || ':' || p_program_id::text, 0));

  if exists (
    select 1 from public."MyDownloads"
    where user_id = p_user_id and routine_package_id = p_program_id
  ) then
    return false;
  end if;

  select category_id into v_category from public."RoutinePackages" where id = p_program_id;
  if not found then
    raise exception 'program % does not exist', p_program_id;
  end if;

  insert into public."MyDownloads" (user_id, routine_package_id, price, downloads_date)
  values (p_user_id, p_program_id, p_price, now());

  -- Same values the app writes for a download (order_number 1, time_ats {1},
  -- the PROGRAM's category, title/goal/etc. left null), except NOT STARTED.
  insert into public."MyRoutines"
    (user_id, downloaded_routine_id, category_id, is_personal, is_started, start_date, order_number, time_ats)
  select p_user_id, r.id, v_category, false, false, now(), 1, array[1]::smallint[]
  from public."Routines" r
  where r.routine_package_id = p_program_id;

  return true;
end;
$$;

revoke all on function public._grant_program(uuid, uuid, double precision) from public, anon, authenticated;


-- ─── paid: called by the Stripe webhook / success page (service role only) ───
-- Safe to call any number of times for the same Checkout Session: the unique
-- session id makes every call after the first a no-op ('duplicate').
-- Returns 'granted' | 'already_owned' | 'duplicate'.

create or replace function public.complete_program_purchase(
  p_user_id            uuid,
  p_program_id         uuid,
  p_program_title      text,
  p_partner_id         uuid,
  p_session_id         text,
  p_payment_intent_id  text,
  p_charge_id          text,
  p_receipt_url        text,
  p_currency           text,
  p_amount_subtotal    integer,
  p_amount_tax         integer,
  p_amount_total       integer,
  p_partner_amount     integer,
  p_destination        text,
  p_transfer_id        text,
  p_ref                text
)
returns text
language plpgsql security definer set search_path = public
as $$
declare
  v_id uuid;
begin
  insert into public."ProgramPurchases" (
    user_id, routine_package_id, program_title, partner_id,
    stripe_checkout_session_id, stripe_payment_intent_id, stripe_charge_id, stripe_receipt_url,
    currency, amount_subtotal, amount_tax, amount_total,
    partner_amount, stripe_destination_account, stripe_transfer_id, ref
  ) values (
    p_user_id, p_program_id, p_program_title, p_partner_id,
    p_session_id, p_payment_intent_id, p_charge_id, p_receipt_url,
    p_currency, p_amount_subtotal, coalesce(p_amount_tax, 0), p_amount_total,
    coalesce(p_partner_amount, 0), p_destination, p_transfer_id, left(p_ref, 64)
  )
  on conflict (stripe_checkout_session_id) do nothing
  returning id into v_id;

  if v_id is null then
    return 'duplicate';
  end if;

  -- MyDownloads.price is in the same units as RoutinePackages.price (dollars).
  if public._grant_program(p_user_id, p_program_id, p_amount_subtotal / 100.0) then
    return 'granted';
  end if;

  update public."ProgramPurchases"
     set status = 'already_owned', updated_at = now()
   where id = v_id;
  return 'already_owned';
end;
$$;

revoke all on function public.complete_program_purchase(
  uuid, uuid, text, uuid, text, text, text, text, text, integer, integer, integer, integer, text, text, text
) from public, anon, authenticated;
grant execute on function public.complete_program_purchase(
  uuid, uuid, text, uuid, text, text, text, text, text, integer, integer, integer, integer, text, text, text
) to service_role;


-- ─── free: a signed-in member claims a free program for THEMSELVES ───────────
-- No service role needed: always acts for auth.uid(), and only for programs
-- that are publicly listed AND free (checked through the same single rule the
-- public catalog uses). Returns 'granted' | 'already_owned' | 'not_available'.

create or replace function public.claim_free_program(p_program_id uuid)
returns text
language plpgsql security definer set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'must be signed in';
  end if;

  if not exists (
    select 1 from public._public_program_cards() c
    where c.id = p_program_id and coalesce(c.price, 0) = 0
  ) then
    return 'not_available';
  end if;

  if public._grant_program(v_uid, p_program_id, 0) then
    return 'granted';
  end if;
  return 'already_owned';
end;
$$;

revoke all on function public.claim_free_program(uuid) from public, anon;
grant execute on function public.claim_free_program(uuid) to authenticated, service_role;

notify pgrst, 'reload schema';

-- Partner-directed member actions: report, block, follow.
-- Consumed mostly by the mobile app (members acting on partners) and the admin
-- side (triaging reports). The partner portal reads only its own follower_count.
--
-- Naming: `Partner*` mirrors the existing `RoutinePackage*` tables. Enum tables
-- use the `…Enum` suffix (matches UserTypesEnum / UserVerificationStatusEnum).

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

-- staff = Super User (1) or Admin (4). Sits alongside can_access_partner_portal().
create or replace function public.is_staff()
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce(
    (select user_type in (1, 4) from public."UserProfiles" where id = auth.uid()),
    false
  );
$$;

revoke all on function public.is_staff() from public;
grant execute on function public.is_staff() to authenticated;

/* ------------------------------------------------------------------ */
/* enum tables                                                        */
/* ------------------------------------------------------------------ */

create table if not exists public."PartnerReportStatusEnum" (
  id    smallint primary key,
  label text not null
);
insert into public."PartnerReportStatusEnum" (id, label) values
  (1, 'Open'), (2, 'Reviewing'), (3, 'Actioned'), (4, 'Dismissed')
on conflict (id) do nothing;

create table if not exists public."PartnerReportReasonEnum" (
  id    smallint primary key,
  label text not null
);
insert into public."PartnerReportReasonEnum" (id, label) values
  (1, 'Inappropriate content'),
  (2, 'Misleading or false claims'),
  (3, 'Spam or scam'),
  (4, 'Impersonation'),
  (5, 'Safety concern'),
  (6, 'Other')
on conflict (id) do nothing;

alter table public."PartnerReportStatusEnum" enable row level security;
alter table public."PartnerReportReasonEnum" enable row level security;
drop policy if exists "read report statuses" on public."PartnerReportStatusEnum";
create policy "read report statuses" on public."PartnerReportStatusEnum"
  for select to authenticated using (true);
drop policy if exists "read report reasons" on public."PartnerReportReasonEnum";
create policy "read report reasons" on public."PartnerReportReasonEnum"
  for select to authenticated using (true);

/* ------------------------------------------------------------------ */
/* PartnerReports — a member reports a partner to Routinli            */
/* ------------------------------------------------------------------ */

create table if not exists public."PartnerReports" (
  id               uuid primary key default gen_random_uuid(),
  created_at       timestamptz not null default now(),
  reporter_user_id uuid not null references auth.users (id) on delete cascade,
  partner_user_id  uuid not null references auth.users (id) on delete cascade,
  reason           smallint references public."PartnerReportReasonEnum" (id),
  comment          text not null,
  status           smallint not null default 1
                     references public."PartnerReportStatusEnum" (id),
  handled_by       uuid references auth.users (id),
  handled_at       timestamptz,
  staff_notes      text,
  constraint partnerreports_not_self check (reporter_user_id <> partner_user_id)
);

create index if not exists partnerreports_partner_idx  on public."PartnerReports" (partner_user_id);
create index if not exists partnerreports_reporter_idx on public."PartnerReports" (reporter_user_id);
create index if not exists partnerreports_status_idx   on public."PartnerReports" (status);
-- at most one open report per member per partner (stops spam, allows re-report later)
create unique index if not exists partnerreports_one_open
  on public."PartnerReports" (reporter_user_id, partner_user_id) where status = 1;

alter table public."PartnerReports" enable row level security;

drop policy if exists "reporter creates own report" on public."PartnerReports";
create policy "reporter creates own report" on public."PartnerReports"
  for insert to authenticated
  with check (reporter_user_id = auth.uid());

drop policy if exists "reporter or staff reads reports" on public."PartnerReports";
create policy "reporter or staff reads reports" on public."PartnerReports"
  for select to authenticated
  using (reporter_user_id = auth.uid() or public.is_staff());

drop policy if exists "staff triages reports" on public."PartnerReports";
create policy "staff triages reports" on public."PartnerReports"
  for update to authenticated
  using (public.is_staff())
  with check (public.is_staff());
-- no delete policy: reports are an audit trail.
-- note: the reported partner has NO access to rows about themselves.

/* ------------------------------------------------------------------ */
/* PartnerBlocks — a member hides a partner                           */
/* ------------------------------------------------------------------ */

create table if not exists public."PartnerBlocks" (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  member_user_id  uuid not null references auth.users (id) on delete cascade,
  partner_user_id uuid not null references auth.users (id) on delete cascade,
  constraint partnerblocks_unique unique (member_user_id, partner_user_id),
  constraint partnerblocks_not_self check (member_user_id <> partner_user_id)
);

create index if not exists partnerblocks_partner_idx on public."PartnerBlocks" (partner_user_id);

alter table public."PartnerBlocks" enable row level security;

drop policy if exists "member manages own blocks" on public."PartnerBlocks";
create policy "member manages own blocks" on public."PartnerBlocks"
  for all to authenticated
  using (member_user_id = auth.uid())
  with check (member_user_id = auth.uid());

drop policy if exists "staff reads blocks" on public."PartnerBlocks";
create policy "staff reads blocks" on public."PartnerBlocks"
  for select to authenticated
  using (public.is_staff());
-- the blocked partner cannot see who blocked them.

/* ------------------------------------------------------------------ */
/* PartnerFollows — a member follows a partner                        */
/* ------------------------------------------------------------------ */

create table if not exists public."PartnerFollows" (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  member_user_id  uuid not null references auth.users (id) on delete cascade,
  partner_user_id uuid not null references auth.users (id) on delete cascade,
  constraint partnerfollows_unique unique (member_user_id, partner_user_id),
  constraint partnerfollows_not_self check (member_user_id <> partner_user_id)
);

create index if not exists partnerfollows_partner_idx on public."PartnerFollows" (partner_user_id);

alter table public."PartnerFollows" enable row level security;

drop policy if exists "member manages own follows" on public."PartnerFollows";
create policy "member manages own follows" on public."PartnerFollows"
  for all to authenticated
  using (member_user_id = auth.uid())
  with check (member_user_id = auth.uid());

drop policy if exists "partner or staff reads followers" on public."PartnerFollows";
create policy "partner or staff reads followers" on public."PartnerFollows"
  for select to authenticated
  using (partner_user_id = auth.uid() or public.is_staff());

/* ------------------------------------------------------------------ */
/* denormalised follower_count on UserProfiles                        */
/* so the mobile app can show "1,240 followers" without reading rows  */
/* ------------------------------------------------------------------ */

alter table public."UserProfiles"
  add column if not exists follower_count integer not null default 0;

create or replace function public.sync_partner_follower_count()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    update public."UserProfiles"
      set follower_count = follower_count + 1
      where id = new.partner_user_id;
  elsif tg_op = 'DELETE' then
    update public."UserProfiles"
      set follower_count = greatest(follower_count - 1, 0)
      where id = old.partner_user_id;
  end if;
  return null;
end;
$$;

drop trigger if exists sync_partner_follower_count on public."PartnerFollows";
create trigger sync_partner_follower_count
  after insert or delete on public."PartnerFollows"
  for each row execute function public.sync_partner_follower_count();

-- follower_count is only added to the privileged-column guard if UserProfiles
-- RLS lets members read other profiles (see note in the chat) — until then it
-- is unreachable by non-owners anyway.

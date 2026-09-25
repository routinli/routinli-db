-- A partner's own sales, for the Earnings page in routinli-partners.
--
-- Partners have NO direct read access to "ProgramPurchases" (RLS: members read
-- their own rows, staff read all) and shouldn't — a purchase row carries the
-- buyer's user_id. This function is the only door: SECURITY DEFINER, scoped to
-- partner_id = auth.uid(), and it never returns user_id or anything else that
-- identifies a member (privacy decision: partners see aggregates, never people).
--
-- Amounts are integer minor units (cents) in the currency of each sale, so
-- totals are grouped per currency rather than summed across currencies.
-- "earnings" = the partner's transferred share (partner_amount) of completed,
-- not-fully-refunded sales. Partial-refund accounting is a later phase (the
-- purchases table itself says so) — such sales still count, and are flagged.
-- 'already_owned' rows (paid twice, awaiting a staff refund) never count.
--
-- Additive only: a new function, nothing the mobile app touches.

create or replace function public.get_partner_earnings()
returns jsonb
language plpgsql stable security definer set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    return jsonb_build_object('totals', '[]'::jsonb, 'by_program', '[]'::jsonb, 'recent', '[]'::jsonb);
  end if;

  return jsonb_build_object(
    'totals', coalesce((
      select jsonb_agg(to_jsonb(t) order by t.currency)
      from (
        select
          currency,
          count(*) filter (where status = 'completed' and refund_status <> 'full')::int          as sales_count,
          coalesce(sum(amount_subtotal) filter (where status = 'completed' and refund_status <> 'full'), 0)::bigint
                                                                                                  as gross,
          coalesce(sum(partner_amount)  filter (where status = 'completed' and refund_status <> 'full'), 0)::bigint
                                                                                                  as earnings,
          coalesce(sum(partner_amount)  filter (where status = 'completed' and refund_status <> 'full'
                                                  and created_at >= date_trunc('month', now())), 0)::bigint
                                                                                                  as month_earnings,
          count(*) filter (where status = 'completed' and refund_status <> 'none')::int          as refunded_count
        from public."ProgramPurchases"
        where partner_id = v_uid
        group by currency
      ) t
    ), '[]'::jsonb),

    'by_program', coalesce((
      select jsonb_agg(to_jsonb(t) order by t.earnings desc, t.program_title)
      from (
        select
          routine_package_id                                                              as program_id,
          max(program_title)                                                              as program_title,
          currency,
          count(*)::int                                                                   as sales_count,
          coalesce(sum(partner_amount), 0)::bigint                                        as earnings
        from public."ProgramPurchases"
        where partner_id = v_uid
          and status = 'completed'
          and refund_status <> 'full'
        group by routine_package_id, currency
      ) t
    ), '[]'::jsonb),

    'recent', coalesce((
      select jsonb_agg(to_jsonb(t) order by t.created_at desc)
      from (
        select
          created_at,
          program_title,
          currency,
          amount_subtotal                                                                 as price,
          partner_amount                                                                  as earnings,
          refund_status,
          -- informational only: did the buyer arrive through this partner's own link?
          (ref is not null and ref = v_uid::text)                                         as via_your_link
        from public."ProgramPurchases"
        where partner_id = v_uid
          and status = 'completed'
        order by created_at desc
        limit 20
      ) t
    ), '[]'::jsonb)
  );
end;
$$;

revoke all on function public.get_partner_earnings() from public;
grant execute on function public.get_partner_earnings() to authenticated;

-- Programs list for the partner dashboard: the caller's marketplace packages
-- (not their personal routines) with status/category labels and download +
-- rating rollups, in one call.

-- DROP first: Postgres refuses to CREATE OR REPLACE when the return columns change.
drop function if exists public.get_partner_programs();

create or replace function public.get_partner_programs()
returns table (
  id             uuid,
  title          text,
  description    text,
  thumb_url      varchar,
  status_id      smallint,
  status_label   text,
  price          double precision,
  category_id    smallint,
  category_label varchar,
  download_count bigint,
  rating_avg     numeric,
  rating_count   bigint,
  created_at     timestamptz,
  modified_at    timestamptz
)
language sql stable security definer set search_path = public
as $$
  select
    p.id,
    p.title,
    p.description,
    coalesce(p.theme_pic_url, p.theme_cover_pic_url)                       as thumb_url,
    p.status_id,
    s.text                                                                as status_label,
    p.price,
    p.category_id,
    c.text                                                                as category_label,
    (select count(*) from public."MyDownloads" d
       where d.routine_package_id = p.id)                                  as download_count,
    (select round(avg(r.rating)::numeric, 2) from public."RoutinePackageRatings" r
       where r.routine_package_id = p.id)                                  as rating_avg,
    (select count(*) from public."RoutinePackageRatings" r
       where r.routine_package_id = p.id)                                  as rating_count,
    p.created_at,
    p.modified_at
  from public."RoutinePackages" p
  left join public."EnumRoutinePackageStatuses" s on s.id = p.status_id
  left join public."EnumCategories" c              on c.id = p.category_id
  where p.creator_id = auth.uid()
    and coalesce(p.is_personal, false) = false
  order by p.modified_at desc nulls last, p.created_at desc;
$$;

revoke all on function public.get_partner_programs() from public;
grant execute on function public.get_partner_programs() to authenticated;

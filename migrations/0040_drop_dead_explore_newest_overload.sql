-- The 1-argument overload of get_explore_programs_newest — confirmed dead by
-- the user (2026-09-25): FlutterFlow calls the 2-argument overload (p_user_id,
-- p_routine_package_id_to_exclude, fixed in migration 0039), not this one.
-- Dropping it rather than leaving an unfiltered, unfixed duplicate sitting in
-- the database as a future trap.

drop function if exists public.get_explore_programs_newest(uuid);

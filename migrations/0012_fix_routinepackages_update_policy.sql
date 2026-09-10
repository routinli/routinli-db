-- The mobile app's UPDATE policy on RoutinePackages was created with a
-- WITH CHECK but no USING clause. In PostgreSQL an UPDATE policy without a
-- USING expression makes NO existing row updatable, so every partner edit
-- silently writes 0 rows (Supabase reports no error for an RLS-blocked update).
--
-- Recreate it with an explicit USING. The mobile app doesn't edit
-- RoutinePackages (partners are web-only; members edit MyRoutines), so this
-- is safe to replace. The 0009 guard trigger still governs *which* columns a
-- partner may change.

drop policy if exists "Users can edit their Routines" on public."RoutinePackages";

drop policy if exists "Creator can edit their package" on public."RoutinePackages";
create policy "Creator can edit their package" on public."RoutinePackages"
  for update to authenticated
  using (auth.uid() = creator_id)
  with check (auth.uid() = creator_id);

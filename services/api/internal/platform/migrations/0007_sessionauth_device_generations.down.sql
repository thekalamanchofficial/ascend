-- Reverses 0007_sessionauth_device_generations.up.sql. Does not DROP ROLE
-- ascend_app, for the same reason every prior *.down.sql in this series
-- doesn't: that role is owned by migration 0001 and may still be depended
-- on by other tables' grants.
REVOKE ALL ON sessionauth_device_generations FROM ascend_app;

DROP TABLE IF EXISTS sessionauth_device_generations;

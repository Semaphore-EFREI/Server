-- Align admin_role enum with API values (planning, absence, manager).

UPDATE administrators
SET role = CASE role
  WHEN 'super_admin' THEN 'manager'
  WHEN 'school_admin' THEN 'planning'
  ELSE role
END;

CREATE TYPE admin_role_new AS ENUM ('planning', 'absence', 'manager');

ALTER TABLE administrators
  ALTER COLUMN role TYPE admin_role_new
  USING role::text::admin_role_new;

DROP TYPE admin_role;
ALTER TYPE admin_role_new RENAME TO admin_role;

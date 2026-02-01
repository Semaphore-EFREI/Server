-- Restore admin_role enum to legacy values (super_admin, school_admin).

CREATE TYPE admin_role_old AS ENUM ('super_admin', 'school_admin');

ALTER TABLE administrators
  ALTER COLUMN role TYPE admin_role_old
  USING (
    CASE role
      WHEN 'manager' THEN 'super_admin'
      WHEN 'planning' THEN 'school_admin'
      WHEN 'absence' THEN 'school_admin'
      ELSE role::text
    END
  )::admin_role_old;

DROP TYPE admin_role;
ALTER TYPE admin_role_old RENAME TO admin_role;

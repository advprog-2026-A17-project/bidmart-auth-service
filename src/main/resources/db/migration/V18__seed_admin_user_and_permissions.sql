-- Bootstrap: Seed admin permissions and first admin user
-- This migration creates the admin:users and admin:roles permissions and links them to the ADMIN role.
-- It also creates the first bootstrap admin user to enable system management.

-- 1. Insert admin permissions
INSERT INTO permissions (id, name) VALUES
    ('00000000-0000-0000-0000-200000000001', 'admin:users'),
    ('00000000-0000-0000-0000-200000000002', 'admin:roles')
ON CONFLICT (name) DO NOTHING;

-- 2. Link admin permissions to ADMIN role (ID: 00000000-0000-0000-0000-000000000000)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-200000000001'), -- admin:users
    ('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-200000000002')  -- admin:roles
ON CONFLICT DO NOTHING;

-- 3. Insert the bootstrap admin user
-- NOTE: Password is BCrypt hash of "verySafepw.09" with cost factor 10
-- This is the bootstrap password only - MUST be changed after first login!
-- To regenerate: Use https://www.bcryptcalculator.com/ or run:
--   $ spring-shell> password encrypt --algorithm bcrypt --raw-password verySafepw.09
INSERT INTO users (id, email, password, enabled, email_verified) 
VALUES (
    '00000000-0000-0000-0000-300000000001',
    'admin@bidmart.com',
    '$2a$10$E/sFx0WaPM7CXb31LJiAa.LZjOZ2iLsVEuoIV8q3JV6XMPDkE58Jq', -- BCrypt hash for "verySafepw.09"
    true,
    true
)
ON CONFLICT (email) DO NOTHING;

-- 4. Assign ADMIN role to the bootstrap admin user
INSERT INTO user_roles (user_id, role_id)
SELECT '00000000-0000-0000-0000-300000000001', '00000000-0000-0000-0000-000000000000'
WHERE NOT EXISTS (
    SELECT 1 FROM user_roles 
    WHERE user_id = '00000000-0000-0000-0000-300000000001' 
    AND role_id = '00000000-0000-0000-0000-000000000000'
);

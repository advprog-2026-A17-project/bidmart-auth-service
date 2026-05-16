-- Grant sellers permission to manage (update/delete/publish/cancel) their listings.
INSERT INTO permissions (id, name) VALUES
    ('00000000-0000-0000-0000-100000000007', 'listing:manage')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,
    permission.id
FROM permissions permission
WHERE permission.name = 'listing:manage'
ON CONFLICT DO NOTHING;

-- Grant sellers permission to close auctions they create through the gateway flow.
INSERT INTO permissions (id, name) VALUES
    ('00000000-0000-0000-0000-100000000006', 'auction:close')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT
    '00000000-0000-0000-0000-000000000002'::uuid,
    permission.id
FROM permissions permission
WHERE permission.name = 'auction:close'
ON CONFLICT DO NOTHING;

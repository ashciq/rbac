-- ============================================================================
-- RBAC Framework - MySQL Seed Data
-- ============================================================================

USE rbac_db;

-- ── Actions ─────────────────────────────────────────────────────────────────

INSERT INTO actions (id, name) VALUES
    ('a1000000-0000-0000-0000-000000000001', 'read'),
    ('a1000000-0000-0000-0000-000000000002', 'create'),
    ('a1000000-0000-0000-0000-000000000003', 'update'),
    ('a1000000-0000-0000-0000-000000000004', 'delete'),
    ('a1000000-0000-0000-0000-000000000005', 'upload'),
    ('a1000000-0000-0000-0000-000000000006', 'manage');

-- ── Resources ───────────────────────────────────────────────────────────────

INSERT INTO resources (id, name, description) VALUES
    ('b1000000-0000-0000-0000-000000000001', 'dashboard',  'Analytics dashboard'),
    ('b1000000-0000-0000-0000-000000000002', 'reports',    'Business reports'),
    ('b1000000-0000-0000-0000-000000000003', 'projects',   'Project workspaces'),
    ('b1000000-0000-0000-0000-000000000004', 'users',      'User accounts'),
    ('b1000000-0000-0000-0000-000000000005', 'settings',   'System settings'),
    ('b1000000-0000-0000-0000-000000000006', 'files',      'File storage'),
    ('b1000000-0000-0000-0000-000000000007', 'audit_logs', 'Audit trail');

-- ── Resource Actions ────────────────────────────────────────────────────────

INSERT INTO resource_actions (resource_id, action_id)
SELECT r.id, a.id FROM resources r, actions a
WHERE (r.name, a.name) IN (
    ('dashboard', 'read'), ('dashboard', 'manage'),
    ('reports', 'read'), ('reports', 'create'), ('reports', 'update'), ('reports', 'delete'), ('reports', 'upload'),
    ('projects', 'read'), ('projects', 'create'), ('projects', 'update'), ('projects', 'delete'),
    ('users', 'read'), ('users', 'create'), ('users', 'update'), ('users', 'delete'), ('users', 'manage'),
    ('settings', 'read'), ('settings', 'update'), ('settings', 'manage'),
    ('files', 'read'), ('files', 'create'), ('files', 'delete'), ('files', 'upload'),
    ('audit_logs', 'read'), ('audit_logs', 'delete')
);

-- ── Roles ───────────────────────────────────────────────────────────────────

INSERT INTO roles (id, name, description) VALUES
    ('c1000000-0000-0000-0000-000000000001', 'viewer',       'Read-only access to non-sensitive resources'),
    ('c1000000-0000-0000-0000-000000000002', 'contributor',  'Can create and edit content'),
    ('c1000000-0000-0000-0000-000000000003', 'editor',       'Full content management including deletion'),
    ('c1000000-0000-0000-0000-000000000004', 'user_manager', 'Can manage user accounts'),
    ('c1000000-0000-0000-0000-000000000005', 'team_lead',    'Editor + user read access + dashboard management'),
    ('c1000000-0000-0000-0000-000000000006', 'admin',        'Full system access'),
    ('c1000000-0000-0000-0000-000000000007', 'auditor',      'Read-only access to everything including audit logs');

-- ── Role Inheritance ────────────────────────────────────────────────────────

INSERT INTO role_inheritance (child_role_id, parent_role_id)
SELECT c.id, p.id FROM roles c, roles p
WHERE (c.name, p.name) IN (
    ('contributor', 'viewer'),
    ('editor', 'contributor'),
    ('team_lead', 'editor'),
    ('team_lead', 'user_manager'),
    ('admin', 'team_lead'),
    ('auditor', 'viewer')
);

-- ── Permissions ─────────────────────────────────────────────────────────────

INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE (ro.name, re.name, a.name) IN (
    -- viewer
    ('viewer', 'dashboard', 'read'), ('viewer', 'reports', 'read'),
    ('viewer', 'projects', 'read'), ('viewer', 'files', 'read'),
    -- contributor
    ('contributor', 'reports', 'create'), ('contributor', 'reports', 'update'),
    ('contributor', 'projects', 'create'), ('contributor', 'projects', 'update'),
    ('contributor', 'files', 'create'), ('contributor', 'files', 'upload'),
    -- editor
    ('editor', 'reports', 'delete'), ('editor', 'reports', 'upload'),
    ('editor', 'projects', 'delete'), ('editor', 'files', 'delete'),
    -- user_manager
    ('user_manager', 'users', 'read'), ('user_manager', 'users', 'create'), ('user_manager', 'users', 'update'),
    -- team_lead
    ('team_lead', 'dashboard', 'manage'), ('team_lead', 'audit_logs', 'read'),
    -- admin
    ('admin', 'users', 'delete'), ('admin', 'users', 'manage'),
    ('admin', 'settings', 'read'), ('admin', 'settings', 'update'), ('admin', 'settings', 'manage'),
    ('admin', 'audit_logs', 'delete'), ('admin', 'files', 'upload'),
    -- auditor
    ('auditor', 'users', 'read'), ('auditor', 'settings', 'read'), ('auditor', 'audit_logs', 'read')
);

-- ── Permission Dependencies ─────────────────────────────────────────────────

INSERT INTO permission_dependencies (permission_action_id, permission_resource_id, requires_action_id, requires_resource_id)
SELECT a1.id, r1.id, a2.id, r2.id
FROM actions a1, resources r1, actions a2, resources r2
WHERE (a1.name, r1.name, a2.name, r2.name) IN (
    ('delete', 'reports', 'read', 'reports'),
    ('update', 'reports', 'read', 'reports'),
    ('upload', 'reports', 'read', 'reports'),
    ('upload', 'reports', 'create', 'reports'),
    ('manage', 'dashboard', 'read', 'dashboard'),
    ('delete', 'projects', 'read', 'projects'),
    ('delete', 'projects', 'update', 'projects'),
    ('manage', 'users', 'read', 'users'),
    ('manage', 'users', 'create', 'users'),
    ('manage', 'users', 'update', 'users'),
    ('manage', 'settings', 'read', 'settings'),
    ('manage', 'settings', 'update', 'settings'),
    ('delete', 'files', 'read', 'files'),
    ('upload', 'files', 'read', 'files'),
    ('upload', 'files', 'create', 'files'),
    ('delete', 'audit_logs', 'read', 'audit_logs')
);

-- ── Users ───────────────────────────────────────────────────────────────────

INSERT INTO users (id, username, display_name, email) VALUES
    ('d1000000-0000-0000-0000-000000000001', 'alice', 'Alice Johnson', 'alice@example.com');

INSERT INTO users (id, username, display_name, email, reports_to) VALUES
    ('d1000000-0000-0000-0000-000000000002', 'bob',   'Bob Smith',      'bob@example.com',   'd1000000-0000-0000-0000-000000000001'),
    ('d1000000-0000-0000-0000-000000000003', 'frank', 'Frank Miller',   'frank@example.com', 'd1000000-0000-0000-0000-000000000001');

INSERT INTO users (id, username, display_name, email, reports_to) VALUES
    ('d1000000-0000-0000-0000-000000000004', 'carol', 'Carol Williams', 'carol@example.com', 'd1000000-0000-0000-0000-000000000002'),
    ('d1000000-0000-0000-0000-000000000005', 'dave',  'Dave Brown',     'dave@example.com',  'd1000000-0000-0000-0000-000000000002'),
    ('d1000000-0000-0000-0000-000000000006', 'grace', 'Grace Wilson',   'grace@example.com', 'd1000000-0000-0000-0000-000000000002');

INSERT INTO users (id, username, display_name, email, reports_to) VALUES
    ('d1000000-0000-0000-0000-000000000007', 'eve',   'Eve Davis',      'eve@example.com',   'd1000000-0000-0000-0000-000000000004');

-- ── User Roles ──────────────────────────────────────────────────────────────

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE (u.username, r.name) IN (
    ('alice', 'admin'),
    ('bob',   'team_lead'),
    ('carol', 'editor'),
    ('dave',  'contributor'),
    ('eve',   'viewer'),
    ('frank', 'auditor'),
    ('grace', 'contributor'),
    ('grace', 'user_manager')
);

-- ── User Grants & Exclusions ────────────────────────────────────────────────

INSERT INTO user_grants (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Investigation access'
FROM users u, resources re, actions a
WHERE u.username = 'carol' AND re.name = 'audit_logs' AND a.name = 'read';

INSERT INTO user_grants (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Settings visibility'
FROM users u, resources re, actions a
WHERE u.username = 'grace' AND re.name = 'settings' AND a.name = 'read';

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Team lead cannot delete users'
FROM users u, resources re, actions a
WHERE u.username = 'bob' AND re.name = 'users' AND a.name = 'delete';

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Report deletion blocked'
FROM users u, resources re, actions a
WHERE u.username = 'dave' AND re.name = 'reports' AND a.name = 'delete';

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'File upload blocked'
FROM users u, resources re, actions a
WHERE u.username = 'grace' AND re.name = 'files' AND a.name = 'upload';

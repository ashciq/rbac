-- ============================================================================
-- RBAC Framework - PostgreSQL Seed Data
-- Matches rbac_model.json v2.0
-- ============================================================================

BEGIN;

-- ── Actions ─────────────────────────────────────────────────────────────────

INSERT INTO actions (name) VALUES
    ('read'), ('create'), ('update'), ('delete'), ('upload'), ('manage');

-- ── Resources ───────────────────────────────────────────────────────────────

INSERT INTO resources (name, description) VALUES
    ('dashboard',  'Analytics dashboard'),
    ('reports',    'Business reports'),
    ('projects',   'Project workspaces'),
    ('users',      'User accounts'),
    ('settings',   'System settings'),
    ('files',      'File storage'),
    ('audit_logs', 'Audit trail');

-- ── Resource Actions (which actions are valid per resource) ──────────────────

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

INSERT INTO roles (name, description) VALUES
    ('viewer',       'Read-only access to non-sensitive resources'),
    ('contributor',  'Can create and edit content'),
    ('editor',       'Full content management including deletion'),
    ('user_manager', 'Can manage user accounts'),
    ('team_lead',    'Editor + user read access + dashboard management'),
    ('admin',        'Full system access'),
    ('auditor',      'Read-only access to everything including audit logs');

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

-- ── Permissions (direct role permissions) ───────────────────────────────────

-- viewer
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'viewer' AND (re.name, a.name) IN (
    ('dashboard', 'read'), ('reports', 'read'), ('projects', 'read'), ('files', 'read')
);

-- contributor
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'contributor' AND (re.name, a.name) IN (
    ('reports', 'create'), ('reports', 'update'),
    ('projects', 'create'), ('projects', 'update'),
    ('files', 'create'), ('files', 'upload')
);

-- editor
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'editor' AND (re.name, a.name) IN (
    ('reports', 'delete'), ('reports', 'upload'),
    ('projects', 'delete'),
    ('files', 'delete')
);

-- user_manager
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'user_manager' AND (re.name, a.name) IN (
    ('users', 'read'), ('users', 'create'), ('users', 'update')
);

-- team_lead
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'team_lead' AND (re.name, a.name) IN (
    ('dashboard', 'manage'), ('audit_logs', 'read')
);

-- admin
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'admin' AND (re.name, a.name) IN (
    ('users', 'delete'), ('users', 'manage'),
    ('settings', 'read'), ('settings', 'update'), ('settings', 'manage'),
    ('audit_logs', 'delete'),
    ('files', 'upload')
);

-- auditor
INSERT INTO permissions (role_id, resource_id, action_id)
SELECT ro.id, re.id, a.id FROM roles ro, resources re, actions a
WHERE ro.name = 'auditor' AND (re.name, a.name) IN (
    ('users', 'read'), ('settings', 'read'), ('audit_logs', 'read')
);

-- ── Permission Dependencies ─────────────────────────────────────────────────

INSERT INTO permission_dependencies (permission_action_id, permission_resource_id, requires_action_id, requires_resource_id)
SELECT a1.id, r1.id, a2.id, r2.id
FROM actions a1, resources r1, actions a2, resources r2
WHERE (a1.name, r1.name, a2.name, r2.name) IN (
    ('delete',  'reports',    'read',   'reports'),
    ('update',  'reports',    'read',   'reports'),
    ('upload',  'reports',    'read',   'reports'),
    ('upload',  'reports',    'create', 'reports'),
    ('manage',  'dashboard',  'read',   'dashboard'),
    ('delete',  'projects',   'read',   'projects'),
    ('delete',  'projects',   'update', 'projects'),
    ('manage',  'users',      'read',   'users'),
    ('manage',  'users',      'create', 'users'),
    ('manage',  'users',      'update', 'users'),
    ('manage',  'settings',   'read',   'settings'),
    ('manage',  'settings',   'update', 'settings'),
    ('delete',  'files',      'read',   'files'),
    ('upload',  'files',      'read',   'files'),
    ('upload',  'files',      'create', 'files'),
    ('delete',  'audit_logs', 'read',   'audit_logs')
);

-- ── Users ───────────────────────────────────────────────────────────────────

-- Insert root user first (no reports_to)
INSERT INTO users (username, display_name, email) VALUES
    ('alice', 'Alice Johnson', 'alice@example.com');

INSERT INTO users (username, display_name, email, reports_to) VALUES
    ('bob',   'Bob Smith',      'bob@example.com',   (SELECT id FROM users WHERE username = 'alice')),
    ('frank', 'Frank Miller',   'frank@example.com', (SELECT id FROM users WHERE username = 'alice'));

INSERT INTO users (username, display_name, email, reports_to) VALUES
    ('carol', 'Carol Williams', 'carol@example.com', (SELECT id FROM users WHERE username = 'bob')),
    ('dave',  'Dave Brown',     'dave@example.com',  (SELECT id FROM users WHERE username = 'bob')),
    ('grace', 'Grace Wilson',   'grace@example.com', (SELECT id FROM users WHERE username = 'bob'));

INSERT INTO users (username, display_name, email, reports_to) VALUES
    ('eve',   'Eve Davis',      'eve@example.com',   (SELECT id FROM users WHERE username = 'carol'));

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

-- ── User Grants ─────────────────────────────────────────────────────────────

INSERT INTO user_grants (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Investigation access'
FROM users u, resources re, actions a
WHERE u.username = 'carol' AND re.name = 'audit_logs' AND a.name = 'read';

INSERT INTO user_grants (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Settings visibility for configuration tasks'
FROM users u, resources re, actions a
WHERE u.username = 'grace' AND re.name = 'settings' AND a.name = 'read';

-- ── User Exclusions ─────────────────────────────────────────────────────────

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Restricted: team lead should not delete users'
FROM users u, resources re, actions a
WHERE u.username = 'bob' AND re.name = 'users' AND a.name = 'delete';

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Restricted: no report deletion for this user'
FROM users u, resources re, actions a
WHERE u.username = 'dave' AND re.name = 'reports' AND a.name = 'delete';

INSERT INTO user_exclusions (user_id, resource_id, action_id, reason)
SELECT u.id, re.id, a.id, 'Restricted: file upload blocked'
FROM users u, resources re, actions a
WHERE u.username = 'grace' AND re.name = 'files' AND a.name = 'upload';

COMMIT;

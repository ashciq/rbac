-- ============================================================================
-- RBAC Framework - PostgreSQL Schema
-- Version: 2.0
--
-- Tables: resources, actions, resource_actions, roles, role_inheritance,
--         permissions, permission_dependencies, users, user_roles,
--         user_grants, user_exclusions
-- ============================================================================

BEGIN;

-- ── Extensions ──────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Resources ───────────────────────────────────────────────────────────────

CREATE TABLE resources (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE actions (
    id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE
);

-- Which actions are valid for which resource
CREATE TABLE resource_actions (
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    PRIMARY KEY (resource_id, action_id)
);

-- ── Roles ───────────────────────────────────────────────────────────────────

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role inheritance (DAG - a role can inherit from multiple parents)
CREATE TABLE role_inheritance (
    child_role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (child_role_id, parent_role_id),
    CHECK (child_role_id != parent_role_id)
);

-- ── Permissions (Role -> Resource -> Action) ────────────────────────────────

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (role_id, resource_id, action_id)
);

-- Permission dependencies (action:resource requires other action:resource)
CREATE TABLE permission_dependencies (
    permission_action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    permission_resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    requires_action_id     UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    requires_resource_id   UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    PRIMARY KEY (permission_action_id, permission_resource_id, requires_action_id, requires_resource_id)
);

-- ── Users ───────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username     VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    email        VARCHAR(255),
    reports_to   UUID REFERENCES users(id) ON DELETE SET NULL,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_reports_to ON users(reports_to);

-- User role assignments
CREATE TABLE user_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

-- Per-user extra grants (beyond roles)
CREATE TABLE user_grants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    granted_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    reason      TEXT,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, resource_id, action_id)
);

-- Per-user exclusions (admin override - strips permission even if role has it)
CREATE TABLE user_exclusions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    action_id   UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    excluded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason      TEXT,
    excluded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, resource_id, action_id)
);

-- ── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX idx_permissions_role ON permissions(role_id);
CREATE INDEX idx_permissions_resource ON permissions(resource_id);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_grants_user ON user_grants(user_id);
CREATE INDEX idx_user_exclusions_user ON user_exclusions(user_id);

-- ── Updated_at trigger ──────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_resources_updated_at BEFORE UPDATE ON resources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMIT;

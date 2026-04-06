-- ============================================================================
-- RBAC Framework - MySQL Schema
-- Version: 2.0
-- ============================================================================

CREATE DATABASE IF NOT EXISTS rbac_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE rbac_db;

-- ── Resources ───────────────────────────────────────────────────────────────

CREATE TABLE resources (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE actions (
    id   CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name VARCHAR(50) NOT NULL UNIQUE
) ENGINE=InnoDB;

CREATE TABLE resource_actions (
    resource_id CHAR(36) NOT NULL,
    action_id   CHAR(36) NOT NULL,
    PRIMARY KEY (resource_id, action_id),
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── Roles ───────────────────────────────────────────────────────────────────

CREATE TABLE roles (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE role_inheritance (
    child_role_id  CHAR(36) NOT NULL,
    parent_role_id CHAR(36) NOT NULL,
    PRIMARY KEY (child_role_id, parent_role_id),
    FOREIGN KEY (child_role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CHECK (child_role_id != parent_role_id)
) ENGINE=InnoDB;

-- ── Permissions ─────────────────────────────────────────────────────────────

CREATE TABLE permissions (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    role_id     CHAR(36) NOT NULL,
    resource_id CHAR(36) NOT NULL,
    action_id   CHAR(36) NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_permission (role_id, resource_id, action_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE permission_dependencies (
    permission_action_id   CHAR(36) NOT NULL,
    permission_resource_id CHAR(36) NOT NULL,
    requires_action_id     CHAR(36) NOT NULL,
    requires_resource_id   CHAR(36) NOT NULL,
    PRIMARY KEY (permission_action_id, permission_resource_id, requires_action_id, requires_resource_id),
    FOREIGN KEY (permission_action_id) REFERENCES actions(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (requires_action_id) REFERENCES actions(id) ON DELETE CASCADE,
    FOREIGN KEY (requires_resource_id) REFERENCES resources(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ── Users ───────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id           CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username     VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL DEFAULT '',
    email        VARCHAR(255),
    reports_to   CHAR(36),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (reports_to) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_reports_to (reports_to)
) ENGINE=InnoDB;

CREATE TABLE user_roles (
    user_id    CHAR(36) NOT NULL,
    role_id    CHAR(36) NOT NULL,
    granted_by CHAR(36),
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE user_grants (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id     CHAR(36) NOT NULL,
    resource_id CHAR(36) NOT NULL,
    action_id   CHAR(36) NOT NULL,
    granted_by  CHAR(36),
    reason      TEXT,
    granted_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_grant (user_id, resource_id, action_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE user_exclusions (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id     CHAR(36) NOT NULL,
    resource_id CHAR(36) NOT NULL,
    action_id   CHAR(36) NOT NULL,
    excluded_by CHAR(36),
    reason      TEXT,
    excluded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_exclusion (user_id, resource_id, action_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    FOREIGN KEY (excluded_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX idx_permissions_role ON permissions(role_id);
CREATE INDEX idx_permissions_resource ON permissions(resource_id);
CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_grants_user ON user_grants(user_id);
CREATE INDEX idx_user_exclusions_user ON user_exclusions(user_id);

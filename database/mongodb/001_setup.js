// ============================================================================
// RBAC Framework - MongoDB Setup & Seed Data
// Version: 2.0
//
// Run: mongosh < 001_setup.js
// Or:  mongosh rbac_db 001_setup.js
// ============================================================================

use("rbac_db");

// ── Drop existing collections ───────────────────────────────────────────────

db.resources.drop();
db.roles.drop();
db.users.drop();
db.permission_dependencies.drop();

// ── Resources ───────────────────────────────────────────────────────────────

db.resources.insertMany([
  { _id: "dashboard",  description: "Analytics dashboard",  allowed_actions: ["read", "manage"] },
  { _id: "reports",    description: "Business reports",     allowed_actions: ["read", "create", "update", "delete", "upload"] },
  { _id: "projects",   description: "Project workspaces",   allowed_actions: ["read", "create", "update", "delete"] },
  { _id: "users",      description: "User accounts",        allowed_actions: ["read", "create", "update", "delete", "manage"] },
  { _id: "settings",   description: "System settings",      allowed_actions: ["read", "update", "manage"] },
  { _id: "files",      description: "File storage",         allowed_actions: ["read", "create", "delete", "upload"] },
  { _id: "audit_logs", description: "Audit trail",          allowed_actions: ["read", "delete"] }
]);

// ── Permission Dependencies ─────────────────────────────────────────────────

db.permission_dependencies.insertMany([
  { _id: "delete:reports",    requires: ["read:reports"] },
  { _id: "update:reports",    requires: ["read:reports"] },
  { _id: "upload:reports",    requires: ["read:reports", "create:reports"] },
  { _id: "manage:dashboard",  requires: ["read:dashboard"] },
  { _id: "delete:projects",   requires: ["read:projects", "update:projects"] },
  { _id: "manage:users",      requires: ["read:users", "create:users", "update:users"] },
  { _id: "manage:settings",   requires: ["read:settings", "update:settings"] },
  { _id: "delete:files",      requires: ["read:files"] },
  { _id: "upload:files",      requires: ["read:files", "create:files"] },
  { _id: "delete:audit_logs", requires: ["read:audit_logs"] }
]);

// ── Roles ───────────────────────────────────────────────────────────────────

db.roles.insertMany([
  {
    _id: "viewer",
    description: "Read-only access to non-sensitive resources",
    inherits: [],
    permissions: {
      dashboard: ["read"],
      reports:   ["read"],
      projects:  ["read"],
      files:     ["read"]
    }
  },
  {
    _id: "contributor",
    description: "Can create and edit content",
    inherits: ["viewer"],
    permissions: {
      reports:  ["create", "update"],
      projects: ["create", "update"],
      files:    ["create", "upload"]
    }
  },
  {
    _id: "editor",
    description: "Full content management including deletion",
    inherits: ["contributor"],
    permissions: {
      reports:  ["delete", "upload"],
      projects: ["delete"],
      files:    ["delete"]
    }
  },
  {
    _id: "user_manager",
    description: "Can manage user accounts",
    inherits: [],
    permissions: {
      users: ["read", "create", "update"]
    }
  },
  {
    _id: "team_lead",
    description: "Editor + user read access + dashboard management",
    inherits: ["editor", "user_manager"],
    permissions: {
      dashboard:  ["manage"],
      audit_logs: ["read"]
    }
  },
  {
    _id: "admin",
    description: "Full system access",
    inherits: ["team_lead"],
    permissions: {
      users:      ["delete", "manage"],
      settings:   ["read", "update", "manage"],
      audit_logs: ["delete"],
      files:      ["upload"]
    }
  },
  {
    _id: "auditor",
    description: "Read-only access to everything including audit logs",
    inherits: ["viewer"],
    permissions: {
      users:      ["read"],
      settings:   ["read"],
      audit_logs: ["read"]
    }
  }
]);

// ── Users ───────────────────────────────────────────────────────────────────

db.users.insertMany([
  {
    _id: "alice",
    display_name: "Alice Johnson",
    email: "alice@example.com",
    roles: ["admin"],
    grants: {},
    exclusions: {},
    reports_to: null,
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "bob",
    display_name: "Bob Smith",
    email: "bob@example.com",
    roles: ["team_lead"],
    grants: {},
    exclusions: { users: ["delete"] },
    reports_to: "alice",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "carol",
    display_name: "Carol Williams",
    email: "carol@example.com",
    roles: ["editor"],
    grants: { audit_logs: ["read"] },
    exclusions: {},
    reports_to: "bob",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "dave",
    display_name: "Dave Brown",
    email: "dave@example.com",
    roles: ["contributor"],
    grants: {},
    exclusions: { reports: ["delete"] },
    reports_to: "bob",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "eve",
    display_name: "Eve Davis",
    email: "eve@example.com",
    roles: ["viewer"],
    grants: {},
    exclusions: {},
    reports_to: "carol",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "frank",
    display_name: "Frank Miller",
    email: "frank@example.com",
    roles: ["auditor"],
    grants: {},
    exclusions: {},
    reports_to: "alice",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    _id: "grace",
    display_name: "Grace Wilson",
    email: "grace@example.com",
    roles: ["contributor", "user_manager"],
    grants: { settings: ["read"] },
    exclusions: { files: ["upload"] },
    reports_to: "bob",
    is_active: true,
    created_at: new Date(),
    updated_at: new Date()
  }
]);

// ── Indexes ─────────────────────────────────────────────────────────────────

db.users.createIndex({ reports_to: 1 });
db.users.createIndex({ roles: 1 });
db.users.createIndex({ is_active: 1 });
db.roles.createIndex({ inherits: 1 });

print("RBAC MongoDB setup complete!");
print(`Resources: ${db.resources.countDocuments()}`);
print(`Roles: ${db.roles.countDocuments()}`);
print(`Users: ${db.users.countDocuments()}`);
print(`Permission Dependencies: ${db.permission_dependencies.countDocuments()}`);

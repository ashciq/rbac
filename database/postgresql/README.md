# PostgreSQL RBAC Setup

## Quick Start

```bash
# Create database
createdb rbac

# Run schema
psql rbac < 001_schema.sql

# Load seed data
psql rbac < 002_seed.sql

# Load helper functions & views
psql rbac < 003_queries.sql
```

## Usage

```sql
-- Check permission
SELECT can_user('bob', 'delete', 'users');        -- FALSE (excluded)
SELECT can_user('alice', 'manage', 'users');       -- TRUE
SELECT can_user('carol', 'read', 'audit_logs');    -- TRUE (granted)

-- Get all effective permissions
SELECT * FROM get_effective_permissions('bob');

-- Export UI manifest (JSON)
SELECT export_ui_manifest('bob');

-- Org hierarchy
SELECT * FROM get_subordinates('alice');
SELECT * FROM get_management_chain('eve');

-- Audit view
SELECT * FROM v_user_permission_audit WHERE username = 'bob';
```

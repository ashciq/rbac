-- ============================================================================
-- RBAC Framework - PostgreSQL Helper Queries & Functions
-- ============================================================================

-- ── 1. CHECK PERMISSION (core query) ────────────────────────────────────────
-- can(user, action, resource) -> boolean
-- Implements: exclusion > grant > role > deny

CREATE OR REPLACE FUNCTION can_user(
    p_username VARCHAR,
    p_action   VARCHAR,
    p_resource VARCHAR
) RETURNS BOOLEAN AS $$
DECLARE
    v_user_id     UUID;
    v_action_id   UUID;
    v_resource_id UUID;
    v_excluded    BOOLEAN;
    v_granted     BOOLEAN;
    v_has_role    BOOLEAN;
BEGIN
    SELECT id INTO v_user_id FROM users WHERE username = p_username AND is_active = TRUE;
    SELECT id INTO v_action_id FROM actions WHERE name = p_action;
    SELECT id INTO v_resource_id FROM resources WHERE name = p_resource;

    IF v_user_id IS NULL OR v_action_id IS NULL OR v_resource_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- 1. Check exclusions (always wins)
    SELECT EXISTS(
        SELECT 1 FROM user_exclusions
        WHERE user_id = v_user_id AND resource_id = v_resource_id AND action_id = v_action_id
    ) INTO v_excluded;
    IF v_excluded THEN RETURN FALSE; END IF;

    -- 2. Check grants
    SELECT EXISTS(
        SELECT 1 FROM user_grants
        WHERE user_id = v_user_id AND resource_id = v_resource_id AND action_id = v_action_id
    ) INTO v_granted;
    IF v_granted THEN RETURN TRUE; END IF;

    -- 3. Check role permissions (including inheritance via recursive CTE)
    SELECT EXISTS(
        WITH RECURSIVE role_tree AS (
            -- Direct roles assigned to user
            SELECT r.id AS role_id
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = v_user_id

            UNION

            -- Inherited roles (walk up the inheritance tree)
            SELECT ri.parent_role_id
            FROM role_inheritance ri
            JOIN role_tree rt ON rt.role_id = ri.child_role_id
        )
        SELECT 1 FROM permissions p
        JOIN role_tree rt ON rt.role_id = p.role_id
        WHERE p.resource_id = v_resource_id AND p.action_id = v_action_id
    ) INTO v_has_role;

    RETURN v_has_role;
END;
$$ LANGUAGE plpgsql STABLE;

-- Usage: SELECT can_user('bob', 'delete', 'users');  -- FALSE (excluded)
-- Usage: SELECT can_user('alice', 'manage', 'users'); -- TRUE


-- ── 2. GET EFFECTIVE PERMISSIONS FOR USER ───────────────────────────────────

CREATE OR REPLACE FUNCTION get_effective_permissions(p_username VARCHAR)
RETURNS TABLE (resource_name VARCHAR, action_name VARCHAR, source VARCHAR) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE role_tree AS (
        SELECT r.id AS role_id, r.name AS role_name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        JOIN users u ON u.id = ur.user_id
        WHERE u.username = p_username

        UNION

        SELECT ri.parent_role_id, r.name
        FROM role_inheritance ri
        JOIN role_tree rt ON rt.role_id = ri.child_role_id
        JOIN roles r ON r.id = ri.parent_role_id
    ),
    role_perms AS (
        SELECT DISTINCT
            re.name AS resource_name,
            a.name AS action_name,
            ('role:' || rt.role_name)::VARCHAR AS source
        FROM permissions p
        JOIN role_tree rt ON rt.role_id = p.role_id
        JOIN resources re ON re.id = p.resource_id
        JOIN actions a ON a.id = p.action_id
    ),
    grant_perms AS (
        SELECT
            re.name AS resource_name,
            a.name AS action_name,
            'grant'::VARCHAR AS source
        FROM user_grants ug
        JOIN users u ON u.id = ug.user_id
        JOIN resources re ON re.id = ug.resource_id
        JOIN actions a ON a.id = ug.action_id
        WHERE u.username = p_username
    ),
    excluded AS (
        SELECT
            re.name AS resource_name,
            a.name AS action_name
        FROM user_exclusions ue
        JOIN users u ON u.id = ue.user_id
        JOIN resources re ON re.id = ue.resource_id
        JOIN actions a ON a.id = ue.action_id
        WHERE u.username = p_username
    ),
    all_perms AS (
        SELECT * FROM role_perms
        UNION
        SELECT * FROM grant_perms
    )
    SELECT ap.resource_name, ap.action_name, ap.source
    FROM all_perms ap
    WHERE NOT EXISTS (
        SELECT 1 FROM excluded e
        WHERE e.resource_name = ap.resource_name AND e.action_name = ap.action_name
    )
    ORDER BY ap.resource_name, ap.action_name;
END;
$$ LANGUAGE plpgsql STABLE;

-- Usage: SELECT * FROM get_effective_permissions('bob');


-- ── 3. GET SUBORDINATES (recursive) ─────────────────────────────────────────

CREATE OR REPLACE FUNCTION get_subordinates(
    p_username VARCHAR,
    p_recursive BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (username VARCHAR, display_name VARCHAR, depth INT) AS $$
BEGIN
    IF p_recursive THEN
        RETURN QUERY
        WITH RECURSIVE org_tree AS (
            SELECT u.id, u.username, u.display_name, 1 AS depth
            FROM users u
            WHERE u.reports_to = (SELECT id FROM users WHERE username = p_username)

            UNION ALL

            SELECT u.id, u.username, u.display_name, ot.depth + 1
            FROM users u
            JOIN org_tree ot ON u.reports_to = ot.id
        )
        SELECT ot.username, ot.display_name, ot.depth
        FROM org_tree ot
        ORDER BY ot.depth, ot.username;
    ELSE
        RETURN QUERY
        SELECT u.username, u.display_name, 1 AS depth
        FROM users u
        WHERE u.reports_to = (SELECT id FROM users WHERE username = p_username)
        ORDER BY u.username;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- Usage: SELECT * FROM get_subordinates('alice');
-- Usage: SELECT * FROM get_subordinates('bob', FALSE);


-- ── 4. GET MANAGEMENT CHAIN ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION get_management_chain(p_username VARCHAR)
RETURNS TABLE (username VARCHAR, display_name VARCHAR, depth INT) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE chain AS (
        SELECT u.id, u.username, u.display_name, u.reports_to, 1 AS depth
        FROM users u
        WHERE u.id = (SELECT reports_to FROM users WHERE username = p_username)

        UNION ALL

        SELECT u.id, u.username, u.display_name, u.reports_to, c.depth + 1
        FROM users u
        JOIN chain c ON u.id = c.reports_to
    )
    SELECT c.username, c.display_name, c.depth
    FROM chain c
    ORDER BY c.depth;
END;
$$ LANGUAGE plpgsql STABLE;

-- Usage: SELECT * FROM get_management_chain('eve');


-- ── 5. EXPORT UI MANIFEST (JSON) ───────────────────────────────────────────

CREATE OR REPLACE FUNCTION export_ui_manifest(p_username VARCHAR)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
BEGIN
    WITH effective AS (
        SELECT resource_name, action_name
        FROM get_effective_permissions(p_username)
    ),
    user_info AS (
        SELECT u.username, u.display_name,
               array_agg(r.name ORDER BY r.name) AS roles
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
        WHERE u.username = p_username
        GROUP BY u.username, u.display_name
    ),
    resource_perms AS (
        SELECT
            re.name AS resource_name,
            jsonb_object_agg(
                a.name,
                CASE WHEN e.action_name IS NOT NULL THEN true ELSE false END
                ORDER BY a.name
            ) AS action_map
        FROM resources re
        JOIN resource_actions ra ON ra.resource_id = re.id
        JOIN actions a ON a.id = ra.action_id
        LEFT JOIN effective e ON e.resource_name = re.name AND e.action_name = a.name
        GROUP BY re.name
    )
    SELECT jsonb_build_object(
        'user', ui.username,
        'display_name', ui.display_name,
        'roles', to_jsonb(ui.roles),
        'permissions', jsonb_object_agg(rp.resource_name, rp.action_map ORDER BY rp.resource_name)
    )
    INTO v_result
    FROM user_info ui, resource_perms rp
    GROUP BY ui.username, ui.display_name, ui.roles;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;

-- Usage: SELECT export_ui_manifest('bob');


-- ── 6. PERMISSION AUDIT VIEW ────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_user_permission_audit AS
WITH RECURSIVE role_tree AS (
    SELECT ur.user_id, r.id AS role_id, r.name AS role_name, 0 AS depth
    FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id

    UNION ALL

    SELECT rt.user_id, ri.parent_role_id, r.name, rt.depth + 1
    FROM role_inheritance ri
    JOIN role_tree rt ON rt.role_id = ri.child_role_id
    JOIN roles r ON r.id = ri.parent_role_id
)
SELECT
    u.username,
    u.display_name,
    re.name AS resource,
    a.name AS action,
    CASE
        WHEN ue.id IS NOT NULL THEN 'EXCLUDED'
        WHEN ug.id IS NOT NULL THEN 'GRANTED'
        WHEN p.id IS NOT NULL THEN 'ROLE:' || rt.role_name
        ELSE 'DENIED'
    END AS source,
    CASE
        WHEN ue.id IS NOT NULL THEN FALSE
        WHEN ug.id IS NOT NULL THEN TRUE
        WHEN p.id IS NOT NULL THEN TRUE
        ELSE FALSE
    END AS allowed
FROM users u
CROSS JOIN resources re
CROSS JOIN resource_actions ra ON ra.resource_id = re.id
JOIN actions a ON a.id = ra.action_id
LEFT JOIN role_tree rt ON rt.user_id = u.id
LEFT JOIN permissions p ON p.role_id = rt.role_id AND p.resource_id = re.id AND p.action_id = a.id
LEFT JOIN user_grants ug ON ug.user_id = u.id AND ug.resource_id = re.id AND ug.action_id = a.id
LEFT JOIN user_exclusions ue ON ue.user_id = u.id AND ue.resource_id = re.id AND ue.action_id = a.id
WHERE u.is_active = TRUE
ORDER BY u.username, re.name, a.name;

-- Usage: SELECT * FROM v_user_permission_audit WHERE username = 'bob';

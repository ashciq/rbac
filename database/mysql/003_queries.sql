-- ============================================================================
-- RBAC Framework - MySQL Helper Queries
-- Note: MySQL uses WITH RECURSIVE (8.0+) for hierarchical queries
-- ============================================================================

USE rbac_db;

-- ── 1. CHECK PERMISSION ─────────────────────────────────────────────────────

DELIMITER //

CREATE FUNCTION can_user(
    p_username VARCHAR(100),
    p_action   VARCHAR(50),
    p_resource VARCHAR(100)
) RETURNS BOOLEAN
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE v_user_id CHAR(36);
    DECLARE v_action_id CHAR(36);
    DECLARE v_resource_id CHAR(36);
    DECLARE v_excluded INT;
    DECLARE v_granted INT;
    DECLARE v_has_role INT;

    SELECT id INTO v_user_id FROM users WHERE username = p_username AND is_active = TRUE;
    SELECT id INTO v_action_id FROM actions WHERE name = p_action;
    SELECT id INTO v_resource_id FROM resources WHERE name = p_resource;

    IF v_user_id IS NULL OR v_action_id IS NULL OR v_resource_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- 1. Exclusions
    SELECT COUNT(*) INTO v_excluded FROM user_exclusions
    WHERE user_id = v_user_id AND resource_id = v_resource_id AND action_id = v_action_id;
    IF v_excluded > 0 THEN RETURN FALSE; END IF;

    -- 2. Grants
    SELECT COUNT(*) INTO v_granted FROM user_grants
    WHERE user_id = v_user_id AND resource_id = v_resource_id AND action_id = v_action_id;
    IF v_granted > 0 THEN RETURN TRUE; END IF;

    -- 3. Role-based (with inheritance)
    SELECT COUNT(*) INTO v_has_role FROM (
        WITH RECURSIVE role_tree AS (
            SELECT r.id AS role_id
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = v_user_id

            UNION ALL

            SELECT ri.parent_role_id
            FROM role_inheritance ri
            JOIN role_tree rt ON rt.role_id = ri.child_role_id
        )
        SELECT 1 FROM permissions p
        JOIN role_tree rt ON rt.role_id = p.role_id
        WHERE p.resource_id = v_resource_id AND p.action_id = v_action_id
        LIMIT 1
    ) t;

    RETURN v_has_role > 0;
END //

DELIMITER ;

-- Usage: SELECT can_user('bob', 'delete', 'users');
-- Usage: SELECT can_user('alice', 'manage', 'users');


-- ── 2. GET EFFECTIVE PERMISSIONS ─────────────────────────────────────────────

DELIMITER //

CREATE PROCEDURE get_effective_permissions(IN p_username VARCHAR(100))
BEGIN
    WITH RECURSIVE role_tree AS (
        SELECT r.id AS role_id, r.name AS role_name
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        JOIN users u ON u.id = ur.user_id
        WHERE u.username = p_username

        UNION ALL

        SELECT ri.parent_role_id, r.name
        FROM role_inheritance ri
        JOIN role_tree rt ON rt.role_id = ri.child_role_id
        JOIN roles r ON r.id = ri.parent_role_id
    ),
    role_perms AS (
        SELECT DISTINCT
            re.name AS resource_name,
            a.name AS action_name,
            CONCAT('role:', rt.role_name) AS source
        FROM permissions p
        JOIN role_tree rt ON rt.role_id = p.role_id
        JOIN resources re ON re.id = p.resource_id
        JOIN actions a ON a.id = p.action_id
    ),
    grant_perms AS (
        SELECT
            re.name AS resource_name,
            a.name AS action_name,
            'grant' AS source
        FROM user_grants ug
        JOIN users u ON u.id = ug.user_id
        JOIN resources re ON re.id = ug.resource_id
        JOIN actions a ON a.id = ug.action_id
        WHERE u.username = p_username
    ),
    excluded AS (
        SELECT re.name AS resource_name, a.name AS action_name
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
END //

DELIMITER ;

-- Usage: CALL get_effective_permissions('bob');


-- ── 3. GET SUBORDINATES ─────────────────────────────────────────────────────

DELIMITER //

CREATE PROCEDURE get_subordinates(IN p_username VARCHAR(100), IN p_recursive BOOLEAN)
BEGIN
    IF p_recursive THEN
        WITH RECURSIVE org_tree AS (
            SELECT u.id, u.username, u.display_name, 1 AS depth
            FROM users u
            WHERE u.reports_to = (SELECT id FROM users WHERE username = p_username)

            UNION ALL

            SELECT u.id, u.username, u.display_name, ot.depth + 1
            FROM users u
            JOIN org_tree ot ON u.reports_to = ot.id
        )
        SELECT username, display_name, depth FROM org_tree ORDER BY depth, username;
    ELSE
        SELECT u.username, u.display_name, 1 AS depth
        FROM users u
        WHERE u.reports_to = (SELECT id FROM users WHERE username = p_username)
        ORDER BY u.username;
    END IF;
END //

DELIMITER ;

-- Usage: CALL get_subordinates('alice', TRUE);


-- ── 4. GET MANAGEMENT CHAIN ─────────────────────────────────────────────────

DELIMITER //

CREATE PROCEDURE get_management_chain(IN p_username VARCHAR(100))
BEGIN
    WITH RECURSIVE chain AS (
        SELECT u.id, u.username, u.display_name, u.reports_to, 1 AS depth
        FROM users u
        WHERE u.id = (SELECT reports_to FROM users WHERE username = p_username)

        UNION ALL

        SELECT u.id, u.username, u.display_name, u.reports_to, c.depth + 1
        FROM users u
        JOIN chain c ON u.id = c.reports_to
    )
    SELECT username, display_name, depth FROM chain ORDER BY depth;
END //

DELIMITER ;

-- Usage: CALL get_management_chain('eve');

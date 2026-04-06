import json
from pathlib import Path

from .exceptions import (
    CyclicDependencyError,
    UnknownPermissionError,
    UnknownRoleError,
)
from .models import Resource, Role, User, ProjectAssignment


class RBACEngine:
    """
    Enterprise RBAC engine for ConstructivIQ.
    Supports:
    - Subscription-level + project-level scoped permissions
    - Resource-action matrix with 11 actions
    - Permission dependencies with transitive resolution
    - Role inheritance + composition (DAG with cycle detection)
    - Per-user per-project grants and exclusions
    - Org hierarchy
    - UI-exportable permission manifests
    """

    def __init__(self, config_path: str | Path | None = None, config: dict | None = None):
        if config:
            self._config = config
        else:
            self._config = self._load_config(config_path)
        self._actions: list[str] = self._config["actions"]
        self._resources: dict[str, Resource] = {}
        self._perm_deps: dict[str, list[str]] = {}
        self._roles: dict[str, Role] = {}
        self._users: dict[str, User] = {}

        self._build_resources()
        self._build_perm_deps()
        self._build_roles()
        self._resolve_all_roles()
        self._build_users()

    # ── Loading ──────────────────────────────────────────────────────

    def _load_config(self, path: str | Path) -> dict:
        with open(Path(path)) as f:
            return json.load(f)

    def _build_resources(self):
        for name, info in self._config["resources"].items():
            self._resources[name] = Resource(
                name=name,
                description=info.get("description", ""),
                scope=info.get("scope", "project"),
                allowed_actions=info["allowed_actions"],
            )

    def _build_perm_deps(self):
        for perm_key, deps in self._config.get("permission_dependencies", {}).items():
            self._perm_deps[perm_key] = deps

    def _build_roles(self):
        raw_roles = self._config["roles"]
        for name, info in raw_roles.items():
            direct = {}
            for resource, actions in info.get("permissions", {}).items():
                direct[resource] = set(actions)
            self._roles[name] = Role(
                name=name,
                description=info.get("description", ""),
                scope=info.get("scope", "project"),
                user_type=info.get("user_type", ""),
                managed_by=info.get("managed_by", ""),
                inherits=info.get("inherits", []),
                direct_permissions=direct,
            )

    def _build_users(self):
        for uid, info in self._config.get("users", {}).items():
            # Project assignments
            assignments = {}
            for proj_id, proj_info in info.get("project_assignments", {}).items():
                assignments[proj_id] = ProjectAssignment(
                    project_id=proj_id,
                    role=proj_info["role"],
                )

            # Per-project grants
            grants = {}
            for proj_id, resources in info.get("grants", {}).items():
                grants[proj_id] = {r: set(a) for r, a in resources.items()}

            # Per-project exclusions
            exclusions = {}
            for proj_id, resources in info.get("exclusions", {}).items():
                exclusions[proj_id] = {r: set(a) for r, a in resources.items()}

            self._users[uid] = User(
                id=uid,
                display_name=info.get("display_name", uid),
                email=info.get("email", ""),
                subscription_role=info.get("subscription_role"),
                project_assignments=assignments,
                grants=grants,
                exclusions=exclusions,
                reports_to=info.get("reports_to"),
            )

    # ── Dependency Resolution ────────────────────────────────────────

    def _resolve_perm_deps(self, action: str, resource: str, ancestors=None, cache=None):
        key = f"{action}:{resource}"
        if cache is None:
            cache = {}
        if ancestors is None:
            ancestors = set()
        if key in cache:
            return cache[key]
        if key in ancestors:
            raise CyclicDependencyError(f"Cycle in permission dependencies: {key}")

        new_ancestors = ancestors | {key}
        result = {resource: {action}}

        for dep_key in self._perm_deps.get(key, []):
            dep_action, dep_resource = dep_key.split(":", 1)
            sub = self._resolve_perm_deps(dep_action, dep_resource, new_ancestors, cache)
            for r, actions in sub.items():
                result.setdefault(r, set()).update(actions)

        cache[key] = result
        return result

    def _resolve_role_perms(self, role_name: str, ancestors=None, cache=None):
        if cache is None:
            cache = {}
        if ancestors is None:
            ancestors = set()
        if role_name in cache:
            return cache[role_name]
        if role_name in ancestors:
            raise CyclicDependencyError(f"Cycle in role inheritance: {role_name}")

        new_ancestors = ancestors | {role_name}
        role = self._roles[role_name]
        merged: dict[str, set] = {}

        for parent in role.inherits:
            parent_perms = self._resolve_role_perms(parent, new_ancestors, cache)
            for r, actions in parent_perms.items():
                merged.setdefault(r, set()).update(actions)

        for r, actions in role.direct_permissions.items():
            merged.setdefault(r, set()).update(actions)

        dep_cache = {}
        expanded: dict[str, set] = {}
        for r, actions in merged.items():
            for action in actions:
                deps = self._resolve_perm_deps(action, r, cache=dep_cache)
                for dep_r, dep_actions in deps.items():
                    expanded.setdefault(dep_r, set()).update(dep_actions)

        cache[role_name] = expanded
        return expanded

    def _resolve_all_roles(self):
        cache = {}
        for role_name in self._roles:
            self._roles[role_name].effective_permissions = self._resolve_role_perms(
                role_name, cache=cache
            )

    # ── Evaluation ───────────────────────────────────────────────────

    def can(self, user_id: str, action: str, resource: str, project_id: str | None = None) -> bool:
        """
        Check permission. For project-scoped resources, project_id is required.
        For subscription-scoped resources, project_id is ignored.
        """
        user = self._users.get(user_id)
        if not user:
            return False

        resource_obj = self._resources.get(resource)
        if not resource_obj:
            return False

        if resource_obj.scope == "subscription":
            return self._can_subscription(user, action, resource)
        else:
            if not project_id:
                return False
            return self._can_project(user, action, resource, project_id)

    def _can_subscription(self, user: User, action: str, resource: str) -> bool:
        if not user.subscription_role:
            return False
        role = self._roles.get(user.subscription_role)
        if not role:
            return False
        return action in role.effective_permissions.get(resource, set())

    def _can_project(self, user: User, action: str, resource: str, project_id: str) -> bool:
        # 1. Exclusions (per project)
        proj_exclusions = user.exclusions.get(project_id, {})
        if action in proj_exclusions.get(resource, set()):
            return False

        # 2. Grants (per project)
        proj_grants = user.grants.get(project_id, {})
        if action in proj_grants.get(resource, set()):
            return True

        # 3. Role-based
        assignment = user.project_assignments.get(project_id)
        if not assignment:
            return False
        role = self._roles.get(assignment.role)
        if not role:
            return False
        return action in role.effective_permissions.get(resource, set())

    def get_effective_permissions(self, user_id: str, project_id: str | None = None) -> dict[str, set]:
        """Get all effective permissions for a user in a given scope."""
        user = self._users.get(user_id)
        if not user:
            return {}

        if project_id:
            return self._get_project_perms(user, project_id)
        else:
            return self._get_subscription_perms(user)

    def _get_subscription_perms(self, user: User) -> dict[str, set]:
        if not user.subscription_role:
            return {}
        role = self._roles.get(user.subscription_role)
        if not role:
            return {}
        return {r: set(a) for r, a in role.effective_permissions.items()}

    def _get_project_perms(self, user: User, project_id: str) -> dict[str, set]:
        perms: dict[str, set] = {}

        assignment = user.project_assignments.get(project_id)
        if assignment:
            role = self._roles.get(assignment.role)
            if role:
                for r, actions in role.effective_permissions.items():
                    perms.setdefault(r, set()).update(actions)

        for r, actions in user.grants.get(project_id, {}).items():
            perms.setdefault(r, set()).update(actions)

        for r, actions in user.exclusions.get(project_id, {}).items():
            if r in perms:
                perms[r] -= actions
                if not perms[r]:
                    del perms[r]

        return perms

    # ── UI Export ────────────────────────────────────────────────────

    def export_ui_manifest(self, user_id: str, project_id: str | None = None) -> dict:
        """Export flat permission manifest for frontend."""
        user = self._users.get(user_id)
        if not user:
            return {}

        effective = self.get_effective_permissions(user_id, project_id)
        scope = "project" if project_id else "subscription"

        permissions = {}
        for r_name, resource in self._resources.items():
            if resource.scope != scope:
                continue
            action_map = {}
            user_actions = effective.get(r_name, set())
            for action in resource.allowed_actions:
                action_map[action] = action in user_actions
            permissions[r_name] = action_map

        result = {
            "user": user.id,
            "display_name": user.display_name,
            "scope": scope,
            "permissions": permissions,
        }
        if project_id:
            assignment = user.project_assignments.get(project_id)
            result["project_id"] = project_id
            result["project_role"] = assignment.role if assignment else None
        else:
            result["subscription_role"] = user.subscription_role

        return result

    def export_role_matrix(self, scope: str | None = None) -> dict:
        """Export role-resource-action matrix for admin panel."""
        matrix = {}
        for role_name, role in self._roles.items():
            if scope and role.scope != scope:
                continue
            role_perms = {}
            for r_name, resource in self._resources.items():
                if resource.scope != role.scope:
                    continue
                action_map = {}
                effective = role.effective_permissions.get(r_name, set())
                direct = role.direct_permissions.get(r_name, set())
                for action in resource.allowed_actions:
                    if action in direct:
                        action_map[action] = "direct"
                    elif action in effective:
                        action_map[action] = "inherited"
                    else:
                        action_map[action] = False
                role_perms[r_name] = action_map
            matrix[role_name] = {
                "description": role.description,
                "scope": role.scope,
                "user_type": role.user_type,
                "inherits": role.inherits,
                "permissions": role_perms,
            }
        return matrix

    # ── Hierarchy ────────────────────────────────────────────────────

    def get_subordinates(self, user_id: str, recursive=True) -> list[str]:
        direct = [uid for uid, u in self._users.items() if u.reports_to == user_id]
        if not recursive:
            return direct
        result = []
        for sub in direct:
            result.append(sub)
            result.extend(self.get_subordinates(sub, recursive=True))
        return result

    def get_management_chain(self, user_id: str) -> list[str]:
        chain = []
        current = self._users.get(user_id)
        visited = set()
        while current and current.reports_to:
            if current.reports_to in visited:
                break
            visited.add(current.reports_to)
            chain.append(current.reports_to)
            current = self._users.get(current.reports_to)
        return chain

    # ── Introspection ────────────────────────────────────────────────

    def explain(self, user_id: str, action: str, resource: str, project_id: str | None = None) -> str:
        user = self._users.get(user_id)
        if not user:
            return f"Unknown user '{user_id}'"

        perm_key = f"{action}:{resource}"
        resource_obj = self._resources.get(resource)
        if not resource_obj:
            return f"Unknown resource '{resource}'"

        if resource_obj.scope == "subscription":
            if not user.subscription_role:
                return f"{user_id} CANNOT {perm_key} -- no subscription role"
            role = self._roles.get(user.subscription_role)
            if role and action in role.effective_permissions.get(resource, set()):
                return f"{user_id} CAN {perm_key} -- subscription role '{user.subscription_role}'"
            return f"{user_id} CANNOT {perm_key} -- subscription role '{user.subscription_role}' does not include this"

        if not project_id:
            return f"{user_id} CANNOT {perm_key} -- project_id required for project-scoped resource"

        proj_exclusions = user.exclusions.get(project_id, {})
        if action in proj_exclusions.get(resource, set()):
            return f"{user_id} CANNOT {perm_key} in {project_id} -- excluded by admin override"

        proj_grants = user.grants.get(project_id, {})
        if action in proj_grants.get(resource, set()):
            return f"{user_id} CAN {perm_key} in {project_id} -- explicitly granted"

        assignment = user.project_assignments.get(project_id)
        if not assignment:
            return f"{user_id} CANNOT {perm_key} in {project_id} -- not assigned to this project"

        role = self._roles.get(assignment.role)
        if role and action in role.effective_permissions.get(resource, set()):
            return f"{user_id} CAN {perm_key} in {project_id} -- project role '{assignment.role}'"

        return f"{user_id} CANNOT {perm_key} in {project_id} -- role '{assignment.role}' does not include this"

    def get_dependency_chain(self, action: str, resource: str) -> list[str]:
        deps = self._resolve_perm_deps(action, resource)
        result = []
        for r, actions in sorted(deps.items()):
            for a in sorted(actions):
                key = f"{a}:{r}"
                if key != f"{action}:{resource}":
                    result.append(key)
        return result

    def get_user(self, user_id: str) -> User:
        return self._users[user_id]

    def list_users(self) -> dict[str, User]:
        return dict(self._users)

    def list_roles(self) -> dict[str, Role]:
        return dict(self._roles)

    def list_resources(self) -> dict[str, Resource]:
        return dict(self._resources)

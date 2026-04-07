import json
from pathlib import Path

from .exceptions import (
    CyclicDependencyError,
    UnknownPermissionError,
    UnknownRoleError,
)
from .models import Resource, Role, User


class RBACEngine:
    """
    Enterprise RBAC engine supporting:
    - Resource-action permission matrix (11 actions)
    - Permission dependencies with transitive resolution
    - Role inheritance + composition (DAG with cycle detection)
    - Per-user grants and exclusions (admin overrides)
    - Org hierarchy (reports_to chain)
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
                inherits=info.get("inherits", []),
                direct_permissions=direct,
            )

    def _build_users(self):
        for uid, info in self._config.get("users", {}).items():
            grants = {r: set(a) for r, a in info.get("grants", {}).items()}
            exclusions = {r: set(a) for r, a in info.get("exclusions", {}).items()}
            self._users[uid] = User(
                id=uid,
                display_name=info.get("display_name", uid),
                roles=info.get("roles", []),
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

    def can(self, user: User | str, action: str, resource: str) -> bool:
        """Check if user has permission. O(1) set lookup after resolution."""
        if isinstance(user, str):
            user = self._users[user]

        if action in user.exclusions.get(resource, set()):
            return False
        if action in user.grants.get(resource, set()):
            return True
        for role_name in user.roles:
            role = self._roles[role_name]
            if action in role.effective_permissions.get(resource, set()):
                return True
        return False

    def get_effective_permissions(self, user: User | str) -> dict[str, set]:
        """Get full permission map: resource -> set of allowed actions."""
        if isinstance(user, str):
            user = self._users[user]

        perms: dict[str, set] = {}
        for role_name in user.roles:
            role = self._roles[role_name]
            for r, actions in role.effective_permissions.items():
                perms.setdefault(r, set()).update(actions)
        for r, actions in user.grants.items():
            perms.setdefault(r, set()).update(actions)
        for r, actions in user.exclusions.items():
            if r in perms:
                perms[r] -= actions
                if not perms[r]:
                    del perms[r]
        return perms

    # ── UI Export ────────────────────────────────────────────────────

    def export_ui_manifest(self, user: User | str) -> dict:
        """Export flat permission manifest for frontend rendering."""
        if isinstance(user, str):
            user = self._users[user]

        effective = self.get_effective_permissions(user)
        permissions = {}
        for r_name, resource in self._resources.items():
            action_map = {}
            user_actions = effective.get(r_name, set())
            for action in resource.allowed_actions:
                action_map[action] = action in user_actions
            permissions[r_name] = action_map

        return {
            "user": user.id,
            "display_name": user.display_name,
            "roles": user.roles,
            "permissions": permissions,
        }

    def export_all_manifests(self) -> dict:
        return {uid: self.export_ui_manifest(uid) for uid in self._users}

    def export_role_matrix(self) -> dict:
        """Export role-resource-action matrix for admin panel."""
        matrix = {}
        for role_name, role in self._roles.items():
            role_perms = {}
            for r_name, resource in self._resources.items():
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

    def explain(self, user: User | str, action: str, resource: str) -> str:
        if isinstance(user, str):
            user = self._users[user]

        perm_key = f"{action}:{resource}"

        if action in user.exclusions.get(resource, set()):
            return f"{user.id} CANNOT {perm_key} -- excluded by admin override"
        if action in user.grants.get(resource, set()):
            return f"{user.id} CAN {perm_key} -- explicitly granted"
        for role_name in user.roles:
            role = self._roles[role_name]
            if action in role.direct_permissions.get(resource, set()):
                return f"{user.id} CAN {perm_key} -- direct permission from role '{role_name}'"
            if action in role.effective_permissions.get(resource, set()):
                return f"{user.id} CAN {perm_key} -- inherited via role '{role_name}'"
        return f"{user.id} CANNOT {perm_key} -- no role grants this"

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

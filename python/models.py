from dataclasses import dataclass, field


@dataclass
class Resource:
    name: str
    description: str
    allowed_actions: list

    def __repr__(self):
        return f"Resource({self.name}, actions={self.allowed_actions})"


@dataclass
class Role:
    name: str
    description: str
    inherits: list
    direct_permissions: dict = field(default_factory=dict)
    effective_permissions: dict = field(default_factory=dict)

    def has(self, action: str, resource: str) -> bool:
        return action in self.effective_permissions.get(resource, set())

    def __repr__(self):
        total = sum(len(v) for v in self.effective_permissions.values())
        return f"Role({self.name}, {total} effective perms)"


@dataclass
class User:
    id: str
    display_name: str
    roles: list
    grants: dict = field(default_factory=dict)
    exclusions: dict = field(default_factory=dict)
    reports_to: str | None = None

    def __repr__(self):
        return f"User({self.id}, roles={self.roles})"

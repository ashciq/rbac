class RBACError(Exception):
    """Base exception for RBAC framework."""


class CyclicDependencyError(RBACError):
    """Raised when a cycle is detected in permission or role dependencies."""


class UnknownPermissionError(RBACError):
    """Raised when referencing a permission that doesn't exist in the config."""


class UnknownRoleError(RBACError):
    """Raised when referencing a role that doesn't exist in the config."""


class InvalidPermissionFormat(RBACError):
    """Raised when a permission key doesn't follow the action:resource format."""

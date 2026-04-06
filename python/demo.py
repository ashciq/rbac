#!/usr/bin/env python3
"""
RBAC Framework v2 Demo
Demonstrates: resource-action matrix, composite roles, admin exclusions,
org hierarchy, and UI-exportable permission manifests.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from python.engine import RBACEngine


def header(title: str):
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}")


def main():
    config_path = Path(__file__).resolve().parent.parent / "schema" / "rbac_model.json"
    engine = RBACEngine(config_path)

    resources = engine.list_resources()
    actions_all = ["read", "create", "update", "delete", "upload", "manage"]

    # ── 1. ROLE PERMISSION MATRIX ────────────────────────────────────
    header("ROLE PERMISSION MATRIX (D=direct, I=inherited, -=denied)")
    role_matrix = engine.export_role_matrix()
    for role_name, info in role_matrix.items():
        inherits = f" (inherits: {', '.join(info['inherits'])})" if info["inherits"] else ""
        print(f"\n  [{role_name.upper()}]{inherits}")
        print(f"  {info['description']}")
        print(f"  {'Resource':<14}", end="")
        for a in actions_all:
            print(f"{a:<10}", end="")
        print()
        print(f"  {'-' * 74}")
        for r_name in resources:
            perms = info["permissions"][r_name]
            print(f"  {r_name:<14}", end="")
            for a in actions_all:
                val = perms.get(a, False)
                if val == "direct":
                    symbol = "D"
                elif val == "inherited":
                    symbol = "I"
                else:
                    symbol = "-"
                print(f"{symbol:<10}", end="")
            print()

    # ── 2. USER PERMISSION MATRIX ────────────────────────────────────
    header("USER PERMISSION MATRIX (Y=yes, X=excluded, -=no)")
    users = engine.list_users()
    for uid, user in users.items():
        effective = engine.get_effective_permissions(user)
        exclusion_keys = {f"{a}:{r}" for r, actions in user.exclusions.items() for a in actions}
        grant_keys = {f"{a}:{r}" for r, actions in user.grants.items() for a in actions}

        roles_str = ", ".join(user.roles)
        extras = []
        if grant_keys:
            extras.append(f"+grants:{','.join(sorted(grant_keys))}")
        if exclusion_keys:
            extras.append(f"-excluded:{','.join(sorted(exclusion_keys))}")
        extra_str = f"  ({' '.join(extras)})" if extras else ""

        print(f"\n  [{uid.upper()}] {user.display_name} -- roles: {roles_str}{extra_str}")
        if user.reports_to:
            chain = engine.get_management_chain(uid)
            print(f"  Org chain: {uid} -> {' -> '.join(chain)}")

        print(f"  {'Resource':<14}", end="")
        for a in actions_all:
            print(f"{a:<10}", end="")
        print()
        print(f"  {'-' * 74}")
        for r_name, resource in resources.items():
            print(f"  {r_name:<14}", end="")
            user_actions = effective.get(r_name, set())
            for a in actions_all:
                if a not in resource.allowed_actions:
                    symbol = "."
                elif a in user.exclusions.get(r_name, set()):
                    symbol = "X"
                elif a in user_actions:
                    symbol = "Y"
                else:
                    symbol = "-"
                print(f"{symbol:<10}", end="")
            print()

    # ── 3. PERMISSION DEPENDENCY CHAINS ──────────────────────────────
    header("PERMISSION DEPENDENCY CHAINS")
    dep_examples = [
        ("manage", "users"),
        ("upload", "reports"),
        ("delete", "projects"),
        ("manage", "settings"),
        ("upload", "files"),
    ]
    for action, resource in dep_examples:
        deps = engine.get_dependency_chain(action, resource)
        if deps:
            print(f"\n  {action}:{resource} requires:")
            for dep in deps:
                print(f"    -> {dep}")
        else:
            print(f"\n  {action}:{resource} -- no dependencies")

    # ── 4. ORG HIERARCHY ─────────────────────────────────────────────
    header("ORG HIERARCHY")
    def print_tree(uid, depth=0):
        user = engine.get_user(uid)
        indent = "  " + "    " * depth
        roles_str = ", ".join(user.roles)
        print(f"{indent}{user.display_name} ({uid}) [{roles_str}]")
        for sub in engine.get_subordinates(uid, recursive=False):
            print_tree(sub, depth + 1)

    # Find root users (no reports_to)
    roots = [uid for uid, u in users.items() if u.reports_to is None]
    for root in roots:
        print_tree(root)

    # ── 5. ACCESS EXPLANATIONS ───────────────────────────────────────
    header("ACCESS EXPLANATIONS")
    explain_cases = [
        ("alice", "manage", "users"),
        ("bob", "delete", "users"),
        ("carol", "read", "audit_logs"),
        ("dave", "delete", "reports"),
        ("eve", "create", "reports"),
        ("frank", "read", "audit_logs"),
        ("grace", "upload", "files"),
        ("grace", "read", "settings"),
        ("bob", "manage", "dashboard"),
    ]
    for uid, action, resource in explain_cases:
        print(f"  {engine.explain(uid, action, resource)}")

    # ── 6. UI MANIFEST EXPORT ────────────────────────────────────────
    header("UI MANIFEST EXPORT (sample: bob)")
    manifest = engine.export_ui_manifest("bob")
    print(json.dumps(manifest, indent=2))

    # ── 7. COMPOSITE ROLE DEMO ───────────────────────────────────────
    header("COMPOSITE ROLE DEMO: grace (contributor + user_manager)")
    grace = engine.get_user("grace")
    effective = engine.get_effective_permissions(grace)
    print(f"\n  Roles: {', '.join(grace.roles)}")
    print(f"  Extra grants: {dict(grace.grants)}")
    print(f"  Exclusions: {dict(grace.exclusions)}")
    print(f"\n  Effective permissions:")
    for r in sorted(effective):
        print(f"    {r}: {', '.join(sorted(effective[r]))}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
RBAC Framework v3 Demo — ConstructivIQ
Demonstrates: subscription + project scoped permissions, construction industry roles,
admin exclusions, per-project grants, and UI manifest export.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from python.engine import RBACEngine


def header(title: str):
    print(f"\n{'=' * 90}")
    print(f"  {title}")
    print(f"{'=' * 90}")


def main():
    config_path = Path(__file__).resolve().parent.parent / "schema" / "rbac_model.json"
    engine = RBACEngine(config_path)

    actions_all = engine._actions
    PROJECT = "project_alpha"

    # ── 1. PROJECT ROLE MATRIX ───────────────────────────────────────
    header("PROJECT ROLE PERMISSION MATRIX (D=direct, I=inherited)")
    role_matrix = engine.export_role_matrix(scope="project")
    project_resources = {n: r for n, r in engine.list_resources().items() if r.scope == "project"}

    for role_name, info in role_matrix.items():
        inherits = f" (inherits: {', '.join(info['inherits'])})" if info["inherits"] else ""
        user_type = f" [{info['user_type']}]" if info["user_type"] else ""
        print(f"\n  [{role_name.upper()}]{user_type}{inherits}")
        print(f"  {info['description']}")
        print(f"  {'Resource':<26}", end="")
        for a in actions_all:
            print(f"{a[:4]:<6}", end="")
        print()
        print(f"  {'-' * 92}")
        for r_name in project_resources:
            perms = info["permissions"].get(r_name, {})
            if not perms:
                continue
            print(f"  {r_name:<26}", end="")
            for a in actions_all:
                val = perms.get(a, False)
                if val == "direct":
                    symbol = "D"
                elif val == "inherited":
                    symbol = "I"
                else:
                    symbol = "-"
                print(f"{symbol:<6}", end="")
            print()

    # ── 2. USER PROJECT PERMISSIONS ──────────────────────────────────
    header(f"USER PERMISSIONS IN '{PROJECT}'")
    users = engine.list_users()

    for uid, user in users.items():
        assignment = user.project_assignments.get(PROJECT)
        if not assignment:
            continue

        effective = engine.get_effective_permissions(uid, PROJECT)
        print(f"\n  [{uid.upper()}] {user.display_name} -- role: {assignment.role}")

        exclusion_info = user.exclusions.get(PROJECT, {})
        grant_info = user.grants.get(PROJECT, {})
        if exclusion_info:
            print(f"    Exclusions: {dict({r: list(a) for r, a in exclusion_info.items()})}")
        if grant_info:
            print(f"    Grants: {dict({r: list(a) for r, a in grant_info.items()})}")

        print(f"    {'Resource':<26}", end="")
        for a in actions_all:
            print(f"{a[:4]:<6}", end="")
        print()
        print(f"    {'-' * 88}")
        for r_name, resource in project_resources.items():
            user_actions = effective.get(r_name, set())
            has_any = any(a in user_actions or a in exclusion_info.get(r_name, set()) for a in resource.allowed_actions)
            if not has_any:
                continue
            print(f"    {r_name:<26}", end="")
            for a in actions_all:
                if a not in resource.allowed_actions:
                    symbol = "."
                elif a in exclusion_info.get(r_name, set()):
                    symbol = "X"
                elif a in user_actions:
                    symbol = "Y"
                else:
                    symbol = "-"
                print(f"{symbol:<6}", end="")
            print()

    # ── 3. SUBSCRIPTION PERMISSIONS ──────────────────────────────────
    header("SUBSCRIPTION-LEVEL PERMISSIONS")
    sub_resources = {n: r for n, r in engine.list_resources().items() if r.scope == "subscription"}

    for uid, user in users.items():
        if not user.subscription_role:
            continue
        effective = engine.get_effective_permissions(uid)
        print(f"\n  [{uid.upper()}] {user.display_name} -- role: {user.subscription_role}")
        for r_name in sub_resources:
            actions = effective.get(r_name, set())
            if actions:
                print(f"    {r_name}: {', '.join(sorted(actions))}")

    # ── 4. PERMISSION CHECKS ────────────────────────────────────────
    header("PERMISSION CHECKS & EXPLANATIONS")
    checks = [
        ("sarah", "create", "submittals", PROJECT),
        ("mike", "create", "submittals", PROJECT),
        ("priya", "approve", "workflows", PROJECT),
        ("james", "download", "materials", PROJECT),
        ("lisa", "download", "risk_reports", PROJECT),
        ("sarah", "manage", "subscription_users", None),
        ("mike", "delete", "subscription_users", None),
        ("raj", "approve", "submittals", PROJECT),
        ("tom", "create", "submittals", PROJECT),
        ("sarah", "manage", "workflow_templates", PROJECT),
    ]
    for uid, action, resource, proj in checks:
        result = engine.can(uid, action, resource, proj)
        explanation = engine.explain(uid, action, resource, proj)
        status = "YES" if result else "NO "
        print(f"  [{status}] {explanation}")

    # ── 5. UI MANIFEST ──────────────────────────────────────────────
    header("UI MANIFEST EXPORT (priya in project_alpha)")
    manifest = engine.export_ui_manifest("priya", PROJECT)
    print(json.dumps(manifest, indent=2))

    # ── 6. DEPENDENCY CHAINS ────────────────────────────────────────
    header("PERMISSION DEPENDENCY CHAINS")
    dep_examples = [
        ("manage", "project_users"),
        ("manage", "workflows"),
        ("manage", "schedules"),
        ("archive", "submittals"),
        ("manage", "subscription_users"),
    ]
    for action, resource in dep_examples:
        deps = engine.get_dependency_chain(action, resource)
        if deps:
            print(f"\n  {action}:{resource} requires:")
            for dep in deps:
                print(f"    -> {dep}")

    # ── 7. COMPARISON: OLD vs NEW ───────────────────────────────────
    header("MIGRATION: OLD PERMISSION ENUM -> NEW RBAC")
    mapping = [
        ("ViewProjectList",                     "list",     "projects",              None),
        ("AddProjectUser",                      "create",   "project_users",         PROJECT),
        ("EditProjectDetail",                   "update",   "project_settings",      PROJECT),
        ("CreateSubmittal",                     "create",   "submittals",            PROJECT),
        ("InlineEditSubmittal",                 "update",   "submittals",            PROJECT),
        ("SubmittalWorkflow",                   "approve",  "workflows",             PROJECT),
        ("AddTradePartner",                     "create",   "trade_partners",        PROJECT),
        ("AddAttachment",                       "upload",   "attachments",           PROJECT),
        ("AddEditCalendar",                     "manage",   "calendars",             PROJECT),
        ("ViewLinkingPage",                     "read",     "linking",               PROJECT),
        ("EditLinkingPage",                     "update",   "linking",               PROJECT),
        ("CreateMaterial",                      "create",   "materials",             PROJECT),
        ("EditMaterialCharacteristics",         "update",   "material_characteristics", PROJECT),
        ("EditMaterialDBOffset",                "update",   "material_dateblock",    PROJECT),
        ("ImportSchedule",                      "upload",   "schedules",             PROJECT),
        ("MakeActiveSchedule",                  "manage",   "schedules",             PROJECT),
        ("DeleteMaterialAttachment",            "delete",   "attachments",           PROJECT),
        ("ViewProjectReports",                  "read",     "risk_reports",          PROJECT),
        ("UploadSpecSectionFile",               "upload",   "spec_sections",         PROJECT),
        ("CreateMaterialComment",               "create",   "material_comments",     PROJECT),
        ("ChangeMaterialTemplate",              "update",   "material_templates",    PROJECT),
        ("EditWorkflowTemplate",                "manage",   "workflow_templates",    PROJECT),
        ("EditRiskThreshold",                   "update",   "risk_thresholds",       PROJECT),
        ("BidPackageWrite",                     "create",   "bid_packages",          PROJECT),
        ("DesignPackageWrite",                  "create",   "design_packages",       PROJECT),
        ("addProjectIntegration",               "create",   "integrations",          PROJECT),
        ("changeProjectIntegration",            "update",   "integrations",          PROJECT),
        ("RequestLeadTime",                     "create",   "lead_time_requests",    PROJECT),
    ]

    print(f"\n  {'Old Enum':<40} {'New Permission':<35} {'GC Admin':<10}")
    print(f"  {'-' * 85}")
    for old_name, action, resource, proj in mapping:
        new_perm = f"{action}:{resource}"
        can_gc = "YES" if engine.can("sarah", action, resource, proj) else "NO"
        print(f"  {old_name:<40} {new_perm:<35} {can_gc:<10}")


if __name__ == "__main__":
    main()

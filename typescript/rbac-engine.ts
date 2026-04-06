/**
 * RBAC Engine - TypeScript SDK
 * Cross-language permission framework with dependency resolution,
 * composite roles, admin overrides, and UI-exportable manifests.
 *
 * Works in both Node.js and Browser environments.
 */

// ── Types ───────────────────────────────────────────────────────────

export interface ResourceConfig {
  description: string;
  allowed_actions: string[];
}

export interface RoleConfig {
  description: string;
  inherits: string[];
  permissions: Record<string, string[]>;
}

export interface UserConfig {
  display_name: string;
  roles: string[];
  grants: Record<string, string[]>;
  exclusions: Record<string, string[]>;
  reports_to: string | null;
}

export interface RBACConfig {
  version: string;
  actions: string[];
  resources: Record<string, ResourceConfig>;
  permission_dependencies: Record<string, string[]>;
  roles: Record<string, RoleConfig>;
  users: Record<string, UserConfig>;
}

export interface UIManifest {
  user: string;
  display_name: string;
  roles: string[];
  permissions: Record<string, Record<string, boolean>>;
}

export interface RoleMatrixEntry {
  description: string;
  inherits: string[];
  permissions: Record<string, Record<string, "direct" | "inherited" | false>>;
}

// ── Models ──────────────────────────────────────────────────────────

export interface Resource {
  name: string;
  description: string;
  allowedActions: string[];
}

export interface Role {
  name: string;
  description: string;
  inherits: string[];
  directPermissions: Map<string, Set<string>>;
  effectivePermissions: Map<string, Set<string>>;
}

export interface User {
  id: string;
  displayName: string;
  roles: string[];
  grants: Map<string, Set<string>>;
  exclusions: Map<string, Set<string>>;
  reportsTo: string | null;
}

// ── Exceptions ──────────────────────────────────────────────────────

export class RBACError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RBACError";
  }
}

export class CyclicDependencyError extends RBACError {
  constructor(message: string) {
    super(message);
    this.name = "CyclicDependencyError";
  }
}

// ── Engine ──────────────────────────────────────────────────────────

export class RBACEngine {
  private actions: string[];
  private resources: Map<string, Resource> = new Map();
  private permDeps: Map<string, string[]> = new Map();
  private roles: Map<string, Role> = new Map();
  private users: Map<string, User> = new Map();

  constructor(config: RBACConfig) {
    this.actions = config.actions;
    this.buildResources(config.resources);
    this.buildPermDeps(config.permission_dependencies || {});
    this.buildRoles(config.roles);
    this.resolveAllRoles();
    this.buildUsers(config.users || {});
  }

  /**
   * Load from JSON string (useful in browser when fetching config).
   */
  static fromJSON(json: string): RBACEngine {
    return new RBACEngine(JSON.parse(json));
  }

  // ── Building ────────────────────────────────────────────────────

  private buildResources(raw: Record<string, ResourceConfig>): void {
    for (const [name, info] of Object.entries(raw)) {
      this.resources.set(name, {
        name,
        description: info.description || "",
        allowedActions: info.allowed_actions,
      });
    }
  }

  private buildPermDeps(raw: Record<string, string[]>): void {
    for (const [key, deps] of Object.entries(raw)) {
      this.permDeps.set(key, deps);
    }
  }

  private buildRoles(raw: Record<string, RoleConfig>): void {
    for (const [name, info] of Object.entries(raw)) {
      const directPerms = new Map<string, Set<string>>();
      for (const [resource, actions] of Object.entries(info.permissions || {})) {
        directPerms.set(resource, new Set(actions));
      }
      this.roles.set(name, {
        name,
        description: info.description || "",
        inherits: info.inherits || [],
        directPermissions: directPerms,
        effectivePermissions: new Map(),
      });
    }
  }

  private buildUsers(raw: Record<string, UserConfig>): void {
    for (const [id, info] of Object.entries(raw)) {
      const grants = new Map<string, Set<string>>();
      for (const [r, actions] of Object.entries(info.grants || {})) {
        grants.set(r, new Set(actions));
      }
      const exclusions = new Map<string, Set<string>>();
      for (const [r, actions] of Object.entries(info.exclusions || {})) {
        exclusions.set(r, new Set(actions));
      }
      this.users.set(id, {
        id,
        displayName: info.display_name || id,
        roles: info.roles || [],
        grants,
        exclusions,
        reportsTo: info.reports_to || null,
      });
    }
  }

  // ── Resolution ──────────────────────────────────────────────────

  private resolvePermDeps(
    action: string,
    resource: string,
    ancestors: Set<string> = new Set(),
    cache: Map<string, Map<string, Set<string>>> = new Map()
  ): Map<string, Set<string>> {
    const key = `${action}:${resource}`;

    if (cache.has(key)) return cache.get(key)!;

    if (ancestors.has(key)) {
      throw new CyclicDependencyError(`Cycle in permission dependencies: ${key}`);
    }

    const newAncestors = new Set(ancestors);
    newAncestors.add(key);

    const result = new Map<string, Set<string>>();
    result.set(resource, new Set([action]));

    const deps = this.permDeps.get(key) || [];
    for (const depKey of deps) {
      const [depAction, depResource] = depKey.split(":", 2);
      const sub = this.resolvePermDeps(depAction, depResource, newAncestors, cache);
      for (const [r, actions] of sub) {
        const existing = result.get(r) || new Set();
        for (const a of actions) existing.add(a);
        result.set(r, existing);
      }
    }

    cache.set(key, result);
    return result;
  }

  private resolveRolePerms(
    roleName: string,
    ancestors: Set<string> = new Set(),
    cache: Map<string, Map<string, Set<string>>> = new Map()
  ): Map<string, Set<string>> {
    if (cache.has(roleName)) return cache.get(roleName)!;

    if (ancestors.has(roleName)) {
      throw new CyclicDependencyError(`Cycle in role inheritance: ${roleName}`);
    }

    const newAncestors = new Set(ancestors);
    newAncestors.add(roleName);

    const role = this.roles.get(roleName)!;
    const merged = new Map<string, Set<string>>();

    // Inherited
    for (const parent of role.inherits) {
      const parentPerms = this.resolveRolePerms(parent, newAncestors, cache);
      for (const [r, actions] of parentPerms) {
        const existing = merged.get(r) || new Set();
        for (const a of actions) existing.add(a);
        merged.set(r, existing);
      }
    }

    // Direct
    for (const [r, actions] of role.directPermissions) {
      const existing = merged.get(r) || new Set();
      for (const a of actions) existing.add(a);
      merged.set(r, existing);
    }

    // Expand dependencies
    const depCache = new Map<string, Map<string, Set<string>>>();
    const expanded = new Map<string, Set<string>>();
    for (const [r, actions] of merged) {
      for (const action of actions) {
        const deps = this.resolvePermDeps(action, r, new Set(), depCache);
        for (const [depR, depActions] of deps) {
          const existing = expanded.get(depR) || new Set();
          for (const a of depActions) existing.add(a);
          expanded.set(depR, existing);
        }
      }
    }

    cache.set(roleName, expanded);
    return expanded;
  }

  private resolveAllRoles(): void {
    const cache = new Map<string, Map<string, Set<string>>>();
    for (const [name, role] of this.roles) {
      role.effectivePermissions = this.resolveRolePerms(name, new Set(), cache);
    }
  }

  // ── Evaluation ──────────────────────────────────────────────────

  /**
   * Core permission check. O(1) set lookup.
   */
  can(userId: string, action: string, resource: string): boolean {
    const user = this.users.get(userId);
    if (!user) throw new RBACError(`Unknown user '${userId}'`);
    return this.canUser(user, action, resource);
  }

  canUser(user: User, action: string, resource: string): boolean {
    // 1. Exclusions always win
    if (user.exclusions.get(resource)?.has(action)) return false;

    // 2. Explicit grants
    if (user.grants.get(resource)?.has(action)) return true;

    // 3. Role-based
    for (const roleName of user.roles) {
      const role = this.roles.get(roleName);
      if (!role) throw new RBACError(`Unknown role '${roleName}'`);
      if (role.effectivePermissions.get(resource)?.has(action)) return true;
    }

    return false;
  }

  /**
   * Get all effective permissions for a user.
   */
  getEffectivePermissions(userId: string): Map<string, Set<string>> {
    const user = this.users.get(userId);
    if (!user) throw new RBACError(`Unknown user '${userId}'`);

    const perms = new Map<string, Set<string>>();

    for (const roleName of user.roles) {
      const role = this.roles.get(roleName)!;
      for (const [r, actions] of role.effectivePermissions) {
        const existing = perms.get(r) || new Set();
        for (const a of actions) existing.add(a);
        perms.set(r, existing);
      }
    }

    for (const [r, actions] of user.grants) {
      const existing = perms.get(r) || new Set();
      for (const a of actions) existing.add(a);
      perms.set(r, existing);
    }

    for (const [r, actions] of user.exclusions) {
      const existing = perms.get(r);
      if (existing) {
        for (const a of actions) existing.delete(a);
        if (existing.size === 0) perms.delete(r);
      }
    }

    return perms;
  }

  // ── UI Export ───────────────────────────────────────────────────

  /**
   * Export flat permission manifest for frontend rendering.
   * Every resource-action pair is true/false.
   */
  exportUIManifest(userId: string): UIManifest {
    const user = this.users.get(userId);
    if (!user) throw new RBACError(`Unknown user '${userId}'`);

    const effective = this.getEffectivePermissions(userId);
    const permissions: Record<string, Record<string, boolean>> = {};

    for (const [rName, resource] of this.resources) {
      const actionMap: Record<string, boolean> = {};
      const userActions = effective.get(rName) || new Set();
      for (const action of resource.allowedActions) {
        actionMap[action] = userActions.has(action);
      }
      permissions[rName] = actionMap;
    }

    return {
      user: user.id,
      display_name: user.displayName,
      roles: user.roles,
      permissions,
    };
  }

  /**
   * Export manifests for all users.
   */
  exportAllManifests(): Record<string, UIManifest> {
    const result: Record<string, UIManifest> = {};
    for (const userId of this.users.keys()) {
      result[userId] = this.exportUIManifest(userId);
    }
    return result;
  }

  /**
   * Export role matrix for admin panel role editor.
   */
  exportRoleMatrix(): Record<string, RoleMatrixEntry> {
    const matrix: Record<string, RoleMatrixEntry> = {};

    for (const [roleName, role] of this.roles) {
      const rolePerms: Record<string, Record<string, "direct" | "inherited" | false>> = {};

      for (const [rName, resource] of this.resources) {
        const actionMap: Record<string, "direct" | "inherited" | false> = {};
        const effective = role.effectivePermissions.get(rName) || new Set();
        const direct = role.directPermissions.get(rName) || new Set();

        for (const action of resource.allowedActions) {
          if (direct.has(action)) {
            actionMap[action] = "direct";
          } else if (effective.has(action)) {
            actionMap[action] = "inherited";
          } else {
            actionMap[action] = false;
          }
        }
        rolePerms[rName] = actionMap;
      }

      matrix[roleName] = {
        description: role.description,
        inherits: role.inherits,
        permissions: rolePerms,
      };
    }

    return matrix;
  }

  // ── Hierarchy ───────────────────────────────────────────────────

  getSubordinates(userId: string, recursive = true): string[] {
    const direct: string[] = [];
    for (const [id, user] of this.users) {
      if (user.reportsTo === userId) direct.push(id);
    }
    if (!recursive) return direct;

    const result: string[] = [];
    for (const sub of direct) {
      result.push(sub);
      result.push(...this.getSubordinates(sub, true));
    }
    return result;
  }

  getManagementChain(userId: string): string[] {
    const chain: string[] = [];
    const visited = new Set<string>();
    let current = this.users.get(userId);

    while (current?.reportsTo) {
      if (visited.has(current.reportsTo)) break;
      visited.add(current.reportsTo);
      chain.push(current.reportsTo);
      current = this.users.get(current.reportsTo);
    }
    return chain;
  }

  // ── Introspection ──────────────────────────────────────────────

  explain(userId: string, action: string, resource: string): string {
    const user = this.users.get(userId);
    if (!user) return `Unknown user '${userId}'`;

    const permKey = `${action}:${resource}`;

    if (user.exclusions.get(resource)?.has(action)) {
      return `${userId} CANNOT ${permKey} -- excluded by admin override`;
    }

    if (user.grants.get(resource)?.has(action)) {
      return `${userId} CAN ${permKey} -- explicitly granted`;
    }

    for (const roleName of user.roles) {
      const role = this.roles.get(roleName)!;
      if (role.directPermissions.get(resource)?.has(action)) {
        return `${userId} CAN ${permKey} -- direct permission from role '${roleName}'`;
      }
      if (role.effectivePermissions.get(resource)?.has(action)) {
        return `${userId} CAN ${permKey} -- inherited via role '${roleName}'`;
      }
    }

    return `${userId} CANNOT ${permKey} -- no role grants this`;
  }

  getUser(userId: string): User | undefined {
    return this.users.get(userId);
  }

  getRole(roleName: string): Role | undefined {
    return this.roles.get(roleName);
  }

  listUsers(): Map<string, User> {
    return new Map(this.users);
  }

  listRoles(): Map<string, Role> {
    return new Map(this.roles);
  }

  listResources(): Map<string, Resource> {
    return new Map(this.resources);
  }
}

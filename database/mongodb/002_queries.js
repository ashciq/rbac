// ============================================================================
// RBAC Framework - MongoDB Queries & Aggregations
// Run individual queries in mongosh
// ============================================================================

use("rbac_db");

// ── 1. CHECK PERMISSION ─────────────────────────────────────────────────────
// Equivalent to can_user(username, action, resource)
// Must resolve role inheritance in application layer or via $graphLookup

// Get all roles for a user (with inheritance resolved via $graphLookup)
function getUserRoles(username) {
  const result = db.users.aggregate([
    { $match: { _id: username, is_active: true } },
    { $unwind: "$roles" },
    {
      $graphLookup: {
        from: "roles",
        startWith: "$roles",
        connectFromField: "inherits",
        connectToField: "_id",
        as: "resolved_roles"
      }
    },
    {
      $project: {
        all_roles: {
          $setUnion: [
            ["$roles"],
            "$resolved_roles._id"
          ]
        }
      }
    },
    {
      $group: {
        _id: null,
        all_roles: { $addToSet: "$all_roles" }
      }
    },
    {
      $project: {
        all_roles: {
          $reduce: {
            input: "$all_roles",
            initialValue: [],
            in: { $setUnion: ["$$value", "$$this"] }
          }
        }
      }
    }
  ]).toArray();

  return result.length > 0 ? result[0].all_roles : [];
}

// Check if user can perform action on resource
function canUser(username, action, resource) {
  const user = db.users.findOne({ _id: username, is_active: true });
  if (!user) return false;

  // 1. Exclusions
  const exclusions = user.exclusions || {};
  if (exclusions[resource] && exclusions[resource].includes(action)) {
    return false;
  }

  // 2. Grants
  const grants = user.grants || {};
  if (grants[resource] && grants[resource].includes(action)) {
    return true;
  }

  // 3. Role-based (with inheritance)
  const allRoles = getUserRoles(username);
  for (const roleName of allRoles) {
    const role = db.roles.findOne({ _id: roleName });
    if (role && role.permissions[resource] && role.permissions[resource].includes(action)) {
      return true;
    }
  }

  return false;
}

// Usage:
print("=== Permission Checks ===");
print(`alice can manage:users = ${canUser("alice", "manage", "users")}`);
print(`bob can delete:users = ${canUser("bob", "delete", "users")}`);
print(`carol can read:audit_logs = ${canUser("carol", "read", "audit_logs")}`);
print(`dave can delete:reports = ${canUser("dave", "delete", "reports")}`);
print(`grace can upload:files = ${canUser("grace", "upload", "files")}`);


// ── 2. GET EFFECTIVE PERMISSIONS ─────────────────────────────────────────────

function getEffectivePermissions(username) {
  const user = db.users.findOne({ _id: username, is_active: true });
  if (!user) return {};

  const allRoles = getUserRoles(username);
  const perms = {};

  // Collect from all resolved roles
  for (const roleName of allRoles) {
    const role = db.roles.findOne({ _id: roleName });
    if (role) {
      for (const [resource, actions] of Object.entries(role.permissions)) {
        if (!perms[resource]) perms[resource] = new Set();
        actions.forEach(a => perms[resource].add(a));
      }
    }
  }

  // Add grants
  for (const [resource, actions] of Object.entries(user.grants || {})) {
    if (!perms[resource]) perms[resource] = new Set();
    actions.forEach(a => perms[resource].add(a));
  }

  // Remove exclusions
  for (const [resource, actions] of Object.entries(user.exclusions || {})) {
    if (perms[resource]) {
      actions.forEach(a => perms[resource].delete(a));
      if (perms[resource].size === 0) delete perms[resource];
    }
  }

  // Convert sets to arrays
  const result = {};
  for (const [resource, actions] of Object.entries(perms)) {
    result[resource] = [...actions].sort();
  }
  return result;
}

print("\n=== Effective Permissions (bob) ===");
printjson(getEffectivePermissions("bob"));


// ── 3. GET SUBORDINATES ──────────────────────────────────────────────────────

function getSubordinates(username, recursive = true) {
  if (recursive) {
    return db.users.aggregate([
      { $match: { _id: username } },
      {
        $graphLookup: {
          from: "users",
          startWith: "$_id",
          connectFromField: "_id",
          connectToField: "reports_to",
          as: "subordinates",
          depthField: "depth"
        }
      },
      { $unwind: "$subordinates" },
      { $sort: { "subordinates.depth": 1 } },
      {
        $project: {
          _id: "$subordinates._id",
          display_name: "$subordinates.display_name",
          depth: "$subordinates.depth"
        }
      }
    ]).toArray();
  } else {
    return db.users.find(
      { reports_to: username },
      { _id: 1, display_name: 1 }
    ).toArray();
  }
}

print("\n=== Subordinates of Alice ===");
printjson(getSubordinates("alice"));


// ── 4. GET MANAGEMENT CHAIN ─────────────────────────────────────────────────

function getManagementChain(username) {
  return db.users.aggregate([
    { $match: { _id: username } },
    {
      $graphLookup: {
        from: "users",
        startWith: "$reports_to",
        connectFromField: "reports_to",
        connectToField: "_id",
        as: "managers",
        depthField: "depth"
      }
    },
    { $unwind: "$managers" },
    { $sort: { "managers.depth": 1 } },
    {
      $project: {
        _id: "$managers._id",
        display_name: "$managers.display_name",
        depth: "$managers.depth"
      }
    }
  ]).toArray();
}

print("\n=== Management Chain for Eve ===");
printjson(getManagementChain("eve"));


// ── 5. EXPORT UI MANIFEST ───────────────────────────────────────────────────

function exportUIManifest(username) {
  const user = db.users.findOne({ _id: username, is_active: true });
  if (!user) return null;

  const effective = getEffectivePermissions(username);
  const resources = db.resources.find().toArray();
  const permissions = {};

  for (const resource of resources) {
    const actionMap = {};
    const userActions = effective[resource._id] || [];
    for (const action of resource.allowed_actions) {
      actionMap[action] = userActions.includes(action);
    }
    permissions[resource._id] = actionMap;
  }

  return {
    user: user._id,
    display_name: user.display_name,
    roles: user.roles,
    permissions
  };
}

print("\n=== UI Manifest (bob) ===");
printjson(exportUIManifest("bob"));


// ── 6. AGGREGATION: USERS PER ROLE ──────────────────────────────────────────

print("\n=== Users Per Role ===");
printjson(
  db.users.aggregate([
    { $unwind: "$roles" },
    {
      $group: {
        _id: "$roles",
        users: { $push: "$_id" },
        count: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]).toArray()
);

/**
 * RBAC TypeScript SDK Demo
 * Run: npx ts-node demo.ts
 */

import * as fs from "fs";
import * as path from "path";
import { RBACEngine } from "./rbac-engine";

const configPath = path.join(__dirname, "..", "schema", "rbac_model.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
const engine = new RBACEngine(config);

console.log("=".repeat(70));
console.log("  RBAC TypeScript SDK Demo");
console.log("=".repeat(70));

// Permission checks
console.log("\n-- Permission Checks --");
const checks: [string, string, string][] = [
  ["alice", "manage", "users"],
  ["bob", "delete", "users"],
  ["carol", "read", "audit_logs"],
  ["dave", "delete", "reports"],
  ["eve", "create", "reports"],
  ["grace", "upload", "files"],
];

for (const [user, action, resource] of checks) {
  const result = engine.can(user, action, resource);
  console.log(`  ${user}.can(${action}, ${resource}) = ${result}`);
}

// Explanations
console.log("\n-- Explanations --");
for (const [user, action, resource] of checks) {
  console.log(`  ${engine.explain(user, action, resource)}`);
}

// UI Manifest
console.log("\n-- UI Manifest (bob) --");
const manifest = engine.exportUIManifest("bob");
console.log(JSON.stringify(manifest, null, 2));

// Hierarchy
console.log("\n-- Org Hierarchy --");
console.log(`  Alice's subordinates: ${engine.getSubordinates("alice").join(", ")}`);
console.log(`  Eve's management chain: ${engine.getManagementChain("eve").join(" -> ")}`);

// Role matrix sample
console.log("\n-- Role Matrix (editor) --");
const matrix = engine.exportRoleMatrix();
const editor = matrix["editor"];
console.log(`  ${editor.description} (inherits: ${editor.inherits.join(", ")})`);
for (const [resource, actions] of Object.entries(editor.permissions)) {
  const entries = Object.entries(actions)
    .filter(([_, v]) => v !== false)
    .map(([a, v]) => `${a}:${v}`)
    .join(", ");
  if (entries) console.log(`    ${resource}: ${entries}`);
}

console.log("\nDone!");

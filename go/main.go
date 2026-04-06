// RBAC Go SDK Demo
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"rbac-go/rbac"
)

func main() {
	engine, err := rbac.NewEngineFromFile("../schema/rbac_model.json")
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("  RBAC Go SDK Demo")
	fmt.Println(strings.Repeat("=", 70))

	// Permission checks
	checks := []struct{ user, action, resource string }{
		{"alice", "manage", "users"},
		{"bob", "delete", "users"},
		{"carol", "read", "audit_logs"},
		{"dave", "delete", "reports"},
		{"eve", "create", "reports"},
		{"grace", "upload", "files"},
	}

	fmt.Println("\n-- Permission Checks --")
	for _, c := range checks {
		result, _ := engine.Can(c.user, c.action, c.resource)
		fmt.Printf("  %s.Can(%s, %s) = %v\n", c.user, c.action, c.resource, result)
	}

	fmt.Println("\n-- Explanations --")
	for _, c := range checks {
		fmt.Printf("  %s\n", engine.Explain(c.user, c.action, c.resource))
	}

	fmt.Println("\n-- UI Manifest (bob) --")
	manifest, _ := engine.ExportUIManifest("bob")
	data, _ := json.MarshalIndent(manifest, "  ", "  ")
	fmt.Printf("  %s\n", string(data))

	fmt.Println("\n-- Hierarchy --")
	subs := engine.GetSubordinates("alice", true)
	fmt.Printf("  Alice's subordinates: %s\n", strings.Join(subs, ", "))
	chain := engine.GetManagementChain("eve")
	fmt.Printf("  Eve's management chain: %s\n", strings.Join(chain, " -> "))

	fmt.Println("\nDone!")
}

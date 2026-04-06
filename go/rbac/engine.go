// Package rbac provides a cross-language RBAC engine with permission
// dependencies, composite roles, admin overrides, and UI manifest export.
package rbac

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ── Config Types (JSON deserialization) ─────────────────────────────

type Config struct {
	Version       string                       `json:"version"`
	Actions       []string                     `json:"actions"`
	Resources     map[string]ResourceConfig    `json:"resources"`
	PermDeps      map[string][]string          `json:"permission_dependencies"`
	Roles         map[string]RoleConfig        `json:"roles"`
	Users         map[string]UserConfig        `json:"users"`
}

type ResourceConfig struct {
	Description    string   `json:"description"`
	AllowedActions []string `json:"allowed_actions"`
}

type RoleConfig struct {
	Description string              `json:"description"`
	Inherits    []string            `json:"inherits"`
	Permissions map[string][]string `json:"permissions"`
}

type UserConfig struct {
	DisplayName string              `json:"display_name"`
	Roles       []string            `json:"roles"`
	Grants      map[string][]string `json:"grants"`
	Exclusions  map[string][]string `json:"exclusions"`
	ReportsTo   *string             `json:"reports_to"`
}

// ── Domain Models ───────────────────────────────────────────────────

type Resource struct {
	Name           string
	Description    string
	AllowedActions []string
}

type Role struct {
	Name                 string
	Description          string
	Inherits             []string
	DirectPermissions    map[string]map[string]bool // resource -> action -> true
	EffectivePermissions map[string]map[string]bool
}

type User struct {
	ID          string
	DisplayName string
	Roles       []string
	Grants      map[string]map[string]bool
	Exclusions  map[string]map[string]bool
	ReportsTo   string
}

// ── UI Export Types ─────────────────────────────────────────────────

type UIManifest struct {
	User        string                       `json:"user"`
	DisplayName string                       `json:"display_name"`
	Roles       []string                     `json:"roles"`
	Permissions map[string]map[string]bool   `json:"permissions"`
}

// ── Engine ──────────────────────────────────────────────────────────

type Engine struct {
	actions   []string
	resources map[string]*Resource
	permDeps  map[string][]string
	roles     map[string]*Role
	users     map[string]*User
	// ordered keys for deterministic iteration
	resourceOrder []string
	roleOrder     []string
	userOrder     []string
}

// NewEngineFromFile loads config from a JSON file.
func NewEngineFromFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	return NewEngine(data)
}

// NewEngine creates an engine from raw JSON bytes.
func NewEngine(data []byte) (*Engine, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	e := &Engine{
		actions:   cfg.Actions,
		resources: make(map[string]*Resource),
		permDeps:  cfg.PermDeps,
		roles:     make(map[string]*Role),
		users:     make(map[string]*User),
	}

	if e.permDeps == nil {
		e.permDeps = make(map[string][]string)
	}

	e.buildResources(cfg.Resources)
	e.buildRoles(cfg.Roles)
	if err := e.resolveAllRoles(); err != nil {
		return nil, err
	}
	e.buildUsers(cfg.Users)

	return e, nil
}

func (e *Engine) buildResources(raw map[string]ResourceConfig) {
	for name, rc := range raw {
		e.resources[name] = &Resource{
			Name:           name,
			Description:    rc.Description,
			AllowedActions: rc.AllowedActions,
		}
		e.resourceOrder = append(e.resourceOrder, name)
	}
	sort.Strings(e.resourceOrder)
}

func (e *Engine) buildRoles(raw map[string]RoleConfig) {
	for name, rc := range raw {
		direct := make(map[string]map[string]bool)
		for resource, actions := range rc.Permissions {
			m := make(map[string]bool)
			for _, a := range actions {
				m[a] = true
			}
			direct[resource] = m
		}
		e.roles[name] = &Role{
			Name:                 name,
			Description:          rc.Description,
			Inherits:             rc.Inherits,
			DirectPermissions:    direct,
			EffectivePermissions: make(map[string]map[string]bool),
		}
		e.roleOrder = append(e.roleOrder, name)
	}
	sort.Strings(e.roleOrder)
}

func (e *Engine) buildUsers(raw map[string]UserConfig) {
	for id, uc := range raw {
		grants := toActionMap(uc.Grants)
		exclusions := toActionMap(uc.Exclusions)
		reportsTo := ""
		if uc.ReportsTo != nil {
			reportsTo = *uc.ReportsTo
		}
		e.users[id] = &User{
			ID:          id,
			DisplayName: uc.DisplayName,
			Roles:       uc.Roles,
			Grants:      grants,
			Exclusions:  exclusions,
			ReportsTo:   reportsTo,
		}
		e.userOrder = append(e.userOrder, id)
	}
	sort.Strings(e.userOrder)
}

func toActionMap(raw map[string][]string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for resource, actions := range raw {
		m := make(map[string]bool)
		for _, a := range actions {
			m[a] = true
		}
		result[resource] = m
	}
	return result
}

// ── Resolution ──────────────────────────────────────────────────────

func (e *Engine) resolvePermDeps(action, resource string, ancestors map[string]bool, cache map[string]map[string]map[string]bool) (map[string]map[string]bool, error) {
	key := action + ":" + resource

	if cached, ok := cache[key]; ok {
		return cached, nil
	}
	if ancestors[key] {
		return nil, fmt.Errorf("cycle in permission dependencies: %s", key)
	}

	newAnc := copySet(ancestors)
	newAnc[key] = true

	result := map[string]map[string]bool{
		resource: {action: true},
	}

	for _, depKey := range e.permDeps[key] {
		parts := strings.SplitN(depKey, ":", 2)
		sub, err := e.resolvePermDeps(parts[0], parts[1], newAnc, cache)
		if err != nil {
			return nil, err
		}
		mergePerms(result, sub)
	}

	cache[key] = result
	return result, nil
}

func (e *Engine) resolveRolePerms(roleName string, ancestors map[string]bool, cache map[string]map[string]map[string]bool) (map[string]map[string]bool, error) {
	if cached, ok := cache[roleName]; ok {
		return cached, nil
	}
	if ancestors[roleName] {
		return nil, fmt.Errorf("cycle in role inheritance: %s", roleName)
	}

	newAnc := copySet(ancestors)
	newAnc[roleName] = true
	role := e.roles[roleName]
	merged := make(map[string]map[string]bool)

	for _, parent := range role.Inherits {
		parentPerms, err := e.resolveRolePerms(parent, newAnc, cache)
		if err != nil {
			return nil, err
		}
		mergePerms(merged, parentPerms)
	}

	mergePerms(merged, role.DirectPermissions)

	// Expand deps
	depCache := make(map[string]map[string]map[string]bool)
	expanded := make(map[string]map[string]bool)
	for r, actions := range merged {
		for a := range actions {
			deps, err := e.resolvePermDeps(a, r, make(map[string]bool), depCache)
			if err != nil {
				return nil, err
			}
			mergePerms(expanded, deps)
		}
	}

	cache[roleName] = expanded
	return expanded, nil
}

func (e *Engine) resolveAllRoles() error {
	cache := make(map[string]map[string]map[string]bool)
	for name, role := range e.roles {
		perms, err := e.resolveRolePerms(name, make(map[string]bool), cache)
		if err != nil {
			return err
		}
		role.EffectivePermissions = perms
	}
	return nil
}

// ── Evaluation ──────────────────────────────────────────────────────

// Can checks if a user has permission to perform action on resource.
func (e *Engine) Can(userID, action, resource string) (bool, error) {
	user, ok := e.users[userID]
	if !ok {
		return false, fmt.Errorf("unknown user '%s'", userID)
	}

	// 1. Exclusions win
	if user.Exclusions[resource][action] {
		return false, nil
	}
	// 2. Grants
	if user.Grants[resource][action] {
		return true, nil
	}
	// 3. Role-based
	for _, roleName := range user.Roles {
		role := e.roles[roleName]
		if role.EffectivePermissions[resource][action] {
			return true, nil
		}
	}
	return false, nil
}

// GetEffectivePermissions returns all permissions for a user.
func (e *Engine) GetEffectivePermissions(userID string) (map[string]map[string]bool, error) {
	user, ok := e.users[userID]
	if !ok {
		return nil, fmt.Errorf("unknown user '%s'", userID)
	}

	perms := make(map[string]map[string]bool)
	for _, roleName := range user.Roles {
		role := e.roles[roleName]
		mergePerms(perms, role.EffectivePermissions)
	}
	mergePerms(perms, user.Grants)

	for r, actions := range user.Exclusions {
		for a := range actions {
			delete(perms[r], a)
			if len(perms[r]) == 0 {
				delete(perms, r)
			}
		}
	}

	return perms, nil
}

// ── UI Export ────────────────────────────────────────────────────────

// ExportUIManifest returns a flat permission manifest for frontend use.
func (e *Engine) ExportUIManifest(userID string) (*UIManifest, error) {
	user, ok := e.users[userID]
	if !ok {
		return nil, fmt.Errorf("unknown user '%s'", userID)
	}

	effective, _ := e.GetEffectivePermissions(userID)
	permissions := make(map[string]map[string]bool)

	for _, rName := range e.resourceOrder {
		resource := e.resources[rName]
		actionMap := make(map[string]bool)
		userActions := effective[rName]
		for _, action := range resource.AllowedActions {
			actionMap[action] = userActions[action]
		}
		permissions[rName] = actionMap
	}

	return &UIManifest{
		User:        user.ID,
		DisplayName: user.DisplayName,
		Roles:       user.Roles,
		Permissions: permissions,
	}, nil
}

// ── Hierarchy ───────────────────────────────────────────────────────

// GetSubordinates returns subordinates of a user.
func (e *Engine) GetSubordinates(userID string, recursive bool) []string {
	var direct []string
	for _, uid := range e.userOrder {
		if e.users[uid].ReportsTo == userID {
			direct = append(direct, uid)
		}
	}
	if !recursive {
		return direct
	}
	var result []string
	for _, sub := range direct {
		result = append(result, sub)
		result = append(result, e.GetSubordinates(sub, true)...)
	}
	return result
}

// GetManagementChain returns the chain of managers up to root.
func (e *Engine) GetManagementChain(userID string) []string {
	var chain []string
	visited := make(map[string]bool)
	current := e.users[userID]
	for current != nil && current.ReportsTo != "" {
		if visited[current.ReportsTo] {
			break
		}
		visited[current.ReportsTo] = true
		chain = append(chain, current.ReportsTo)
		current = e.users[current.ReportsTo]
	}
	return chain
}

// Explain returns a human-readable reason for access decision.
func (e *Engine) Explain(userID, action, resource string) string {
	user, ok := e.users[userID]
	if !ok {
		return fmt.Sprintf("Unknown user '%s'", userID)
	}
	permKey := action + ":" + resource

	if user.Exclusions[resource][action] {
		return fmt.Sprintf("%s CANNOT %s -- excluded by admin override", userID, permKey)
	}
	if user.Grants[resource][action] {
		return fmt.Sprintf("%s CAN %s -- explicitly granted", userID, permKey)
	}
	for _, roleName := range user.Roles {
		role := e.roles[roleName]
		if role.DirectPermissions[resource][action] {
			return fmt.Sprintf("%s CAN %s -- direct permission from role '%s'", userID, permKey, roleName)
		}
		if role.EffectivePermissions[resource][action] {
			return fmt.Sprintf("%s CAN %s -- inherited via role '%s'", userID, permKey, roleName)
		}
	}
	return fmt.Sprintf("%s CANNOT %s -- no role grants this", userID, permKey)
}

// ── Helpers ─────────────────────────────────────────────────────────

func copySet(s map[string]bool) map[string]bool {
	c := make(map[string]bool, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

func mergePerms(dst, src map[string]map[string]bool) {
	for r, actions := range src {
		if dst[r] == nil {
			dst[r] = make(map[string]bool)
		}
		for a := range actions {
			dst[r][a] = true
		}
	}
}

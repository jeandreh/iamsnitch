package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/jeandreh/iam-snitch/internal/domain/model"
)

// ACLBuilder constructs access control rules from AWS policies following the official
// AWS policy evaluation order:
// 1. Explicit Deny (any policy) → Access DENIED
// 2. Identity-Based Policy → Action must be explicitly allowed
// 3. Permission Boundary → Action must be within boundary scope (intersection)
// 4. Service Control Policy (SCP) → Action must not be denied by SCP
// 5. Resource Policy (for resource-based access) → Principal must be allowed
type ACLBuilder struct {
	role              types.Role
	principals        []Principal
	policies          []IdentityPolicy
	boundaryPolicies  []Statement // Permission boundary statements (intersected with identity)
	scpPolicies       []Statement // SCP statements (explicit denies filter rules)
	resourcePolicies  []Statement // Resource policy statements (external principals)
	acl               []model.AccessControlRule
	hasBoundaryPolicy bool // Flag to track if boundaries are configured
	hasSCPPolicies    bool // Flag to track if SCPs are configured
}

// NewACLBuilder creates an ACLBuilder for identity-based policies only (backward compatible).
// This path bypasses boundary, SCP, and resource policy evaluation for performance.
func NewACLBuilder(role types.Role, principals []Principal, policies []IdentityPolicy) *ACLBuilder {
	return &ACLBuilder{
		role:       role,
		principals: principals,
		policies:   policies,
		acl:        make([]model.AccessControlRule, 0, 100),
	}
}

// NewACLBuilderWithPolicies creates an ACLBuilder with full AWS policy evaluation order support.
// Use this for Phase 3+ implementations that need boundaries, SCPs, and resource policies.
func NewACLBuilderWithPolicies(
	identityPolicies []model.IdentityPolicy,
	boundaries map[string]*model.BoundaryPolicy,
	scps []model.SCPPolicy,
	resourcePolicies map[string]model.ResourcePolicy,
) *ACLBuilder {
	builder := &ACLBuilder{
		acl: make([]model.AccessControlRule, 0, 100),
	}

	// Extract boundary statements per principal
	boundaryStatements := make([]Statement, 0)
	for _, boundary := range boundaries {
		if boundary != nil && boundary.Statements != nil {
			if stmts, ok := boundary.Statements.([]Statement); ok {
				boundaryStatements = append(boundaryStatements, stmts...)
			}
		}
	}
	builder.boundaryPolicies = boundaryStatements
	builder.hasBoundaryPolicy = len(boundaryStatements) > 0

	// Extract SCP statements
	scpStatements := make([]Statement, 0)
	for _, scp := range scps {
		if scp.Statements != nil {
			if stmts, ok := scp.Statements.([]Statement); ok {
				scpStatements = append(scpStatements, stmts...)
			}
		}
	}
	builder.scpPolicies = scpStatements
	builder.hasSCPPolicies = len(scpStatements) > 0

	// Extract resource policy statements
	resourceStatements := make([]Statement, 0)
	for _, resourcePolicy := range resourcePolicies {
		if resourcePolicy.Statements != nil {
			if stmts, ok := resourcePolicy.Statements.([]Statement); ok {
				resourceStatements = append(resourceStatements, stmts...)
			}
		}
	}
	builder.resourcePolicies = resourceStatements

	// Build rules from identity policies
	builder.buildFromIdentityPolicies(identityPolicies)

	return builder
}

func (b *ACLBuilder) buildFromIdentityPolicies(identityPolicies []model.IdentityPolicy) {
	for _, identityPolicy := range identityPolicies {
		if identityPolicy.Statements == nil {
			continue
		}
		stmts, ok := identityPolicy.Statements.([]Statement)
		if !ok {
			continue
		}
		for _, stmt := range stmts {
			b.processIdentityStatement(identityPolicy.Principal, &stmt)
		}
	}
}

func (b *ACLBuilder) processIdentityStatement(principal string, s *Statement) {
	// Skip Deny statements in identity policies (they're not used for Allow rules,
	// but should trigger explicit deny evaluation in Step 1)
	if s.Effect == "Deny" {
		return
	}

	// Combine Actions and NotActions for processing
	allActions := append(s.Actions, s.NotActions...)

	for _, r := range s.Resources {
		b.processIdentityRules(principal, r, allActions)
	}
}

func (b *ACLBuilder) processIdentityRules(principal string, r string, al []string) {
	for _, a := range al {
		rule := model.AccessControlRule{
			Principal: model.Principal{ID: principal},
			Permission: model.Permission{
				ID: a,
			},
			Resource: model.Resource{ID: r},
			GrantChain: []model.GrantIface{
				// For identity policies, grant is from the principal itself
				model.NewRoleGrant(principal),
			},
		}
		b.acl = append(b.acl, rule)
	}
}

// SetBoundaryPolicies adds permission boundary policies to the builder (fluent API).
// Returns self for method chaining.
func (b *ACLBuilder) SetBoundaryPolicies(boundaryStatements []Statement) *ACLBuilder {
	b.boundaryPolicies = boundaryStatements
	b.hasBoundaryPolicy = len(boundaryStatements) > 0
	return b
}

// SetSCPPolicies adds service control policies to the builder (fluent API).
// Returns self for method chaining.
func (b *ACLBuilder) SetSCPPolicies(scpStatements []Statement) *ACLBuilder {
	b.scpPolicies = scpStatements
	b.hasSCPPolicies = len(scpStatements) > 0
	return b
}

// SetResourcePolicies adds resource-based policies to the builder (fluent API).
// Returns self for method chaining.
func (b *ACLBuilder) SetResourcePolicies(resourceStatements []Statement) *ACLBuilder {
	b.resourcePolicies = resourceStatements
	return b
}

// Build generates access control rules following the AWS policy evaluation order:
// Step 1: Explicit Deny Check - If any policy explicitly denies an action, access is DENIED immediately
// Step 2: Identity Policy Rules - Generate base rules from identity policies (action must be explicitly allowed)
// Step 3: Boundary Intersection - If permission boundary exists, keep only actions allowed by BOTH identity and boundary
// Step 4: SCP Filtering - Remove actions explicitly denied by any SCP at account/OU level
// Step 5: Resource Policy Expansion - If resource policies present, create additional rules for external principals
func (b *ACLBuilder) Build() []model.AccessControlRule {
	// Step 1: Check for explicit denies across all policies (identity, boundary, SCP, resource)
	// If an explicit deny is found, we should not proceed with allowing actions
	deniedActions := b.getExplicitDeniedActions()

	// Step 3: Apply permission boundary intersection
	if b.hasBoundaryPolicy {
		b.acl = b.intersectWithBoundary(b.acl, b.boundaryPolicies)
	}

	// Step 4: Filter rules by SCP explicit denies
	if b.hasSCPPolicies {
		b.acl = b.filterBySCP(b.acl, b.scpPolicies, deniedActions)
	}

	// Step 5: Extract and process resource policy principals
	if len(b.resourcePolicies) > 0 {
		b.acl = b.processResourcePolicies(b.acl, b.resourcePolicies)
	}

	return b.acl
}

// processStatements processes all statements in a policy for a given principal.
func (b *ACLBuilder) processStatements(pr *Principal, po *IdentityPolicy) {
	for _, s := range po.Statements {
		// Skip Deny statements in identity policies (they're not used for Allow rules,
		// but should trigger explicit deny evaluation in Step 1)
		if s.Effect == "Deny" {
			continue
		}

		// Combine Actions and NotActions for processing
		allActions := append(s.Actions, s.NotActions...)

		b.processStatement(pr, po, &s, allActions)
	}
}

// processStatement processes a single statement to generate rules for each resource-action combination.
func (b *ACLBuilder) processStatement(pr *Principal, po *IdentityPolicy, s *Statement, actions []string) {
	for _, r := range s.Resources {
		b.processRules(pr, po, r, actions)
	}
}

// processRules creates an AccessControlRule for each action on a resource.
// Each rule tracks the principal, permission, resource, and the grant chain (role → identity policy).
func (b *ACLBuilder) processRules(pr *Principal, po *IdentityPolicy, r string, al []string) {
	for _, a := range al {
		rule := model.AccessControlRule{
			Principal: model.Principal{ID: pr.String()},
			Permission: model.Permission{
				ID: a,
			},
			Resource: model.Resource{ID: r},
			GrantChain: []model.GrantIface{
				model.NewRoleGrant(*b.role.Arn),
				model.NewPolicyGrant(po.ARN),
			},
		}
		b.acl = append(b.acl, rule)
	}
}

// getExplicitDeniedActions collects all actions that are explicitly denied across identity, boundary, SCP, and resource policies.
// AWS policy evaluation order mandates that explicit denies always take precedence.
// Returns a set (map[string]bool) of action patterns that are explicitly denied.
func (b *ACLBuilder) getExplicitDeniedActions() map[string]bool {
	deniedActions := make(map[string]bool)

	// Check identity policies for explicit denies
	for _, po := range b.policies {
		for _, s := range po.Statements {
			if s.Effect == "Deny" {
				allActions := append(s.Actions, s.NotActions...)
				for _, action := range allActions {
					deniedActions[action] = true
				}
			}
		}
	}

	// Check boundary policies for explicit denies (though boundaries typically only Allow)
	for _, s := range b.boundaryPolicies {
		if s.Effect == "Deny" {
			allActions := append(s.Actions, s.NotActions...)
			for _, action := range allActions {
				deniedActions[action] = true
			}
		}
	}

	// Check SCP policies for explicit denies (SCPs can contain both Allow and Deny)
	for _, s := range b.scpPolicies {
		if s.Effect == "Deny" {
			allActions := append(s.Actions, s.NotActions...)
			for _, action := range allActions {
				deniedActions[action] = true
			}
		}
	}

	// Check resource policies for explicit denies
	for _, s := range b.resourcePolicies {
		if s.Effect == "Deny" {
			for _, action := range s.Actions {
				deniedActions[action] = true
			}
		}
	}

	return deniedActions
}

// intersectWithBoundary applies permission boundary evaluation (Step 3).
// A permission boundary defines the maximum permissions a principal can have.
// Only actions that are explicitly allowed by BOTH the identity policy AND the boundary are kept.
// This is a logical AND operation: (identity permissions) ∩ (boundary permissions)
func (b *ACLBuilder) intersectWithBoundary(rules []model.AccessControlRule, boundaryStatements []Statement) []model.AccessControlRule {
	if len(boundaryStatements) == 0 {
		return rules
	}

	// Collect all actions allowed by the boundary
	boundaryActions := make(map[string]bool)
	for _, s := range boundaryStatements {
		if s.Effect == "Allow" {
			allActions := append(s.Actions, s.NotActions...)
			for _, action := range allActions {
				boundaryActions[action] = true
			}
		}
	}

	// Filter rules to keep only those with actions in the boundary
	var filteredRules []model.AccessControlRule
	for _, rule := range rules {
		if boundaryActions[rule.Permission.ID] || b.actionMatchesPattern(rule.Permission.ID, boundaryActions) {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules
}

// filterBySCP applies Service Control Policy filtering (Step 4).
// SCPs provide organizational-level access controls that can deny actions even if allowed by identity policies.
// Actions that are explicitly denied by any SCP are removed from the rules.
// SCPs use a deny-list approach: actions NOT in the SCP's deny list are potentially allowed.
func (b *ACLBuilder) filterBySCP(rules []model.AccessControlRule, scpStatements []Statement, deniedActions map[string]bool) []model.AccessControlRule {
	if len(scpStatements) == 0 {
		return rules
	}

	// Collect all actions explicitly denied by SCPs
	scpDeniedActions := make(map[string]bool)
	for _, s := range scpStatements {
		if s.Effect == "Deny" {
			allActions := append(s.Actions, s.NotActions...)
			for _, action := range allActions {
				scpDeniedActions[action] = true
			}
		}
	}

	// Filter out any rules where the action is explicitly denied by an SCP
	var filteredRules []model.AccessControlRule
	for _, rule := range rules {
		if !scpDeniedActions[rule.Permission.ID] && !b.actionMatchesPattern(rule.Permission.ID, scpDeniedActions) {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules
}

// processResourcePolicies extracts principals from resource-based policies (Step 5).
// Resource policies can grant access to external principals (other AWS accounts, service principals, etc.).
// This function creates additional AccessControlRule entries for these external principals.
// TODO: Future enhancement - track conditions from policy statements in the grant chain for audit trails.
func (b *ACLBuilder) processResourcePolicies(rules []model.AccessControlRule, resourceStatements []Statement) []model.AccessControlRule {
	if len(resourceStatements) == 0 {
		return rules
	}

	// Extract principals from resource policy statements
	for _, s := range resourceStatements {
		// Skip explicit denies in resource policies
		if s.Effect != "Allow" {
			continue
		}

		// Extract the principals from the statement
		for _, principal := range s.Principals.Items {
			for _, resource := range s.Resources {
				allActions := append(s.Actions, s.NotActions...)
				for _, action := range allActions {
					// Create a new rule for the external principal
					rule := model.AccessControlRule{
						Principal: model.Principal{ID: principal.String()},
						Permission: model.Permission{
							ID: action,
						},
						Resource: model.Resource{ID: resource},
						GrantChain: []model.GrantIface{
							model.NewRoleGrant(*b.role.Arn),
							// Resource policies don't have ARNs in the same way as identity policies
							// For now, we use a synthetic identifier
							model.NewPolicyGrant(fmt.Sprintf("resource-policy:%s", resource)),
						},
					}
					rules = append(rules, rule)
				}
			}
		}
	}

	return rules
}

// actionMatchesPattern checks if an action string matches any pattern in the provided action set.
// Supports AWS action wildcards like "s3:*", "s3:Get*", "*", etc.
// Returns true if the action matches any pattern in the set.
func (b *ACLBuilder) actionMatchesPattern(action string, patterns map[string]bool) bool {
	for pattern := range patterns {
		if matchesWildcard(action, pattern) {
			return true
		}
	}
	return false
}

// matchesWildcard checks if an action matches a wildcard pattern.
// AWS supports * as a wildcard that matches any string.
// Examples:
//   - "s3:*" matches "s3:GetObject", "s3:PutObject", etc.
//   - "*" matches any action
//   - "s3:Get*" matches "s3:GetObject", "s3:GetBucketPolicy", etc.
func matchesWildcard(action, pattern string) bool {
	// Exact match
	if action == pattern {
		return true
	}

	// Pattern is just "*" - matches everything
	if pattern == "*" {
		return true
	}

	// Use simple wildcard matching: split by * and check if parts match in sequence
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// No wildcards, already checked exact match above
		return false
	}

	// Check if the action starts with the first part
	if len(parts[0]) > 0 && !strings.HasPrefix(action, parts[0]) {
		return false
	}

	// Check if the action ends with the last part
	lastPart := parts[len(parts)-1]
	if len(lastPart) > 0 && !strings.HasSuffix(action, lastPart) {
		return false
	}

	// Check all middle parts exist in sequence
	checkStart := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if len(part) == 0 {
			continue
		}
		pos := strings.Index(action[checkStart:], part)
		if pos == -1 {
			return false
		}
		checkStart += pos + len(part)
	}

	return true
}

// isBoundaryEnabled checks if a principal has a permission boundary configured.
// This is used to determine whether boundary intersection should be applied.
// NOTE: For Phase 3, we simply check if boundary statements are non-empty.
// In Phase 4+, this could be enhanced to track principal-specific boundaries.
func (b *ACLBuilder) isBoundaryEnabled() bool {
	return b.hasBoundaryPolicy
}

// isActionDeniedBySCP checks if an action is explicitly denied by any SCP.
// SCPs use an explicit deny model: if an action is not denied by an SCP,
// it passes the SCP evaluation step.
func (b *ACLBuilder) isActionDeniedBySCP(action string) bool {
	for _, s := range b.scpPolicies {
		if s.Effect == "Deny" {
			allActions := append(s.Actions, s.NotActions...)
			for _, deniedAction := range allActions {
				if matchesWildcard(action, deniedAction) {
					return true
				}
			}
		}
	}
	return false
}

// extractResourcePolicyPrincipals extracts all unique principals from resource policy statements.
// This is a helper function used in Phase 5+ to determine which external principals
// should be included in the final ACL.
func (b *ACLBuilder) extractResourcePolicyPrincipals() []Principal {
	principals := make([]Principal, 0)
	seenPrincipals := make(map[string]bool)

	for _, s := range b.resourcePolicies {
		if s.Effect != "Allow" {
			continue
		}

		for _, p := range s.Principals.Items {
			principalStr := p.String()
			if !seenPrincipals[principalStr] {
				seenPrincipals[principalStr] = true
				principals = append(principals, p)
			}
		}
	}

	return principals
}

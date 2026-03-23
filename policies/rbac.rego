package grafana.governance.rbac

import future.keywords.if
import future.keywords.in

# ============================================================================
# Grafana Governance - RBAC Policy
# Validates role assignments, membership constraints, and privilege escalation
# Applies to OrgMember resources (grafana.crossplane.io/v1beta1)
# ============================================================================

# Valid Grafana roles
valid_roles := {"Viewer", "Editor", "Admin"}

# Maximum members per organization
max_members_per_org := 500

# Roles ordered by privilege level (higher number = more privileged)
role_privilege := {
    "Viewer": 1,
    "Editor": 2,
    "Admin": 3
}

# ============================================================================
# Main deny rules
# ============================================================================

deny[msg] {
    input.kind == "OrgMember"
    msg := org_member_violations[_]
}

deny[msg] {
    input.kind == "NOCDefaultMemberList"
    msg := noc_member_list_violations[_]
}

# ============================================================================
# OrgMember validations
# ============================================================================

org_member_violations[msg] {
    role := input.spec.forProvider.role
    not role in valid_roles
    msg := sprintf("ERROR [RBAC-001]: Invalid role '%v'. Valid roles: Viewer, Editor, Admin", [role])
}

org_member_violations[msg] {
    not input.spec.forProvider.email
    msg := "ERROR [RBAC-002]: OrgMember spec.forProvider.email is required"
}

org_member_violations[msg] {
    email := input.spec.forProvider.email
    not re_match(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, email)
    msg := sprintf("ERROR [RBAC-003]: OrgMember email '%v' is not a valid email address", [email])
}

org_member_violations[msg] {
    not input.spec.forProvider.orgId
    not input.spec.forProvider.orgIdRef
    msg := "ERROR [RBAC-004]: OrgMember must specify either spec.forProvider.orgId or spec.forProvider.orgIdRef"
}

# ============================================================================
# NOCDefaultMemberList validations
# ============================================================================

noc_member_list_violations[msg] {
    members := input.spec.members
    not members
    msg := "ERROR [RBAC-010]: NOCDefaultMemberList spec.members is required"
}

noc_member_list_violations[msg] {
    members := input.spec.members
    count(members) == 0
    msg := "ERROR [RBAC-011]: NOCDefaultMemberList spec.members must have at least one member"
}

noc_member_list_violations[msg] {
    members := input.spec.members
    admin_members := [m | m := members[_]; m.grafanaRole == "Admin"]
    count(admin_members) == 0
    msg := "ERROR [RBAC-012]: NOCDefaultMemberList must have at least one member with grafanaRole: Admin"
}

noc_member_list_violations[msg] {
    member := input.spec.members[_]
    role := member.grafanaRole
    not role in valid_roles
    msg := sprintf("ERROR [RBAC-013]: NOCDefaultMemberList member role '%v' is invalid. Valid roles: Viewer, Editor, Admin", [role])
}

noc_member_list_violations[msg] {
    member := input.spec.members[_]
    not member.email
    msg := "ERROR [RBAC-014]: NOCDefaultMemberList member must have an email field"
}

noc_member_list_violations[msg] {
    member := input.spec.members[_]
    email := member.email
    not re_match(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, email)
    msg := sprintf("ERROR [RBAC-015]: NOCDefaultMemberList member email '%v' is not valid", [email])
}

# ============================================================================
# Org membership aggregate validations (for future use with full state input)
# These rules operate on org_state input: {members: [...], org_name: "..."}
# ============================================================================

# Check: at least 1 Admin per org
at_least_one_admin {
    members := input.org_state.members
    some m in members
    m.role == "Admin"
}

deny[msg] {
    input.kind == "OrgMemberState"
    not at_least_one_admin
    org := input.org_state.org_name
    msg := sprintf("ERROR [RBAC-020]: Organization '%v' must have at least one Admin member", [org])
}

# Check: max members per org
deny[msg] {
    input.kind == "OrgMemberState"
    members := input.org_state.members
    count(members) > max_members_per_org
    org := input.org_state.org_name
    msg := sprintf("ERROR [RBAC-021]: Organization '%v' has %v members, exceeding maximum of %v", [org, count(members), max_members_per_org])
}

# ============================================================================
# Privilege escalation detection
# Used during bulk-rbac operations
# Input format: {kind: "PrivilegeChange", current_role: "Viewer", new_role: "Admin", approved: false}
# ============================================================================

deny[msg] {
    input.kind == "PrivilegeChange"
    current_privilege := role_privilege[input.current_role]
    new_privilege := role_privilege[input.new_role]
    new_privilege > current_privilege
    not input.approved
    msg := sprintf("ERROR [RBAC-030]: Privilege escalation from '%v' to '%v' for user '%v' requires approval (set approved: true or use --conflict-policy escalate with approver token)", [input.current_role, input.new_role, input.user_email])
}

deny[msg] {
    input.kind == "PrivilegeChange"
    current_privilege := role_privilege[input.current_role]
    new_privilege := role_privilege[input.new_role]
    new_privilege > current_privilege
    input.approved
    not input.approver_email
    msg := sprintf("ERROR [RBAC-031]: Privilege escalation for user '%v' is approved but missing approver_email", [input.user_email])
}

# ============================================================================
# Warn rules (non-blocking advisory checks)
# ============================================================================

warn[msg] {
    input.kind == "OrgMember"
    role := input.spec.forProvider.role
    role == "Admin"
    msg := sprintf("WARN [RBAC-W001]: Admin role assignment for user '%v' - confirm this is intentional. Admin users have full org access.", [input.spec.forProvider.email])
}

warn[msg] {
    input.kind == "OrgMemberState"
    members := input.org_state.members
    admin_members := [m | m := members[_]; m.role == "Admin"]
    count(admin_members) > 5
    msg := sprintf("WARN [RBAC-W002]: Organization '%v' has %v Admin members. Consider reducing to 2-3 for least-privilege.", [input.org_state.org_name, count(admin_members)])
}

warn[msg] {
    input.kind == "OrgMemberState"
    members := input.org_state.members
    count(members) > (max_members_per_org * 0.8)
    msg := sprintf("WARN [RBAC-W003]: Organization '%v' is at %v%% of member capacity (%v/%v)", [input.org_state.org_name, count(members) * 100 / max_members_per_org, count(members), max_members_per_org])
}

# ============================================================================
# Helper functions
# ============================================================================

# Get privilege level for a role (defaults to 0 for unknown)
get_privilege(role) := level {
    level := role_privilege[role]
} else := 0

# Check if escalation is occurring
is_escalation(current_role, new_role) {
    get_privilege(new_role) > get_privilege(current_role)
}

# Check if role is valid
is_valid_role(role) {
    role in valid_roles
}

#!/usr/bin/env python3
"""
Grafana Governance Platform - Bulk RBAC Manager
Reads current RBAC state, applies bulk role assignments with conflict resolution,
generates/updates members.yaml files, and outputs a preview matrix.

Conflict Policies:
  skip      - Skip if user already has a role in the org (keep existing)
  override  - Always set the new role (overwrite existing)
  escalate  - Allow if new role is higher privilege, otherwise skip

Usage:
  python bulk-rbac.py --users user1@vpbank.com,user2@vpbank.com \\
    --orgs ORG-Platform-2025,ORG-Payments-2025 \\
    --role Editor --conflict-policy escalate

  python bulk-rbac.py --users user1@vpbank.com --orgs ORG-Platform-2025 \\
    --role Admin --conflict-policy override --apply

  python bulk-rbac.py --show-state --orgs ORG-Platform-2025
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML")
    sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

REPO_ROOT = Path(__file__).parent.parent
ORGS_DIR = REPO_ROOT / "orgs"

VALID_ROLES = ["Viewer", "Editor", "Admin"]
ROLE_PRIVILEGE = {"Viewer": 1, "Editor": 2, "Admin": 3}

VALID_CONFLICT_POLICIES = ["skip", "override", "escalate"]

# ============================================================================
# Data models
# ============================================================================

class MemberRecord:
    def __init__(self, email: str, role: str, org_k8s_name: str, source: str = "manual"):
        self.email = email
        self.role = role
        self.org_k8s_name = org_k8s_name
        self.source = source

    def __repr__(self):
        return f"MemberRecord(email={self.email}, role={self.role}, org={self.org_k8s_name})"

class ChangeRecord:
    def __init__(self, email: str, org: str, old_role: Optional[str], new_role: str, action: str, reason: str):
        self.email = email
        self.org = org
        self.old_role = old_role
        self.new_role = new_role
        self.action = action   # ADD, UPDATE, SKIP, ESCALATE_BLOCKED
        self.reason = reason

# ============================================================================
# YAML reading
# ============================================================================

def org_name_to_k8s_name(org_name: str) -> str:
    """Convert ORG-Platform-2025 -> org-platform-2025."""
    if org_name.startswith("ORG-"):
        return "org-" + org_name[4:].lower().replace(" ", "-")
    return org_name.lower().replace(" ", "-")

def find_org_dir(org_name: str) -> Optional[Path]:
    """Find the org directory for a given org name."""
    k8s_name = org_name_to_k8s_name(org_name)
    org_dir = ORGS_DIR / k8s_name
    if org_dir.exists():
        return org_dir
    return None

def load_current_members(org_k8s_name: str) -> Dict[str, MemberRecord]:
    """Load current members from an org's members.yaml file."""
    members_file = ORGS_DIR / org_k8s_name / "members.yaml"
    if not members_file.exists():
        return {}

    current: Dict[str, MemberRecord] = {}
    try:
        with open(members_file) as f:
            content = f.read()
        for doc in yaml.safe_load_all(content):
            if doc and isinstance(doc, dict) and doc.get("kind") == "OrgMember":
                for_provider = doc.get("spec", {}).get("forProvider", {})
                email = for_provider.get("email")
                role = for_provider.get("role")
                source = doc.get("metadata", {}).get("labels", {}).get("source", "manual")
                if email and role:
                    current[email] = MemberRecord(
                        email=email, role=role,
                        org_k8s_name=org_k8s_name, source=source
                    )
    except Exception as e:
        print(f"WARNING: Could not read {members_file}: {e}")

    return current

def load_all_org_members() -> Dict[str, Dict[str, MemberRecord]]:
    """Load members from all org directories."""
    result = {}
    if not ORGS_DIR.exists():
        return result
    for org_dir in ORGS_DIR.iterdir():
        if org_dir.is_dir() and not org_dir.name.startswith("_"):
            members = load_current_members(org_dir.name)
            if members:
                result[org_dir.name] = members
    return result

# ============================================================================
# YAML generation
# ============================================================================

def to_k8s_name(value: str) -> str:
    """Convert any string to a valid Kubernetes resource name."""
    value = value.lower()
    value = re.sub(r'[^a-z0-9-]', '-', value)
    value = re.sub(r'-+', '-', value)
    return value.strip('-')[:63]

def build_member_manifest(
    email: str,
    role: str,
    org_k8s_name: str,
    source: str = "manual",
    noc_injected: bool = False
) -> dict:
    """Build an OrgMember Crossplane manifest dict."""
    email_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
    k8s_name = to_k8s_name(f"{org_k8s_name}-{email_slug}")

    labels = {
        "org": org_k8s_name,
        "source": "noc-auto-injected" if noc_injected else source,
    }
    annotations = {}
    if noc_injected:
        annotations["governance.grafana.io/injected-from"] = "config/noc/noc-default-members.yaml"

    return {
        "apiVersion": "grafana.crossplane.io/v1beta1",
        "kind": "OrgMember",
        "metadata": {
            "name": k8s_name,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "forProvider": {
                "email": email,
                "role": role,
                "orgIdRef": {"name": org_k8s_name},
            }
        }
    }

def write_members_file(
    org_k8s_name: str,
    members: Dict[str, MemberRecord],
    dry_run: bool = False
) -> Optional[Path]:
    """Write members.yaml for an org."""
    org_dir = ORGS_DIR / org_k8s_name
    members_file = org_dir / "members.yaml"

    if not dry_run:
        org_dir.mkdir(parents=True, exist_ok=True)

    lines = [f"# OrgMember resources for {org_k8s_name}\n# Managed by bulk-rbac.py\n"]

    # NOC members first
    noc_emails = []
    regular_emails = []
    for email, member in members.items():
        if member.source in ("noc-auto-injected", "noc"):
            noc_emails.append(email)
        else:
            regular_emails.append(email)

    all_ordered = noc_emails + sorted(regular_emails)
    first = True
    manifests = []
    for email in all_ordered:
        member = members[email]
        manifest = build_member_manifest(
            email=email,
            role=member.role,
            org_k8s_name=org_k8s_name,
            source=member.source,
            noc_injected=(member.source in ("noc-auto-injected", "noc"))
        )
        manifests.append(manifest)

    if not dry_run:
        with open(members_file, 'w') as f:
            for i, manifest in enumerate(manifests):
                if i > 0:
                    f.write("---\n")
                yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  Written: {members_file}")
        return members_file
    return None

# ============================================================================
# Conflict resolution
# ============================================================================

def resolve_conflict(
    email: str,
    org_k8s_name: str,
    new_role: str,
    existing: MemberRecord,
    conflict_policy: str,
) -> Tuple[str, ChangeRecord]:
    """
    Resolve role conflict. Returns (action, ChangeRecord).
    Actions: ADD, UPDATE, SKIP, ESCALATE_BLOCKED
    """
    existing_privilege = ROLE_PRIVILEGE.get(existing.role, 0)
    new_privilege = ROLE_PRIVILEGE.get(new_role, 0)

    if existing.role == new_role:
        return "SKIP", ChangeRecord(
            email=email, org=org_k8s_name,
            old_role=existing.role, new_role=new_role,
            action="SKIP", reason="Same role already assigned"
        )

    if conflict_policy == "skip":
        return "SKIP", ChangeRecord(
            email=email, org=org_k8s_name,
            old_role=existing.role, new_role=new_role,
            action="SKIP", reason=f"Conflict policy=skip: user has existing role '{existing.role}'"
        )

    elif conflict_policy == "override":
        return "UPDATE", ChangeRecord(
            email=email, org=org_k8s_name,
            old_role=existing.role, new_role=new_role,
            action="UPDATE", reason=f"Conflict policy=override: updating from '{existing.role}' to '{new_role}'"
        )

    elif conflict_policy == "escalate":
        if new_privilege > existing_privilege:
            return "UPDATE", ChangeRecord(
                email=email, org=org_k8s_name,
                old_role=existing.role, new_role=new_role,
                action="ESCALATE", reason=f"Privilege escalation approved: '{existing.role}' -> '{new_role}'"
            )
        else:
            return "SKIP", ChangeRecord(
                email=email, org=org_k8s_name,
                old_role=existing.role, new_role=new_role,
                action="SKIP",
                reason=f"Conflict policy=escalate: new role '{new_role}' is not higher than existing '{existing.role}'"
            )

    return "SKIP", ChangeRecord(
        email=email, org=org_k8s_name,
        old_role=existing.role, new_role=new_role,
        action="SKIP", reason="Unknown conflict policy"
    )

# ============================================================================
# Main bulk assignment logic
# ============================================================================

def apply_bulk_rbac(
    users: List[str],
    orgs: List[str],
    role: str,
    conflict_policy: str,
    dry_run: bool = True,
) -> Tuple[Dict[str, Dict[str, MemberRecord]], List[ChangeRecord]]:
    """
    Apply bulk RBAC assignments.
    Returns: (updated_members_by_org, changes)
    """
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Valid: {', '.join(VALID_ROLES)}")
    if conflict_policy not in VALID_CONFLICT_POLICIES:
        raise ValueError(f"Invalid conflict policy '{conflict_policy}'. Valid: {', '.join(VALID_CONFLICT_POLICIES)}")

    changes: List[ChangeRecord] = []
    org_member_states: Dict[str, Dict[str, MemberRecord]] = {}

    for org_name in orgs:
        org_k8s_name = org_name_to_k8s_name(org_name)
        current_members = load_current_members(org_k8s_name)

        # Copy current state
        import copy
        updated_members = copy.deepcopy(current_members)

        for email in users:
            email = email.strip()
            if not email:
                continue

            if email in current_members:
                # Conflict resolution
                action, change = resolve_conflict(
                    email=email,
                    org_k8s_name=org_k8s_name,
                    new_role=role,
                    existing=current_members[email],
                    conflict_policy=conflict_policy,
                )
                changes.append(change)
                if action in ("UPDATE", "ESCALATE"):
                    updated_members[email] = MemberRecord(
                        email=email, role=role,
                        org_k8s_name=org_k8s_name, source="manual"
                    )
            else:
                # New member
                updated_members[email] = MemberRecord(
                    email=email, role=role,
                    org_k8s_name=org_k8s_name, source="manual"
                )
                changes.append(ChangeRecord(
                    email=email, org=org_k8s_name,
                    old_role=None, new_role=role,
                    action="ADD", reason="New member added"
                ))

        org_member_states[org_k8s_name] = updated_members

        # Write files
        if not dry_run:
            write_members_file(org_k8s_name, updated_members, dry_run=False)

    return org_member_states, changes

# ============================================================================
# Display helpers
# ============================================================================

def print_preview_matrix(
    users: List[str],
    orgs: List[str],
    changes: List[ChangeRecord],
    all_states: Dict[str, Dict[str, MemberRecord]]
):
    """Print a text table showing user roles per org before and after."""
    print()
    print("BULK RBAC PREVIEW MATRIX")
    print("=" * 80)

    org_k8s_names = [org_name_to_k8s_name(org) for org in orgs]
    col_width = max(20, max(len(o) for o in org_k8s_names) + 2)
    email_width = max(30, max(len(u) for u in users) + 2) if users else 30

    # Header
    header = f"{'User Email':<{email_width}}"
    for org in org_k8s_names:
        header += f"{'| ' + org:<{col_width}}"
    print(header)
    print("-" * len(header))

    # Build change lookup
    change_map: Dict[Tuple[str, str], ChangeRecord] = {}
    for change in changes:
        change_map[(change.email, change.org)] = change

    for email in users:
        email = email.strip()
        row = f"{email:<{email_width}}"
        for org_k8s_name in org_k8s_names:
            change = change_map.get((email, org_k8s_name))
            if change:
                if change.action == "ADD":
                    cell = f"-> {change.new_role}"
                elif change.action in ("UPDATE", "ESCALATE"):
                    cell = f"{change.old_role}->{change.new_role}"
                elif change.action == "SKIP":
                    cell = f"[{change.old_role}]SKIP"
                else:
                    cell = change.action
            else:
                # Check if user exists in org
                state = all_states.get(org_k8s_name, {})
                member = state.get(email)
                cell = f"[{member.role}]" if member else "N/A"
            row += f"| {cell:<{col_width-2}}"
        print(row)

    print("=" * 80)

def print_change_report(changes: List[ChangeRecord]):
    """Print a detailed list of all changes."""
    print()
    print("CHANGE REPORT")
    print("=" * 80)

    by_action: Dict[str, List[ChangeRecord]] = {}
    for change in changes:
        by_action.setdefault(change.action, []).append(change)

    for action in ["ADD", "UPDATE", "ESCALATE", "SKIP", "ESCALATE_BLOCKED"]:
        action_changes = by_action.get(action, [])
        if not action_changes:
            continue
        print(f"\n{action} ({len(action_changes)}):")
        print("-" * 60)
        for c in action_changes:
            old_str = f"{c.old_role} -> " if c.old_role else "NEW -> "
            print(f"  [{c.org}] {c.email}: {old_str}{c.new_role}")
            print(f"    Reason: {c.reason}")

    print()
    totals = {action: len(items) for action, items in by_action.items()}
    print("Summary:")
    for action, count in totals.items():
        print(f"  {action}: {count}")
    print("=" * 80)

def print_org_state(org_k8s_name: str):
    """Display the current RBAC state for an org."""
    members = load_current_members(org_k8s_name)
    if not members:
        print(f"\nNo members found for org: {org_k8s_name}")
        return

    print(f"\nCurrent RBAC State: {org_k8s_name}")
    print("=" * 60)
    print(f"{'Email':<40} {'Role':<10} {'Source'}")
    print("-" * 60)
    for email in sorted(members.keys()):
        m = members[email]
        print(f"{email:<40} {m.role:<10} {m.source}")
    print(f"\nTotal: {len(members)} members")
    admin_count = sum(1 for m in members.values() if m.role == "Admin")
    print(f"Admins: {admin_count}")
    print("=" * 60)

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Bulk RBAC management for Grafana organizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview adding users as Editors (dry-run)
  python bulk-rbac.py --users user1@vpbank.com,user2@vpbank.com \\
    --orgs ORG-Platform-2025,ORG-Payments-2025 --role Editor --conflict-policy skip

  # Apply changes
  python bulk-rbac.py --users user1@vpbank.com --orgs ORG-Platform-2025 \\
    --role Admin --conflict-policy override --apply

  # Allow privilege escalation only
  python bulk-rbac.py --users user1@vpbank.com --orgs ORG-Platform-2025 \\
    --role Admin --conflict-policy escalate --apply

  # Show current state
  python bulk-rbac.py --show-state --orgs ORG-Platform-2025
        """
    )
    parser.add_argument("--users", help="Comma-separated list of user emails")
    parser.add_argument("--orgs", help="Comma-separated list of org names (e.g., ORG-Platform-2025)")
    parser.add_argument("--role", choices=VALID_ROLES, help="Role to assign: Viewer, Editor, Admin")
    parser.add_argument("--conflict-policy", choices=VALID_CONFLICT_POLICIES, default="skip",
                        help="How to handle conflicts: skip (keep existing), override (force new), escalate (allow upgrade only)")
    parser.add_argument("--apply", action="store_true",
                        help="Apply changes by writing members.yaml files (default: dry-run preview)")
    parser.add_argument("--show-state", action="store_true",
                        help="Show current RBAC state for specified orgs")
    parser.add_argument("--show-all-state", action="store_true",
                        help="Show current RBAC state for all orgs")
    args = parser.parse_args()

    # Show state mode
    if args.show_all_state:
        all_members = load_all_org_members()
        if not all_members:
            print("No org members found in repository")
            return
        for org_k8s_name in sorted(all_members.keys()):
            print_org_state(org_k8s_name)
        return

    if args.show_state:
        if not args.orgs:
            print("ERROR: --orgs is required with --show-state")
            sys.exit(1)
        for org in args.orgs.split(","):
            org_k8s_name = org_name_to_k8s_name(org.strip())
            print_org_state(org_k8s_name)
        return

    # Validation
    if not args.users:
        print("ERROR: --users is required")
        parser.print_help()
        sys.exit(1)
    if not args.orgs:
        print("ERROR: --orgs is required")
        parser.print_help()
        sys.exit(1)
    if not args.role:
        print("ERROR: --role is required")
        parser.print_help()
        sys.exit(1)

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    dry_run = not args.apply

    # Validate emails
    email_re = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    invalid_emails = [u for u in users if not email_re.match(u)]
    if invalid_emails:
        print(f"ERROR: Invalid email addresses: {', '.join(invalid_emails)}")
        sys.exit(1)

    print(f"\nBulk RBAC Operation")
    print(f"  Users:           {len(users)}")
    print(f"  Orgs:            {len(orgs)}")
    print(f"  Role:            {args.role}")
    print(f"  Conflict policy: {args.conflict_policy}")
    print(f"  Mode:            {'APPLY' if not dry_run else 'DRY RUN (preview only)'}")

    try:
        all_states, changes = apply_bulk_rbac(
            users=users,
            orgs=orgs,
            role=args.role,
            conflict_policy=args.conflict_policy,
            dry_run=dry_run,
        )
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print_preview_matrix(users, orgs, changes, all_states)
    print_change_report(changes)

    if dry_run:
        print("\nThis was a DRY RUN. Use --apply to write changes.")
    else:
        print(f"\nChanges applied. {len([c for c in changes if c.action in ('ADD','UPDATE','ESCALATE')])} members updated.")

if __name__ == "__main__":
    main()

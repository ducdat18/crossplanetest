#!/usr/bin/env python3
"""
Grafana Governance Platform - Code Generator
Generates Crossplane YAML manifests for dashboards, alerts, and organizations.

Subcommands:
  generate-dashboard  Generate a Dashboard manifest from a template
  generate-alert      Generate an AlertRule manifest + routing + folder
  generate-org        Generate org.yaml + members.yaml + all tier folders

Usage:
  python code-generator.py generate-dashboard --template TPL-DASH-001 --name PLAT-api-latency-v1.0 --datasource-uid DS-prom-platform-metrics-prod --org ORG-Platform-2025

  python code-generator.py generate-alert --template TPL-ALERT-001 --name PLAT-SVC-CRIT-my-service-errors --interval 1m --org ORG-Platform-2025

  python code-generator.py generate-org --org-name Platform --year 2025 --org-code PLAT --output-dir ./orgs/
"""

import argparse
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML")
    sys.exit(1)

# ============================================================================
# Paths
# ============================================================================

REPO_ROOT = Path(__file__).parent.parent
TEMPLATES_DIR = REPO_ROOT / "templates"
SCHEMAS_DIR = REPO_ROOT / "schemas"
CONFIG_DIR = REPO_ROOT / "config"
NOC_CONFIG_PATH = CONFIG_DIR / "noc" / "noc-default-members.yaml"

# ============================================================================
# Naming validation helpers
# ============================================================================

NAMING_PATTERNS = {
    "dashboard": re.compile(r'^[A-Z]{2,6}-[a-z0-9-]+-v[0-9]+\.[0-9]+$'),
    "alert_rule": re.compile(r'^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$'),
    "organization": re.compile(r'^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$'),
    "datasource": re.compile(r'^DS-[a-z]+-[a-z0-9-]+-[a-z]+(-(prod|stg|dev))?$'),
}

def validate_name(name: str, pattern_key: str) -> bool:
    pattern = NAMING_PATTERNS.get(pattern_key)
    if not pattern:
        return True
    return bool(pattern.match(name))

def to_k8s_name(name: str) -> str:
    """Convert a display name to a valid Kubernetes resource name."""
    name = name.lower()
    name = re.sub(r'[^a-z0-9-]', '-', name)
    name = re.sub(r'-+', '-', name)
    name = name.strip('-')
    return name[:63]

# ============================================================================
# NOC member loading
# ============================================================================

def load_noc_members(exclude_noc: bool = False) -> List[dict]:
    """Load NOC default members from config file."""
    if exclude_noc:
        return []

    if not NOC_CONFIG_PATH.exists():
        print(f"WARNING: NOC config not found at {NOC_CONFIG_PATH}, skipping NOC members")
        return []

    try:
        with open(NOC_CONFIG_PATH) as f:
            doc = yaml.safe_load(f)
        return doc.get("spec", {}).get("members", [])
    except Exception as e:
        print(f"WARNING: Could not load NOC config: {e}")
        return []

# ============================================================================
# Routing engine integration
# ============================================================================

ROUTING_MATRIX = [
    {"tier": "ultra-rt",  "severity": "page",     "max_seconds": 30,         "folder_suffix": "UltraRealTime"},
    {"tier": "real-time", "severity": "critical",  "max_seconds": 60,         "folder_suffix": "RealTime"},
    {"tier": "nrt",       "severity": "warning",   "max_seconds": 300,        "folder_suffix": "NearRealTime"},
    {"tier": "standard",  "severity": "warning",   "max_seconds": 900,        "folder_suffix": "Standard"},
    {"tier": "degraded",  "severity": "info",      "max_seconds": 3600,       "folder_suffix": "Degraded"},
    {"tier": "trend",     "severity": "info",      "max_seconds": 86400,      "folder_suffix": "Trend"},
    {"tier": "daily",     "severity": "report",    "max_seconds": float('inf'), "folder_suffix": "Report"},
]

DURATION_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}

def parse_duration_to_seconds(duration_str: str) -> int:
    total = 0
    for value, unit in re.findall(r'(\d+)([smhd])', str(duration_str)):
        total += int(value) * DURATION_UNITS[unit]
    return total if total > 0 else 300  # default 5m

def classify_interval(interval_str: str) -> dict:
    seconds = parse_duration_to_seconds(interval_str)
    for tier in ROUTING_MATRIX:
        if seconds < tier["max_seconds"]:
            return tier
    return ROUTING_MATRIX[-1]

# ============================================================================
# Template loading
# ============================================================================

def load_template(template_type: str, template_id: str) -> Optional[dict]:
    """Load a template YAML file by template ID."""
    template_dirs = {
        "dashboard": TEMPLATES_DIR / "dashboards",
        "alert": TEMPLATES_DIR / "alerts",
    }
    search_dir = template_dirs.get(template_type)
    if not search_dir or not search_dir.exists():
        return None

    for f in search_dir.glob("*.yaml"):
        if template_id in f.name:
            with open(f) as fh:
                docs = list(yaml.safe_load_all(fh.read()))
            for doc in docs:
                if doc and isinstance(doc, dict):
                    return doc
    return None

# ============================================================================
# Dashboard generator
# ============================================================================

def generate_dashboard(
    template_id: str,
    dashboard_name: str,
    datasource_uid: str,
    org_name: str,
    folder_uid: Optional[str] = None,
    lifecycle: str = "production",
    output_path: Optional[Path] = None,
    dry_run: bool = False
) -> dict:
    """Generate a Dashboard manifest from a template."""

    # Validate naming
    if not validate_name(dashboard_name, "dashboard"):
        print(f"WARNING: Dashboard name '{dashboard_name}' does not match convention "
              f"^[A-Z]{{2,6}}-[a-z0-9-]+-v[0-9]+\\.[0-9]+$ (proceeding anyway)")

    # Load template
    template = load_template("dashboard", template_id)
    if not template:
        print(f"WARNING: Template {template_id} not found, generating minimal manifest")
        template = {}

    k8s_name = to_k8s_name(dashboard_name)
    uid = k8s_name[:40]

    # Build configJson
    base_config = {}
    if template:
        config_json_str = template.get("spec", {}).get("forProvider", {}).get("configJson", "{}")
        try:
            base_config = json.loads(config_json_str)
        except json.JSONDecodeError:
            base_config = {}

    base_config["title"] = dashboard_name
    base_config["uid"] = uid
    if "schemaVersion" not in base_config:
        base_config["schemaVersion"] = 39
    if "panels" not in base_config:
        base_config["panels"] = []

    # Substitute datasource UID in config
    config_json_str = json.dumps(base_config, indent=2)
    config_json_str = config_json_str.replace("__ds_uid__", datasource_uid)

    # Build manifest
    manifest = {
        "apiVersion": "oss.grafana.crossplane.io/v1alpha1",
        "kind": "Dashboard",
        "metadata": {
            "name": k8s_name,
            "labels": {
                "template_id": template_id,
                "lifecycle": lifecycle,
            },
            "annotations": {
                "governance.grafana.io/dashboard-name": dashboard_name,
                "governance.grafana.io/template-id": template_id,
                "governance.grafana.io/org": org_name,
                "governance.grafana.io/generated-by": "code-generator.py",
                "governance.grafana.io/generated-date": str(date.today()),
            }
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "deletionPolicy": "Delete",
            "forProvider": {
                "overwrite": True,
                "message": f"Generated from {template_id} - {dashboard_name}",
                "configJson": config_json_str,
            }
        }
    }

    if folder_uid:
        manifest["spec"]["forProvider"]["folder"] = folder_uid

    if not dry_run and output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  Written: {output_path}")

    return manifest

# ============================================================================
# Alert generator
# ============================================================================

def generate_alert(
    template_id: str,
    alert_name: str,
    interval: str,
    org_name: str,
    datasource_uid: str,
    job_label: str = ".*",
    output_dir: Optional[Path] = None,
    dry_run: bool = False
) -> dict:
    """Generate an AlertRule manifest from a template."""

    # Validate naming
    if not validate_name(alert_name, "alert_rule"):
        print(f"WARNING: Alert name '{alert_name}' does not match convention "
              f"^[A-Z]{{2,6}}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$ (proceeding anyway)")

    # Classify routing
    routing = classify_interval(interval)
    tier = routing["tier"]
    severity = routing["severity"]
    folder_suffix = routing["folder_suffix"]

    # Determine org code and folder UID
    org_code_match = re.match(r'^ORG-([A-Z][a-zA-Z0-9]+)-[0-9]{4}$', org_name)
    if org_code_match:
        org_name_part = org_code_match.group(1)
        upper_chars = ''.join(c for c in org_name_part if c.isupper())
        org_code = upper_chars[:4] if len(upper_chars) >= 2 else org_name_part[:4].upper()
    else:
        org_code = "ORG"

    org_code_lower = org_code.lower()
    folder_uid = f"{org_code_lower}-{folder_suffix.lower()}"
    org_k8s_name = "org-" + org_name[4:].lower().replace(" ", "-") if org_name.startswith("ORG-") else to_k8s_name(org_name)

    # Load template
    template = load_template("alert", template_id)

    k8s_name = to_k8s_name(alert_name)

    # Build data queries from template or minimal
    data_queries = []
    if template:
        tmpl_data = template.get("spec", {}).get("forProvider", {}).get("data", [])
        import copy
        data_queries = copy.deepcopy(tmpl_data)
        # Substitute placeholders
        for item in data_queries:
            model = item.get("model", {})
            expr = model.get("expr", "")
            if expr:
                expr = expr.replace("__ds_uid__", datasource_uid)
                expr = expr.replace("__job__", job_label)
                model["expr"] = expr
            if item.get("datasourceUid") == "__ds_uid__":
                item["datasourceUid"] = datasource_uid
    else:
        # Minimal data definition
        data_queries = [
            {
                "refId": "A",
                "queryType": "",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": datasource_uid,
                "model": {
                    "expr": f'up{{job="{job_label}"}}',
                    "refId": "A",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                }
            },
            {
                "refId": "B",
                "queryType": "",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [{
                        "evaluator": {"params": [0], "type": "gt"},
                        "operator": {"type": "and"},
                        "query": {"params": ["A"]},
                        "reducer": {"params": [], "type": "last"},
                        "type": "query"
                    }],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "hide": False,
                    "refId": "B",
                    "type": "threshold"
                }
            }
        ]

    manifest = {
        "apiVersion": "oss.grafana.crossplane.io/v1alpha1",
        "kind": "AlertRule",
        "metadata": {
            "name": k8s_name,
            "labels": {
                "org": org_k8s_name,
                "template_id": template_id,
                "tier": tier,
                "severity": severity,
            },
            "annotations": {
                "governance.grafana.io/template-id": template_id,
                "governance.grafana.io/org": org_name,
                "governance.grafana.io/generated-by": "code-generator.py",
                "governance.grafana.io/generated-date": str(date.today()),
            }
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "deletionPolicy": "Delete",
            "forProvider": {
                "name": alert_name,
                "folderUid": folder_uid,
                "ruleGroup": f"{tier}-alerts",
                "noDataState": "NoData",
                "execErrState": "Error",
                "for": interval,
                "isPaused": False,
                "annotations": {
                    "summary": f"Alert: {alert_name}",
                    "description": f"Generated from template {template_id}. Configure this annotation with a meaningful description.",
                    "runbook_url": f"https://wiki.vpbank.com.vn/runbooks/{k8s_name}",
                },
                "labels": {
                    "tier": tier,
                    "severity": severity,
                    "template_id": template_id,
                    "org": org_name,
                },
                "data": data_queries,
            }
        }
    }

    # Copy annotations from template if available
    if template:
        tmpl_annotations = template.get("spec", {}).get("forProvider", {}).get("annotations", {})
        if tmpl_annotations.get("runbook_url"):
            manifest["spec"]["forProvider"]["annotations"]["runbook_url"] = tmpl_annotations["runbook_url"]
        if tmpl_annotations.get("summary"):
            manifest["spec"]["forProvider"]["annotations"]["summary"] = tmpl_annotations["summary"].replace("{{ $labels.job }}", job_label)

    # Generate folder manifest
    folder_manifest = {
        "apiVersion": "oss.grafana.crossplane.io/v1alpha1",
        "kind": "Folder",
        "metadata": {
            "name": f"{org_code_lower}-{folder_suffix.lower()}-folder",
            "labels": {"org": org_k8s_name, "tier": tier, "managed-by": "code-generator"},
            "annotations": {
                "governance.grafana.io/tier": tier,
                "governance.grafana.io/generated-by": "code-generator.py",
            }
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "deletionPolicy": "Orphan",
            "forProvider": {
                "title": f"{org_code}/{folder_suffix}",
                "uid": folder_uid,
                "orgIdRef": {"name": org_k8s_name}
            }
        }
    }

    if not dry_run and output_dir:
        # Write folder manifest if not exists
        folder_output = output_dir / "folders" / f"{tier}-folder.yaml"
        if not folder_output.exists():
            folder_output.parent.mkdir(parents=True, exist_ok=True)
            with open(folder_output, 'w') as f:
                yaml.dump(folder_manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"  Created folder: {folder_output}")
        else:
            print(f"  Folder exists: {folder_output} (skipping)")

        # Write alert manifest
        alert_output = output_dir / "alerts" / f"{k8s_name}.yaml"
        alert_output.parent.mkdir(parents=True, exist_ok=True)
        with open(alert_output, 'w') as f:
            yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  Written alert: {alert_output}")

    return manifest

# ============================================================================
# Org generator
# ============================================================================

TIER_FOLDERS = [
    {"tier": "real-time",  "folder_suffix": "RealTime",     "uid_suffix": "realtime"},
    {"tier": "nrt",        "folder_suffix": "NearRealTime",  "uid_suffix": "nearrealtime"},
    {"tier": "standard",   "folder_suffix": "Standard",      "uid_suffix": "standard"},
    {"tier": "degraded",   "folder_suffix": "Degraded",      "uid_suffix": "degraded"},
    {"tier": "daily",      "folder_suffix": "Report",        "uid_suffix": "report"},
]

def generate_org(
    org_name: str,
    year: int,
    org_code: str,
    department: str = "engineering",
    exclude_noc: bool = False,
    role_overrides: Optional[Dict[str, str]] = None,
    extra_members: Optional[List[dict]] = None,
    output_dir: Optional[Path] = None,
    dry_run: bool = False
) -> dict:
    """Generate a complete org directory: org.yaml, members.yaml, and all tier folders."""

    full_org_name = f"ORG-{org_name}-{year}"
    org_k8s_name = f"org-{org_name.lower()}-{year}"
    org_code_upper = org_code.upper()
    org_code_lower = org_code.lower()

    # Validate org name
    if not re.match(r'^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$', full_org_name):
        print(f"WARNING: Generated org name '{full_org_name}' may not match convention")

    # Generate org.yaml
    org_manifest = {
        "apiVersion": "grafana.crossplane.io/v1beta1",
        "kind": "Organization",
        "metadata": {
            "name": org_k8s_name,
            "labels": {
                "department": department,
                "lifecycle": "active",
                "noc-managed": "false" if exclude_noc else "true",
                "year": str(year),
            },
            "annotations": {
                "governance.grafana.io/org-name": full_org_name,
                "governance.grafana.io/admin-team": f"TEAM-{org_code_upper}-admin",
                "governance.grafana.io/created-date": str(date.today()),
                "governance.grafana.io/generated-by": "code-generator.py",
            }
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "deletionPolicy": "Orphan",
            "forProvider": {"name": full_org_name}
        }
    }

    # Generate members
    noc_members = load_noc_members(exclude_noc)
    member_manifests = []
    noc_role_overrides = role_overrides or {}

    for noc_member in noc_members:
        email = noc_member["email"]
        role = noc_role_overrides.get(email, noc_member.get("grafanaRole", "Viewer"))
        email_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
        k8s_name = to_k8s_name(f"{org_k8s_name}-{email_slug}")[:63]

        member_manifests.append({
            "apiVersion": "grafana.crossplane.io/v1beta1",
            "kind": "OrgMember",
            "metadata": {
                "name": k8s_name,
                "labels": {
                    "org": org_k8s_name,
                    "source": "noc-auto-injected",
                    "role-group": "noc",
                },
                "annotations": {
                    "governance.grafana.io/injected-from": "config/noc/noc-default-members.yaml",
                }
            },
            "spec": {
                "providerConfigRef": {"name": "default"},
                "forProvider": {
                    "email": email,
                    "role": role,
                    "orgIdRef": {"name": org_k8s_name}
                }
            }
        })

    # Add extra members
    for extra in (extra_members or []):
        email = extra["email"]
        role = extra.get("role", "Viewer")
        email_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
        k8s_name = to_k8s_name(f"{org_k8s_name}-{email_slug}")[:63]

        member_manifests.append({
            "apiVersion": "grafana.crossplane.io/v1beta1",
            "kind": "OrgMember",
            "metadata": {
                "name": k8s_name,
                "labels": {"org": org_k8s_name, "source": "manual", "role-group": "team"},
            },
            "spec": {
                "providerConfigRef": {"name": "default"},
                "forProvider": {
                    "email": email,
                    "role": role,
                    "orgIdRef": {"name": org_k8s_name}
                }
            }
        })

    # Generate tier folders
    folder_manifests = []
    for folder_def in TIER_FOLDERS:
        folder_manifests.append({
            "apiVersion": "oss.grafana.crossplane.io/v1alpha1",
            "kind": "Folder",
            "metadata": {
                "name": f"{org_code_lower}-{folder_def['uid_suffix']}-folder",
                "labels": {
                    "org": org_k8s_name,
                    "tier": folder_def["tier"],
                    "managed-by": "code-generator",
                },
                "annotations": {
                    "governance.grafana.io/tier": folder_def["tier"],
                    "governance.grafana.io/generated-by": "code-generator.py",
                }
            },
            "spec": {
                "providerConfigRef": {"name": "default"},
                "deletionPolicy": "Orphan",
                "forProvider": {
                    "title": f"{org_code_upper}/{folder_def['folder_suffix']}",
                    "uid": f"{org_code_lower}-{folder_def['uid_suffix']}",
                    "orgIdRef": {"name": org_k8s_name}
                }
            }
        })

    if not dry_run and output_dir:
        org_output_dir = output_dir / org_k8s_name
        org_output_dir.mkdir(parents=True, exist_ok=True)

        # Write org.yaml
        org_file = org_output_dir / "org.yaml"
        with open(org_file, 'w') as f:
            yaml.dump(org_manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  Written: {org_file}")

        # Write members.yaml (multi-document)
        members_file = org_output_dir / "members.yaml"
        with open(members_file, 'w') as f:
            f.write(f"# OrgMember resources for {full_org_name}\n")
            f.write(f"# Generated by code-generator.py on {date.today()}\n")
            for i, member in enumerate(member_manifests):
                if i > 0:
                    f.write("---\n")
                yaml.dump(member, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  Written: {members_file}")

        # Write folder files
        folders_dir = org_output_dir / "folders"
        folders_dir.mkdir(exist_ok=True)
        for folder_def, folder_manifest in zip(TIER_FOLDERS, folder_manifests):
            folder_file = folders_dir / f"{folder_def['uid_suffix']}-folder.yaml"
            with open(folder_file, 'w') as f:
                yaml.dump(folder_manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"  Written: {folder_file}")

    return {
        "org": org_manifest,
        "members": member_manifests,
        "folders": folder_manifests,
        "org_name": full_org_name,
        "k8s_name": org_k8s_name,
    }

# ============================================================================
# CLI
# ============================================================================

def cmd_generate_dashboard(args):
    print(f"\nGenerating Dashboard manifest...")
    print(f"  Template:    {args.template}")
    print(f"  Name:        {args.name}")
    print(f"  Datasource:  {args.datasource_uid}")
    print(f"  Org:         {args.org}")

    output_path = None
    if args.output_dir:
        k8s_name = to_k8s_name(args.name)
        output_path = Path(args.output_dir) / f"{k8s_name}.yaml"

    manifest = generate_dashboard(
        template_id=args.template,
        dashboard_name=args.name,
        datasource_uid=args.datasource_uid,
        org_name=args.org,
        folder_uid=args.folder_uid,
        lifecycle=getattr(args, 'lifecycle', 'production'),
        output_path=output_path,
        dry_run=args.dry_run,
    )

    if args.dry_run or not args.output_dir:
        print("\nGenerated manifest (dry-run):")
        print("-" * 60)
        print(yaml.dump(manifest, default_flow_style=False, allow_unicode=True, sort_keys=False))

def cmd_generate_alert(args):
    print(f"\nGenerating AlertRule manifest...")
    print(f"  Template:    {args.template}")
    print(f"  Name:        {args.name}")
    print(f"  Interval:    {args.interval}")
    print(f"  Org:         {args.org}")

    routing = classify_interval(args.interval)
    print(f"  Routed to:   tier={routing['tier']}, severity={routing['severity']}, folder={routing['folder_suffix']}")

    output_dir = Path(args.output_dir) if args.output_dir else None

    manifest = generate_alert(
        template_id=args.template,
        alert_name=args.name,
        interval=args.interval,
        org_name=args.org,
        datasource_uid=getattr(args, 'datasource_uid', 'DS-prom-platform-metrics-prod'),
        job_label=getattr(args, 'job', '.*'),
        output_dir=output_dir,
        dry_run=args.dry_run,
    )

    if args.dry_run or not args.output_dir:
        print("\nGenerated manifest (dry-run):")
        print("-" * 60)
        print(yaml.dump(manifest, default_flow_style=False, allow_unicode=True, sort_keys=False))

def cmd_generate_org(args):
    print(f"\nGenerating Organization structure...")
    print(f"  Org Name:    {args.org_name}")
    print(f"  Year:        {args.year}")
    print(f"  Org Code:    {args.org_code}")
    print(f"  NOC:         {'excluded' if args.exclude_noc else 'included'}")

    output_dir = Path(args.output_dir) if args.output_dir else None

    # Parse role overrides: "email:role,email:role"
    role_overrides = {}
    if getattr(args, 'role_overrides', None):
        for override in args.role_overrides.split(","):
            if ":" in override:
                email, role = override.split(":", 1)
                role_overrides[email.strip()] = role.strip()

    # Parse extra members: "email:role,email:role"
    extra_members = []
    if getattr(args, 'members', None):
        for member_str in args.members.split(","):
            if ":" in member_str:
                email, role = member_str.split(":", 1)
                extra_members.append({"email": email.strip(), "role": role.strip()})

    result = generate_org(
        org_name=args.org_name,
        year=int(args.year),
        org_code=args.org_code,
        department=getattr(args, 'department', 'engineering'),
        exclude_noc=args.exclude_noc,
        role_overrides=role_overrides,
        extra_members=extra_members,
        output_dir=output_dir,
        dry_run=args.dry_run,
    )

    if args.dry_run or not args.output_dir:
        print(f"\nWould create: {result['org_name']} ({result['k8s_name']})")
        print(f"Members: {len(result['members'])} (including {'no' if args.exclude_noc else len([m for m in result['members'] if 'noc-auto-injected' in str(m.get('metadata',{}).get('labels',{}).get('source',''))])} NOC)")
        print(f"Folders: {len(result['folders'])} tier folders")
        print("\nOrg manifest (dry-run):")
        print("-" * 60)
        print(yaml.dump(result["org"], default_flow_style=False, allow_unicode=True, sort_keys=False))

def main():
    parser = argparse.ArgumentParser(
        description="Generate Crossplane Grafana manifests for governance platform",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be generated without writing files")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-dashboard
    dash_parser = subparsers.add_parser("generate-dashboard", help="Generate a Dashboard manifest")
    dash_parser.add_argument("--template", required=True, help="Template ID, e.g., TPL-DASH-001")
    dash_parser.add_argument("--name", required=True, help="Dashboard name following convention, e.g., PLAT-api-latency-v1.0")
    dash_parser.add_argument("--datasource-uid", required=True, help="Prometheus datasource UID")
    dash_parser.add_argument("--org", required=True, help="Organization name, e.g., ORG-Platform-2025")
    dash_parser.add_argument("--folder-uid", help="Target folder UID")
    dash_parser.add_argument("--lifecycle", default="production", choices=["dev","staging","production","deprecated"])
    dash_parser.add_argument("--output-dir", help="Output directory for the manifest")
    dash_parser.set_defaults(func=cmd_generate_dashboard)

    # generate-alert
    alert_parser = subparsers.add_parser("generate-alert", help="Generate an AlertRule manifest")
    alert_parser.add_argument("--template", required=True, help="Template ID, e.g., TPL-ALERT-001")
    alert_parser.add_argument("--name", required=True, help="Alert rule name following convention, e.g., PLAT-SVC-CRIT-high-error-rate")
    alert_parser.add_argument("--interval", required=True, help="Alert interval/duration, e.g., 5m, 30s, 1h")
    alert_parser.add_argument("--org", required=True, help="Organization name, e.g., ORG-Platform-2025")
    alert_parser.add_argument("--datasource-uid", default="DS-prom-platform-metrics-prod", help="Prometheus datasource UID")
    alert_parser.add_argument("--job", default=".*", help="Prometheus job label selector")
    alert_parser.add_argument("--output-dir", help="Output directory for the manifest")
    alert_parser.set_defaults(func=cmd_generate_alert)

    # generate-org
    org_parser = subparsers.add_parser("generate-org", help="Generate a complete org structure")
    org_parser.add_argument("--org-name", required=True, help="Organization name part, e.g., Platform (will create ORG-Platform-YEAR)")
    org_parser.add_argument("--year", required=True, help="Year, e.g., 2025")
    org_parser.add_argument("--org-code", required=True, help="Short org code, e.g., PLAT")
    org_parser.add_argument("--department", default="engineering", help="Department label")
    org_parser.add_argument("--exclude-noc", action="store_true", help="Exclude NOC default members")
    org_parser.add_argument("--role-overrides", help="Override NOC roles: 'noc-lead@vpbank.com.vn:Editor'")
    org_parser.add_argument("--members", help="Additional members: 'user@vpbank.com.vn:Editor,user2@vpbank.com.vn:Viewer'")
    org_parser.add_argument("--output-dir", help="Parent output directory (org subdir will be created)")
    org_parser.set_defaults(func=cmd_generate_org)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

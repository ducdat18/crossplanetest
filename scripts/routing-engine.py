#!/usr/bin/env python3
"""
Grafana Governance Platform - Alert Routing Engine
Classifies AlertRule manifests into routing tiers based on the 'for' interval
and generates appropriate folder manifests and labels.

Routing Matrix:
  < 30s    → ultra-rt   | page     | PagerDuty Immediate
  30s–1m   → real-time  | critical | PagerDuty + Slack #alerts-critical
  1m–5m    → nrt        | warning  | Slack #alerts-warning
  5m–15m   → standard   | warning  | Slack #alerts-standard
  15m–1h   → degraded   | info     | Slack #alerts-info
  1h–24h   → trend      | info     | Email digest hourly
  >=24h    → daily      | report   | Email report daily

Usage:
  python routing-engine.py --alert-file path/to/alert.yaml --org ORG-Platform-2025
  python routing-engine.py --alert-file path/to/alert.yaml --org ORG-Platform-2025 --output-dir ./orgs/org-platform-2025/
  python routing-engine.py --interval 5m
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML")
    sys.exit(1)

# ============================================================================
# Routing Matrix Definition
# ============================================================================

ROUTING_MATRIX = [
    {
        "tier": "ultra-rt",
        "display_name": "Ultra-Real-time",
        "severity": "page",
        "max_seconds": 30,        # < 30s
        "folder_suffix": "UltraRealTime",
        "notification": {
            "channels": ["pagerduty-immediate"],
            "pagerduty": True,
            "slack": None,
            "email": None,
            "urgency": "high"
        }
    },
    {
        "tier": "real-time",
        "display_name": "Real-time",
        "severity": "critical",
        "max_seconds": 60,        # 30s - 1m
        "folder_suffix": "RealTime",
        "notification": {
            "channels": ["pagerduty", "slack-alerts-critical"],
            "pagerduty": True,
            "slack": "#alerts-critical",
            "email": None,
            "urgency": "high"
        }
    },
    {
        "tier": "nrt",
        "display_name": "Near-Real-time",
        "severity": "warning",
        "max_seconds": 300,       # 1m - 5m
        "folder_suffix": "NearRealTime",
        "notification": {
            "channels": ["slack-alerts-warning"],
            "pagerduty": False,
            "slack": "#alerts-warning",
            "email": None,
            "urgency": "medium"
        }
    },
    {
        "tier": "standard",
        "display_name": "Standard",
        "severity": "warning",
        "max_seconds": 900,       # 5m - 15m
        "folder_suffix": "Standard",
        "notification": {
            "channels": ["slack-alerts-standard"],
            "pagerduty": False,
            "slack": "#alerts-standard",
            "email": None,
            "urgency": "medium"
        }
    },
    {
        "tier": "degraded",
        "display_name": "Degraded",
        "severity": "info",
        "max_seconds": 3600,      # 15m - 1h
        "folder_suffix": "Degraded",
        "notification": {
            "channels": ["slack-alerts-info"],
            "pagerduty": False,
            "slack": "#alerts-info",
            "email": None,
            "urgency": "low"
        }
    },
    {
        "tier": "trend",
        "display_name": "Trend",
        "severity": "info",
        "max_seconds": 86400,     # 1h - 24h
        "folder_suffix": "Trend",
        "notification": {
            "channels": ["email-digest-hourly"],
            "pagerduty": False,
            "slack": None,
            "email": "digest-hourly",
            "urgency": "low"
        }
    },
    {
        "tier": "daily",
        "display_name": "Daily Report",
        "severity": "report",
        "max_seconds": float('inf'),  # >= 24h
        "folder_suffix": "Report",
        "notification": {
            "channels": ["email-report-daily"],
            "pagerduty": False,
            "slack": None,
            "email": "report-daily",
            "urgency": "none"
        }
    }
]

# ============================================================================
# Duration parsing
# ============================================================================

DURATION_UNITS = {
    's': 1,
    'm': 60,
    'h': 3600,
    'd': 86400,
}

def parse_duration(duration_str: str) -> int:
    """Parse a duration string like '5m', '30s', '1h', '2h30m' into seconds."""
    if not duration_str:
        raise ValueError("Empty duration string")

    duration_str = str(duration_str).strip()
    total_seconds = 0
    pattern = re.compile(r'(\d+)([smhd])')
    matches = pattern.findall(duration_str)

    if not matches:
        raise ValueError(f"Cannot parse duration: '{duration_str}'. Expected format: 30s, 5m, 1h, 24h")

    for value, unit in matches:
        total_seconds += int(value) * DURATION_UNITS[unit]

    return total_seconds

def seconds_to_human(seconds: int) -> str:
    """Convert seconds to human-readable duration string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        mins = seconds // 60
        secs = seconds % 60
        if secs:
            return f"{mins}m{secs}s"
        return f"{mins}m"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        if mins:
            return f"{hours}h{mins}m"
        return f"{hours}h"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        if hours:
            return f"{days}d{hours}h"
        return f"{days}d"

# ============================================================================
# Routing classification
# ============================================================================

def classify_interval(seconds: int) -> dict:
    """Classify an interval in seconds into the appropriate routing tier."""
    for tier_def in ROUTING_MATRIX:
        if seconds < tier_def["max_seconds"]:
            return tier_def
    # >= 24h falls into daily
    return ROUTING_MATRIX[-1]

def get_routing_for_interval(interval_str: str) -> dict:
    """Get full routing classification for a duration string."""
    seconds = parse_duration(interval_str)
    tier = classify_interval(seconds)
    return {
        "input_interval": interval_str,
        "seconds": seconds,
        "tier": tier["tier"],
        "display_name": tier["display_name"],
        "severity": tier["severity"],
        "folder_suffix": tier["folder_suffix"],
        "notification": tier["notification"],
    }

# ============================================================================
# Folder manifest generation
# ============================================================================

def org_name_to_code(org_name: str) -> str:
    """Extract org code from org name like 'ORG-Platform-2025' -> 'PLAT'."""
    # Try to extract meaningful abbreviation
    match = re.match(r'^ORG-([A-Z][a-zA-Z0-9]+)-[0-9]{4}$', org_name)
    if match:
        name_part = match.group(1)
        # Return first 4 uppercase chars or full name if short
        upper_chars = ''.join(c for c in name_part if c.isupper())
        if len(upper_chars) >= 2:
            return upper_chars[:4]
        return name_part[:4].upper()
    return "ORG"

def generate_folder_manifest(org_name: str, org_k8s_name: str, routing: dict) -> dict:
    """Generate a Folder Crossplane manifest for the given org and routing tier."""
    org_code = org_name_to_code(org_name)
    org_code_lower = org_code.lower()
    folder_suffix = routing["folder_suffix"]
    folder_title = f"{org_code}/{folder_suffix}"
    folder_uid = f"{org_code_lower}-{folder_suffix.lower()}"
    k8s_name = f"{org_code_lower}-{folder_suffix.lower()}-folder"

    return {
        "apiVersion": "oss.grafana.crossplane.io/v1alpha1",
        "kind": "Folder",
        "metadata": {
            "name": k8s_name,
            "labels": {
                "org": org_k8s_name,
                "tier": routing["tier"],
                "managed-by": "routing-engine",
            },
            "annotations": {
                "governance.grafana.io/tier": routing["tier"],
                "governance.grafana.io/severity": routing["severity"],
                "governance.grafana.io/notification": str(routing["notification"]["channels"]),
                "governance.grafana.io/generated-by": "routing-engine.py",
            }
        },
        "spec": {
            "providerConfigRef": {"name": "default"},
            "deletionPolicy": "Orphan",
            "forProvider": {
                "title": folder_title,
                "uid": folder_uid,
                "orgIdRef": {"name": org_k8s_name}
            }
        }
    }

# ============================================================================
# Alert manifest update
# ============================================================================

def apply_routing_to_alert(doc: dict, routing: dict, org_name: str) -> dict:
    """Apply routing tier labels and folder UID to an AlertRule manifest."""
    org_code = org_name_to_code(org_name)
    org_code_lower = org_code.lower()

    folder_uid = f"{org_code_lower}-{routing['folder_suffix'].lower()}"

    # Deep-copy to avoid mutation
    import copy
    doc = copy.deepcopy(doc)

    for_provider = doc.setdefault("spec", {}).setdefault("forProvider", {})
    for_provider["folderUid"] = folder_uid

    labels = for_provider.setdefault("labels", {})
    labels["tier"] = routing["tier"]
    labels["severity"] = routing["severity"]

    return doc

# ============================================================================
# File I/O
# ============================================================================

def load_alert_file(file_path: Path) -> dict:
    """Load and parse an AlertRule YAML file."""
    try:
        with open(file_path) as f:
            content = f.read()
        docs = list(yaml.safe_load_all(content))
        for doc in docs:
            if doc and doc.get("kind") == "AlertRule":
                return doc
        raise ValueError(f"No AlertRule document found in {file_path}")
    except yaml.YAMLError as e:
        raise ValueError(f"YAML parse error in {file_path}: {e}")

def write_yaml_file(data: dict, output_path: Path):
    """Write a dict to a YAML file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(f"  Written: {output_path}")

# ============================================================================
# Main logic
# ============================================================================

def process_alert_file(
    alert_file: Path,
    org_name: str,
    output_dir: Optional[Path],
    dry_run: bool
) -> dict:
    """Process an alert file, classify it, and optionally write outputs."""
    doc = load_alert_file(alert_file)
    for_duration = doc.get("spec", {}).get("forProvider", {}).get("for")

    if not for_duration:
        print("WARNING: Alert has no 'for' field, defaulting to 5m")
        for_duration = "5m"

    routing = get_routing_for_interval(str(for_duration))
    org_k8s_name = org_name.lower().replace(" ", "-")
    # Make valid k8s name from org_name
    # ORG-Platform-2025 -> org-platform-2025
    if org_name.startswith("ORG-"):
        org_k8s_name = "org-" + org_name[4:].lower().replace(" ", "-")

    folder_manifest = generate_folder_manifest(org_name, org_k8s_name, routing)
    updated_alert = apply_routing_to_alert(doc, routing, org_name)

    result = {
        "routing": routing,
        "folder_manifest": folder_manifest,
        "updated_alert": updated_alert,
        "org_k8s_name": org_k8s_name,
    }

    if output_dir and not dry_run:
        # Write folder manifest
        folder_output = output_dir / "folders" / f"{routing['tier']}-folder.yaml"
        if not folder_output.exists():
            write_yaml_file(folder_manifest, folder_output)
            print(f"  Created folder manifest: {folder_output}")
        else:
            print(f"  Folder manifest already exists: {folder_output} (skipping)")

        # Write updated alert
        alert_name = updated_alert.get("metadata", {}).get("name", "alert")
        alert_output = output_dir / "alerts" / f"{alert_name}.yaml"
        write_yaml_file(updated_alert, alert_output)
        print(f"  Written updated alert: {alert_output}")

    return result

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Classify alert intervals and generate routing manifests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Classify an alert file and show routing info
  python routing-engine.py --alert-file orgs/org-platform-2025/alerts/my-alert.yaml --org ORG-Platform-2025

  # Classify and write outputs
  python routing-engine.py --alert-file templates/alerts/TPL-ALERT-001-http-error-rate.yaml \\
    --org ORG-Platform-2025 --output-dir ./orgs/org-platform-2025/

  # Just classify an interval
  python routing-engine.py --interval 5m

  # Show full routing matrix
  python routing-engine.py --show-matrix
        """
    )
    parser.add_argument("--alert-file", type=Path, help="Path to AlertRule YAML file")
    parser.add_argument("--org", help="Organization name (e.g., ORG-Platform-2025)")
    parser.add_argument("--output-dir", type=Path, help="Output directory for generated files")
    parser.add_argument("--interval", help="Classify a specific interval (e.g., 5m, 30s, 1h)")
    parser.add_argument("--show-matrix", action="store_true", help="Display the full routing matrix")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without writing files")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    args = parser.parse_args()

    if args.show_matrix:
        print("\nALERT ROUTING MATRIX")
        print("=" * 80)
        print(f"{'Interval Range':<20} {'Tier':<12} {'Severity':<10} {'Notification'}")
        print("-" * 80)
        ranges = [
            ("< 30s",      "ultra-rt",  "page",     "PagerDuty Immediate"),
            ("30s - 1m",   "real-time", "critical", "PagerDuty + Slack #alerts-critical"),
            ("1m - 5m",    "nrt",       "warning",  "Slack #alerts-warning"),
            ("5m - 15m",   "standard",  "warning",  "Slack #alerts-standard"),
            ("15m - 1h",   "degraded",  "info",     "Slack #alerts-info"),
            ("1h - 24h",   "trend",     "info",     "Email digest hourly"),
            (">= 24h",     "daily",     "report",   "Email report daily"),
        ]
        for r in ranges:
            print(f"{r[0]:<20} {r[1]:<12} {r[2]:<10} {r[3]}")
        print("=" * 80)
        return

    if args.interval:
        try:
            routing = get_routing_for_interval(args.interval)
            if args.json:
                print(json.dumps(routing, indent=2))
            else:
                print(f"\nInterval: {args.interval} ({routing['seconds']}s)")
                print(f"  Tier:         {routing['tier']} ({routing['display_name']})")
                print(f"  Severity:     {routing['severity']}")
                print(f"  Folder:       <ORG_CODE>/{routing['folder_suffix']}")
                print(f"  Notification: {', '.join(routing['notification']['channels'])}")
                if routing['notification']['pagerduty']:
                    print("  PagerDuty:    Yes (Immediate)")
                if routing['notification']['slack']:
                    print(f"  Slack:        {routing['notification']['slack']}")
                if routing['notification']['email']:
                    print(f"  Email:        {routing['notification']['email']}")
        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        return

    if args.alert_file:
        if not args.alert_file.exists():
            print(f"ERROR: Alert file not found: {args.alert_file}")
            sys.exit(1)
        if not args.org:
            print("ERROR: --org is required when using --alert-file")
            sys.exit(1)

        try:
            result = process_alert_file(
                alert_file=args.alert_file,
                org_name=args.org,
                output_dir=args.output_dir,
                dry_run=args.dry_run
            )

            routing = result["routing"]
            folder = result["folder_manifest"]

            if args.json:
                output = {
                    "routing": routing,
                    "folder_uid": folder["spec"]["forProvider"]["uid"],
                    "folder_title": folder["spec"]["forProvider"]["title"],
                    "labels": {
                        "tier": routing["tier"],
                        "severity": routing["severity"],
                    }
                }
                print(json.dumps(output, indent=2))
            else:
                print(f"\nAlert Routing Analysis")
                print("=" * 60)
                print(f"  Alert file:   {args.alert_file}")
                print(f"  Interval:     {routing['input_interval']} ({routing['seconds']}s)")
                print(f"  Org:          {args.org}")
                print()
                print("Routing Decision:")
                print(f"  Tier:         {routing['tier']} ({routing['display_name']})")
                print(f"  Severity:     {routing['severity']}")
                print(f"  Folder UID:   {folder['spec']['forProvider']['uid']}")
                print(f"  Folder Title: {folder['spec']['forProvider']['title']}")
                print(f"  Notifications: {', '.join(routing['notification']['channels'])}")

                if args.dry_run:
                    print()
                    print("DRY RUN - Would generate:")
                    print(f"  - Folder manifest: {folder['spec']['forProvider']['uid']}")
                    print()
                    print("Folder YAML:")
                    print("-" * 60)
                    print(yaml.dump(folder, default_flow_style=False, sort_keys=False))

        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        return

    parser.print_help()

if __name__ == "__main__":
    main()

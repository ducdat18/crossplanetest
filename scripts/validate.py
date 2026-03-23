#!/usr/bin/env python3
"""
Grafana Governance Platform - Manifest Validator
Validates Crossplane YAML manifests against JSON schemas and naming conventions.

Usage:
    python validate.py --file path/to/file.yaml
    python validate.py --dir ./orgs
    python validate.py --dir . --changed-only

Exit codes:
    0 = All validations passed
    1 = One or more ERRORs found
    2 = Warnings only (no errors)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install PyYAML")
    sys.exit(1)

try:
    import jsonschema
    from jsonschema import validate as jschema_validate, ValidationError
except ImportError:
    print("ERROR: jsonschema is required. Install with: pip install jsonschema")
    sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

REPO_ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas"

NAMING_PATTERNS = {
    "dashboard": re.compile(r'^[A-Z]{2,6}-[a-z0-9-]+-v[0-9]+\.[0-9]+$'),
    "alert_rule": re.compile(r'^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$'),
    "folder": re.compile(r'^[A-Z]{2,6}/[A-Z][a-zA-Z0-9]+(/[A-Z][a-zA-Z0-9]+)*$'),
    "datasource": re.compile(r'^DS-[a-z]+-[a-z0-9-]+-[a-z]+(-(prod|stg|dev))?$'),
    "organization": re.compile(r'^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$'),
    "team": re.compile(r'^TEAM-[A-Z]{2,6}-[a-z0-9-]+$'),
    "k8s_name": re.compile(r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
}

TIER_SEVERITY_MAP = {
    "ultra-rt": "page",
    "real-time": "critical",
    "nrt": "warning",
    "standard": "warning",
    "degraded": "info",
    "trend": "info",
    "daily": "report",
}

VALID_ROLES = {"Viewer", "Editor", "Admin"}

# ============================================================================
# Result tracking
# ============================================================================

class ValidationResult:
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.infos: List[str] = []
        self.files_checked: int = 0
        self.files_passed: int = 0

    def error(self, msg: str, file: str = ""):
        prefix = f"[{file}] " if file else ""
        self.errors.append(f"ERROR: {prefix}{msg}")

    def warn(self, msg: str, file: str = ""):
        prefix = f"[{file}] " if file else ""
        self.warnings.append(f"WARN:  {prefix}{msg}")

    def info(self, msg: str, file: str = ""):
        prefix = f"[{file}] " if file else ""
        self.infos.append(f"INFO:  {prefix}{msg}")

    def has_errors(self) -> bool:
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

# ============================================================================
# Schema loading
# ============================================================================

_schema_cache: Dict[str, dict] = {}

def load_schema(schema_name: str) -> Optional[dict]:
    if schema_name in _schema_cache:
        return _schema_cache[schema_name]
    schema_path = SCHEMAS_DIR / f"{schema_name}.json"
    if schema_path.exists():
        with open(schema_path) as f:
            schema = json.load(f)
        _schema_cache[schema_name] = schema
        return schema
    return None

def get_schema_for_resource(api_version: str, kind: str) -> Optional[dict]:
    kind_map = {
        "Dashboard": "dashboard",
        "AlertRule": "alert-rule",
        "Organization": "org",
        "Folder": "folder",
    }
    schema_name = kind_map.get(kind)
    if schema_name:
        return load_schema(schema_name)
    return None

# ============================================================================
# YAML loading
# ============================================================================

def load_yaml_documents(file_path: Path) -> List[dict]:
    """Load all YAML documents from a file (handles multi-document files)."""
    docs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # Filter out comment-only lines at the start
        for doc in yaml.safe_load_all(content):
            if doc is not None:
                docs.append(doc)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML parse error: {e}")
    except Exception as e:
        raise ValueError(f"File read error: {e}")
    return docs

# ============================================================================
# Individual validators
# ============================================================================

def validate_k8s_name(name: str, result: ValidationResult, file_str: str):
    if not NAMING_PATTERNS["k8s_name"].match(name):
        result.error(
            f"metadata.name '{name}' must be a valid Kubernetes DNS label "
            f"(lowercase, 3-63 chars, alphanumeric and hyphens only)",
            file_str
        )

def validate_dashboard(doc: dict, result: ValidationResult, file_str: str):
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "")
    validate_k8s_name(name, result, file_str)

    labels = metadata.get("labels", {})
    if not labels.get("template_id"):
        result.error("metadata.labels.template_id is required (e.g., TPL-DASH-001)", file_str)
    elif not re.match(r'^TPL-DASH-[0-9]{3}$', labels["template_id"]):
        result.error(f"metadata.labels.template_id '{labels['template_id']}' must match TPL-DASH-NNN", file_str)

    lifecycle = labels.get("lifecycle")
    if not lifecycle:
        result.error("metadata.labels.lifecycle is required (dev/staging/production/deprecated)", file_str)
    elif lifecycle not in {"dev", "staging", "production", "deprecated"}:
        result.error(f"metadata.labels.lifecycle '{lifecycle}' is invalid", file_str)

    for_provider = doc.get("spec", {}).get("forProvider", {})
    config_json_str = for_provider.get("configJson")
    if not config_json_str:
        result.error("spec.forProvider.configJson is required", file_str)
        return

    try:
        config_json = json.loads(config_json_str)
    except json.JSONDecodeError as e:
        result.error(f"spec.forProvider.configJson is not valid JSON: {e}", file_str)
        return

    title = config_json.get("title", "")
    if not title:
        result.error("configJson.title is required", file_str)
    elif not NAMING_PATTERNS["dashboard"].match(title):
        result.error(
            f"configJson.title '{title}' does not match naming convention "
            f"^[A-Z]{{2,6}}-[a-z0-9-]+-v[0-9]+\\.[0-9]+$",
            file_str
        )

    if not config_json.get("uid"):
        result.error("configJson.uid is required", file_str)
    elif not re.match(r'^[a-z0-9-]{4,40}$', config_json["uid"]):
        result.error(f"configJson.uid '{config_json['uid']}' must be lowercase alphanumeric with hyphens (4-40 chars)", file_str)

    if not config_json.get("schemaVersion"):
        result.error("configJson.schemaVersion is required", file_str)

    panels = config_json.get("panels")
    if panels is None:
        result.error("configJson.panels array is required", file_str)
    elif len(panels) == 0:
        result.warn("configJson.panels is empty - dashboard has no panels", file_str)

    if not metadata.get("annotations", {}).get("governance.grafana.io/owner-team"):
        result.warn("Annotation 'governance.grafana.io/owner-team' is recommended", file_str)

def validate_alert_rule(doc: dict, result: ValidationResult, file_str: str):
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "")
    validate_k8s_name(name, result, file_str)

    for_provider = doc.get("spec", {}).get("forProvider", {})

    alert_name = for_provider.get("name", "")
    if not alert_name:
        result.error("spec.forProvider.name is required", file_str)
    elif not NAMING_PATTERNS["alert_rule"].match(alert_name):
        result.error(
            f"spec.forProvider.name '{alert_name}' does not match naming convention "
            f"^[A-Z]{{2,6}}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$",
            file_str
        )

    labels = for_provider.get("labels", {})

    tier = labels.get("tier")
    if not tier:
        result.error("spec.forProvider.labels.tier is required", file_str)
    elif tier not in TIER_SEVERITY_MAP:
        result.error(f"spec.forProvider.labels.tier '{tier}' is invalid. Valid: {', '.join(TIER_SEVERITY_MAP)}", file_str)

    severity = labels.get("severity")
    if not severity:
        result.error("spec.forProvider.labels.severity is required", file_str)
    elif severity not in {"page", "critical", "warning", "info", "report"}:
        result.error(f"spec.forProvider.labels.severity '{severity}' is invalid", file_str)

    if tier and severity and tier in TIER_SEVERITY_MAP:
        expected_severity = TIER_SEVERITY_MAP[tier]
        if severity != expected_severity:
            result.error(
                f"Tier '{tier}' requires severity '{expected_severity}' but got '{severity}' - "
                f"check routing matrix alignment",
                file_str
            )

    template_id = labels.get("template_id")
    if not template_id:
        result.error("spec.forProvider.labels.template_id is required (e.g., TPL-ALERT-001)", file_str)
    elif not re.match(r'^TPL-ALERT-[0-9]{3}$', template_id):
        result.error(f"spec.forProvider.labels.template_id '{template_id}' must match TPL-ALERT-NNN", file_str)

    annotations = for_provider.get("annotations", {})
    if not annotations.get("summary"):
        result.error("spec.forProvider.annotations.summary is required", file_str)
    elif len(annotations["summary"]) < 10:
        result.error("spec.forProvider.annotations.summary must be at least 10 characters", file_str)

    runbook = annotations.get("runbook_url")
    if not runbook:
        result.error("spec.forProvider.annotations.runbook_url is required", file_str)
    elif not re.match(r'^https?://', runbook):
        result.error(f"spec.forProvider.annotations.runbook_url '{runbook}' must be a valid HTTP/HTTPS URL", file_str)

    if not annotations.get("description"):
        result.warn("spec.forProvider.annotations.description is recommended", file_str)

    data = for_provider.get("data")
    if not data:
        result.error("spec.forProvider.data[] is required with at least one query", file_str)
    elif len(data) == 0:
        result.error("spec.forProvider.data[] must have at least one query definition", file_str)

    for_duration = for_provider.get("for")
    if not for_duration:
        result.error("spec.forProvider.for (evaluation duration) is required", file_str)
    elif not re.match(r'^([0-9]+[smhd])+$', str(for_duration)):
        result.error(f"spec.forProvider.for '{for_duration}' must be a valid duration (e.g., 5m, 30s, 1h)", file_str)

    if not labels.get("service") and "templates" not in file_str.replace("\\", "/"):
        result.warn("spec.forProvider.labels.service is recommended to indicate what service is monitored", file_str)

def validate_folder(doc: dict, result: ValidationResult, file_str: str):
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "")
    validate_k8s_name(name, result, file_str)

    for_provider = doc.get("spec", {}).get("forProvider", {})

    title = for_provider.get("title", "")
    if not title:
        result.error("spec.forProvider.title is required", file_str)
    elif not NAMING_PATTERNS["folder"].match(title):
        result.error(
            f"spec.forProvider.title '{title}' does not match naming convention "
            f"^[A-Z]{{2,6}}/[A-Z][a-zA-Z0-9]+(/[A-Z][a-zA-Z0-9]+)*$",
            file_str
        )

    uid = for_provider.get("uid")
    if not uid:
        result.error("spec.forProvider.uid is required", file_str)
    elif not re.match(r'^[a-z0-9-]{4,40}$', uid):
        result.error(f"spec.forProvider.uid '{uid}' must be lowercase alphanumeric with hyphens (4-40 chars)", file_str)

def validate_organization(doc: dict, result: ValidationResult, file_str: str):
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "")
    validate_k8s_name(name, result, file_str)

    for_provider = doc.get("spec", {}).get("forProvider", {})
    org_name = for_provider.get("name", "")
    if not org_name:
        result.error("spec.forProvider.name is required", file_str)
    elif not NAMING_PATTERNS["organization"].match(org_name):
        result.error(
            f"spec.forProvider.name '{org_name}' does not match naming convention "
            f"^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{{4}}$",
            file_str
        )

def validate_org_member(doc: dict, result: ValidationResult, file_str: str):
    metadata = doc.get("metadata", {})
    name = metadata.get("name", "")
    validate_k8s_name(name, result, file_str)

    for_provider = doc.get("spec", {}).get("forProvider", {})

    email = for_provider.get("email")
    if not email:
        result.error("spec.forProvider.email is required", file_str)
    elif not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email):
        result.error(f"spec.forProvider.email '{email}' is not a valid email address", file_str)

    role = for_provider.get("role")
    if not role:
        result.error("spec.forProvider.role is required (Viewer, Editor, Admin)", file_str)
    elif role not in VALID_ROLES:
        result.error(f"spec.forProvider.role '{role}' is invalid. Valid: {', '.join(VALID_ROLES)}", file_str)

    has_org = for_provider.get("orgId") or for_provider.get("orgIdRef")
    if not has_org:
        result.error("spec.forProvider.orgId or spec.forProvider.orgIdRef is required", file_str)

# ============================================================================
# Common validations
# ============================================================================

def validate_common(doc: dict, result: ValidationResult, file_str: str):
    if not doc.get("apiVersion"):
        result.error("apiVersion is required", file_str)
    if not doc.get("kind"):
        result.error("kind is required", file_str)

    spec = doc.get("spec", {})
    if not spec:
        result.error("spec is required", file_str)
        return

    provider_ref = spec.get("providerConfigRef", {})
    if not provider_ref.get("name"):
        result.error("spec.providerConfigRef.name is required", file_str)

# ============================================================================
# PromQL basic syntax check
# ============================================================================

def check_promql_syntax(expr: str, file_str: str, result: ValidationResult):
    """Basic PromQL syntax check - bracket balance and common issues."""
    if not expr or expr.strip() == "":
        return

    # Check bracket balance
    opens = expr.count('(') + expr.count('[') + expr.count('{')
    closes = expr.count(')') + expr.count(']') + expr.count('}')
    if opens != closes:
        result.warn(
            f"PromQL expression may have unbalanced brackets (opens={opens}, closes={closes}): {expr[:80]}...",
            file_str
        )

    # Check for common template placeholders not substituted (skip for template files)
    if re.search(r'__[a-z_]+__', expr) and "templates" not in file_str.replace("\\", "/"):
        result.warn(
            f"PromQL expression contains unsubstituted template placeholder: {expr[:80]}",
            file_str
        )

# ============================================================================
# Cross-resource reference checks
# ============================================================================

def collect_all_resources(root_dir: Path) -> Dict[str, List[dict]]:
    """Scan all YAML files and collect resources by kind."""
    resources: Dict[str, List[dict]] = {}
    for yaml_file in root_dir.rglob("*.yaml"):
        try:
            docs = load_yaml_documents(yaml_file)
            for doc in docs:
                if isinstance(doc, dict) and doc.get("kind"):
                    kind = doc["kind"]
                    if kind not in resources:
                        resources[kind] = []
                    resources[kind].append({"doc": doc, "file": str(yaml_file)})
        except Exception:
            pass
    return resources

def check_folder_uid_references(resources: Dict[str, List[dict]], result: ValidationResult):
    """Check that folderUid references in AlertRules exist as Folder resources."""
    folder_uids = set()
    for folder_entry in resources.get("Folder", []):
        uid = folder_entry["doc"].get("spec", {}).get("forProvider", {}).get("uid")
        if uid:
            folder_uids.add(uid)

    for alert_entry in resources.get("AlertRule", []):
        doc = alert_entry["doc"]
        file_str = alert_entry["file"]
        folder_uid = doc.get("spec", {}).get("forProvider", {}).get("folderUid")
        if folder_uid and folder_uid not in folder_uids:
            result.warn(
                f"AlertRule references folderUid '{folder_uid}' but no Folder resource with that uid was found in the repo",
                file_str
            )

def check_uid_uniqueness(resources: Dict[str, List[dict]], result: ValidationResult):
    """Check that folder UIDs are unique across all Folder resources."""
    seen_uids: Dict[str, str] = {}
    for folder_entry in resources.get("Folder", []):
        doc = folder_entry["doc"]
        file_str = folder_entry["file"]
        uid = doc.get("spec", {}).get("forProvider", {}).get("uid")
        if uid:
            if uid in seen_uids:
                result.error(
                    f"Folder uid '{uid}' is not unique - also defined in {seen_uids[uid]}",
                    file_str
                )
            else:
                seen_uids[uid] = file_str

def check_noc_admin_presence(resources: Dict[str, List[dict]], result: ValidationResult):
    """Check that each org has at least one Admin from NOC."""
    org_members: Dict[str, List[dict]] = {}
    for member_entry in resources.get("OrgMember", []):
        doc = member_entry["doc"]
        org_ref = (doc.get("spec", {}).get("forProvider", {}).get("orgIdRef") or {}).get("name", "unknown")
        if org_ref not in org_members:
            org_members[org_ref] = []
        org_members[org_ref].append(doc)

    for org, members in org_members.items():
        admins = [m for m in members if m.get("spec", {}).get("forProvider", {}).get("role") == "Admin"]
        if not admins:
            result.error(f"Organization '{org}' has no Admin members - at least one Admin is required")

# ============================================================================
# Main validator dispatcher
# ============================================================================

def validate_document(doc: dict, file_str: str, result: ValidationResult):
    """Validate a single YAML document."""
    kind = doc.get("kind")
    api_version = doc.get("apiVersion", "")

    # Skip non-Crossplane/governance documents
    if not kind or not api_version:
        return

    validate_common(doc, result, file_str)

    if kind == "Dashboard":
        validate_dashboard(doc, result, file_str)
    elif kind == "AlertRule":
        validate_alert_rule(doc, result, file_str)
        # Check PromQL in data
        for data_item in doc.get("spec", {}).get("forProvider", {}).get("data", []):
            model = data_item.get("model", {})
            expr = model.get("expr", "")
            if expr:
                check_promql_syntax(expr, file_str, result)
    elif kind == "Folder":
        validate_folder(doc, result, file_str)
    elif kind == "Organization":
        validate_organization(doc, result, file_str)
    elif kind == "OrgMember":
        validate_org_member(doc, result, file_str)

    # JSON schema validation (skip strict validation for template files)
    if "templates" in file_str.replace("\\", "/"):
        return
    schema = get_schema_for_resource(api_version, kind)
    if schema:
        try:
            # Remove x-governance-rules from schema for validation (it's metadata)
            schema_copy = {k: v for k, v in schema.items() if not k.startswith('x-')}
            jschema_validate(instance=doc, schema=schema_copy)
        except ValidationError as e:
            result.warn(f"JSON Schema validation: {e.message}", file_str)

def is_template_file(file_path: Path) -> bool:
    """Return True if this file is a template (in templates/ directory)."""
    parts = file_path.parts
    return "templates" in parts

def validate_file(file_path: Path, result: ValidationResult):
    """Validate a single YAML file."""
    file_str = str(file_path.relative_to(REPO_ROOT) if file_path.is_absolute() else file_path)
    result.files_checked += 1
    had_errors_before = len(result.errors)

    try:
        docs = load_yaml_documents(file_path)
    except ValueError as e:
        result.error(str(e), file_str)
        return

    if not docs:
        result.info("File is empty or contains only comments", file_str)
        return

    for doc in docs:
        if isinstance(doc, dict):
            validate_document(doc, file_str, result)

    if len(result.errors) == had_errors_before:
        result.files_passed += 1
        result.info(f"PASSED", file_str)

# ============================================================================
# Output formatting
# ============================================================================

def print_report(result: ValidationResult, verbose: bool = False):
    print()
    print("=" * 70)
    print("  GRAFANA GOVERNANCE PLATFORM - VALIDATION REPORT")
    print("=" * 70)
    print(f"  Files checked : {result.files_checked}")
    print(f"  Files passed  : {result.files_passed}")
    print(f"  Errors        : {len(result.errors)}")
    print(f"  Warnings      : {len(result.warnings)}")
    print("=" * 70)

    if result.errors:
        print()
        print("ERRORS (must fix before merge):")
        print("-" * 70)
        for err in result.errors:
            print(f"  {err}")

    if result.warnings:
        print()
        print("WARNINGS (recommended to fix):")
        print("-" * 70)
        for warn in result.warnings:
            print(f"  {warn}")

    if verbose and result.infos:
        print()
        print("INFO:")
        print("-" * 70)
        for info in result.infos:
            print(f"  {info}")

    print()
    if result.has_errors():
        print("  RESULT: FAILED - Fix errors before merging")
    elif result.has_warnings():
        print("  RESULT: PASSED WITH WARNINGS")
    else:
        print("  RESULT: PASSED")
    print("=" * 70)

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Validate Crossplane Grafana manifests against governance rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate.py --file orgs/org-platform-2025/org.yaml
  python validate.py --dir orgs/org-platform-2025
  python validate.py --dir . --verbose
  python validate.py --dir . --cross-check
        """
    )
    parser.add_argument("--file", type=Path, help="Validate a single YAML file")
    parser.add_argument("--dir", type=Path, help="Validate all YAML files in a directory (recursive)")
    parser.add_argument("--cross-check", action="store_true",
                        help="Perform cross-resource reference checks (requires --dir)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show INFO messages in output")
    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    result = ValidationResult()

    if args.file:
        if not args.file.exists():
            print(f"ERROR: File not found: {args.file}")
            sys.exit(1)
        validate_file(args.file, result)

    elif args.dir:
        if not args.dir.exists():
            print(f"ERROR: Directory not found: {args.dir}")
            sys.exit(1)

        # Directories to skip (non-governance YAML files)
        SKIP_DIRS = {"_template", "provider", "config", "scripts", "schemas", "policies", "argocd"}
        yaml_files = list(args.dir.rglob("*.yaml"))
        yaml_files = [f for f in yaml_files
                      if not any(p.startswith('.') for p in f.parts)
                      and not any(p in SKIP_DIRS for p in f.parts)]
        if not yaml_files:
            print(f"No YAML files found in {args.dir}")
            sys.exit(0)

        print(f"Validating {len(yaml_files)} YAML files in {args.dir}...")
        for yaml_file in sorted(yaml_files):
            validate_file(yaml_file, result)

        # Cross-resource checks
        if args.cross_check:
            print("Running cross-resource reference checks...")
            all_resources = collect_all_resources(args.dir)
            check_folder_uid_references(all_resources, result)
            check_uid_uniqueness(all_resources, result)
            check_noc_admin_presence(all_resources, result)

    print_report(result, verbose=args.verbose)

    if result.has_errors():
        sys.exit(1)
    elif result.has_warnings():
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()

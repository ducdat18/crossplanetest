package grafana.governance.naming

import future.keywords.if
import future.keywords.in

# ============================================================================
# Grafana Governance - Naming Convention Policy
# Validates naming conventions for all Grafana resources managed via Crossplane
# Provider: provider-grafana v2.6.0
# ============================================================================

# ----------------------------------------------------------------------------
# Main deny rules - collected from all resource-specific validators
# ----------------------------------------------------------------------------

deny[msg] {
    input.kind == "Dashboard"
    msg := dashboard_violations[_]
}

deny[msg] {
    input.kind == "AlertRule"
    msg := alert_rule_violations[_]
}

deny[msg] {
    input.kind == "RuleGroup"
    msg := rule_group_violations[_]
}

deny[msg] {
    input.kind == "Folder"
    msg := folder_violations[_]
}

deny[msg] {
    input.kind == "Organization"
    msg := org_violations[_]
}

deny[msg] {
    input.kind == "DataSource"
    msg := datasource_violations[_]
}

# warn is non-blocking - used for advisory checks
warn[msg] {
    input.kind == "Dashboard"
    msg := dashboard_warnings[_]
}

warn[msg] {
    input.kind == "AlertRule"
    msg := alert_rule_warnings[_]
}

warn[msg] {
    input.kind == "RuleGroup"
    msg := rule_group_warnings[_]
}

# ============================================================================
# Dashboard Validations
# Pattern: ^[A-Z]{2,6}-[a-z0-9-]+-v[0-9]+\.[0-9]+$
# ============================================================================

dashboard_violations[msg] {
    name := input.spec.forProvider.configJson
    # configJson must be provided
    not name
    msg := "ERROR [DASH-001]: Dashboard spec.forProvider.configJson is required"
}

dashboard_violations[msg] {
    title := json.unmarshal(input.spec.forProvider.configJson).title
    not re_match(`^[A-Z]{2,6}-[a-z0-9-]+-v[0-9]+\.[0-9]+$`, title)
    msg := sprintf("ERROR [DASH-002]: Dashboard title '%v' violates naming convention. Pattern: ^[A-Z]{2,6}-[a-z0-9-]+-v[0-9]+\\.[0-9]+$. Example: PLAT-api-latency-v1.0", [title])
}

dashboard_violations[msg] {
    not input.metadata.labels.template_id
    msg := "ERROR [DASH-003]: Dashboard metadata.labels.template_id is required. Example: TPL-DASH-001"
}

dashboard_violations[msg] {
    template_id := input.metadata.labels.template_id
    not re_match(`^TPL-DASH-[0-9]{3}$`, template_id)
    msg := sprintf("ERROR [DASH-004]: Dashboard label template_id '%v' is invalid. Pattern: ^TPL-DASH-[0-9]{3}$", [template_id])
}

dashboard_violations[msg] {
    not input.metadata.labels.lifecycle
    msg := "ERROR [DASH-005]: Dashboard metadata.labels.lifecycle is required. Values: dev, staging, production, deprecated"
}

dashboard_violations[msg] {
    lifecycle := input.metadata.labels.lifecycle
    valid_lifecycles := {"dev", "staging", "production", "deprecated"}
    not lifecycle in valid_lifecycles
    msg := sprintf("ERROR [DASH-006]: Dashboard label lifecycle '%v' is invalid. Valid values: dev, staging, production, deprecated", [lifecycle])
}

dashboard_violations[msg] {
    dash_json := json.unmarshal(input.spec.forProvider.configJson)
    not dash_json.uid
    msg := "ERROR [DASH-007]: Dashboard configJson must include a 'uid' field"
}

dashboard_violations[msg] {
    dash_json := json.unmarshal(input.spec.forProvider.configJson)
    uid := dash_json.uid
    not re_match(`^[a-z0-9-]{4,40}$`, uid)
    msg := sprintf("ERROR [DASH-008]: Dashboard configJson.uid '%v' must be lowercase alphanumeric with hyphens, 4-40 chars", [uid])
}

dashboard_violations[msg] {
    dash_json := json.unmarshal(input.spec.forProvider.configJson)
    not dash_json.schemaVersion
    msg := "ERROR [DASH-009]: Dashboard configJson must include 'schemaVersion' field"
}

dashboard_violations[msg] {
    dash_json := json.unmarshal(input.spec.forProvider.configJson)
    not dash_json.panels
    msg := "ERROR [DASH-010]: Dashboard configJson must include 'panels' array"
}

dashboard_warnings[msg] {
    not input.metadata.annotations["governance.grafana.io/owner-team"]
    msg := "WARN [DASH-W001]: Dashboard should have annotation 'governance.grafana.io/owner-team' specifying the owning team"
}

dashboard_warnings[msg] {
    dash_json := json.unmarshal(input.spec.forProvider.configJson)
    count(dash_json.panels) == 0
    msg := "WARN [DASH-W002]: Dashboard has no panels defined"
}

# ============================================================================
# AlertRule Validations
# Pattern: ^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$
# ============================================================================

alert_rule_violations[msg] {
    name := input.spec.forProvider.name
    not re_match(`^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$`, name)
    msg := sprintf("ERROR [ALERT-001]: AlertRule name '%v' violates naming convention. Pattern: ^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$. Example: PLAT-SVC-CRIT-high-error-rate", [name])
}

alert_rule_violations[msg] {
    not input.spec.forProvider.labels.tier
    msg := "ERROR [ALERT-002]: AlertRule spec.forProvider.labels.tier is required. Values: ultra-rt, real-time, nrt, standard, degraded, trend, daily"
}

alert_rule_violations[msg] {
    tier := input.spec.forProvider.labels.tier
    valid_tiers := {"ultra-rt", "real-time", "nrt", "standard", "degraded", "trend", "daily"}
    not tier in valid_tiers
    msg := sprintf("ERROR [ALERT-003]: AlertRule label tier '%v' is invalid. Valid: ultra-rt, real-time, nrt, standard, degraded, trend, daily", [tier])
}

alert_rule_violations[msg] {
    not input.spec.forProvider.labels.severity
    msg := "ERROR [ALERT-004]: AlertRule spec.forProvider.labels.severity is required. Values: page, critical, warning, info, report"
}

alert_rule_violations[msg] {
    severity := input.spec.forProvider.labels.severity
    valid_severities := {"page", "critical", "warning", "info", "report"}
    not severity in valid_severities
    msg := sprintf("ERROR [ALERT-005]: AlertRule label severity '%v' is invalid. Valid: page, critical, warning, info, report", [severity])
}

alert_rule_violations[msg] {
    not input.spec.forProvider.labels.template_id
    msg := "ERROR [ALERT-006]: AlertRule spec.forProvider.labels.template_id is required. Example: TPL-ALERT-001"
}

alert_rule_violations[msg] {
    template_id := input.spec.forProvider.labels.template_id
    not re_match(`^TPL-ALERT-[0-9]{3}$`, template_id)
    msg := sprintf("ERROR [ALERT-007]: AlertRule label template_id '%v' is invalid. Pattern: ^TPL-ALERT-[0-9]{3}$", [template_id])
}

alert_rule_violations[msg] {
    not input.spec.forProvider.annotations.summary
    msg := "ERROR [ALERT-008]: AlertRule spec.forProvider.annotations.summary is required"
}

alert_rule_violations[msg] {
    not input.spec.forProvider.annotations.runbook_url
    msg := "ERROR [ALERT-009]: AlertRule spec.forProvider.annotations.runbook_url is required"
}

alert_rule_violations[msg] {
    runbook := input.spec.forProvider.annotations.runbook_url
    not re_match(`^https?://`, runbook)
    msg := sprintf("ERROR [ALERT-010]: AlertRule annotation runbook_url '%v' must be a valid HTTP/HTTPS URL", [runbook])
}

alert_rule_violations[msg] {
    tier := input.spec.forProvider.labels.tier
    severity := input.spec.forProvider.labels.severity
    not tier_severity_match(tier, severity)
    msg := sprintf("ERROR [ALERT-011]: AlertRule tier '%v' does not match severity '%v'. Check routing matrix alignment.", [tier, severity])
}

alert_rule_violations[msg] {
    not input.spec.forProvider.data
    msg := "ERROR [ALERT-012]: AlertRule spec.forProvider.data[] query definitions are required"
}

alert_rule_violations[msg] {
    count(input.spec.forProvider.data) == 0
    msg := "ERROR [ALERT-013]: AlertRule spec.forProvider.data must have at least one query definition"
}

alert_rule_warnings[msg] {
    not input.spec.forProvider.annotations.description
    msg := "WARN [ALERT-W001]: AlertRule should have annotation 'description' with detailed explanation"
}

alert_rule_warnings[msg] {
    not input.spec.forProvider.labels.service
    msg := "WARN [ALERT-W002]: AlertRule should have label 'service' specifying which service is monitored"
}

# Helper: tier must match expected severity
tier_severity_match("ultra-rt", "page") := true
tier_severity_match("real-time", "critical") := true
tier_severity_match("nrt", "warning") := true
tier_severity_match("standard", "warning") := true
tier_severity_match("degraded", "info") := true
tier_severity_match("trend", "info") := true
tier_severity_match("daily", "report") := true

# ============================================================================
# Folder Validations
# Pattern: ^[A-Z]{2,6}\/[A-Z][a-zA-Z0-9]+(\/[A-Z][a-zA-Z0-9]+)*$
# ============================================================================

folder_violations[msg] {
    title := input.spec.forProvider.title
    not re_match(`^[A-Z]{2,6}\/[A-Z][a-zA-Z0-9]+(\/[A-Z][a-zA-Z0-9]+)*$`, title)
    msg := sprintf("ERROR [FOLD-001]: Folder title '%v' violates naming convention. Pattern: ^[A-Z]{2,6}/[A-Z][a-zA-Z0-9]+(/[A-Z][a-zA-Z0-9]+)*$. Example: PLAT/RealTime", [title])
}

folder_violations[msg] {
    not input.spec.forProvider.uid
    msg := "ERROR [FOLD-002]: Folder spec.forProvider.uid is required"
}

folder_violations[msg] {
    uid := input.spec.forProvider.uid
    not re_match(`^[a-z0-9-]{4,40}$`, uid)
    msg := sprintf("ERROR [FOLD-003]: Folder uid '%v' must be lowercase alphanumeric with hyphens, 4-40 chars", [uid])
}

# ============================================================================
# Organization Validations
# Pattern: ^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$
# ============================================================================

org_violations[msg] {
    name := input.spec.forProvider.name
    not re_match(`^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$`, name)
    msg := sprintf("ERROR [ORG-001]: Organization name '%v' violates naming convention. Pattern: ^ORG-[A-Z][a-zA-Z0-9]+-[0-9]{4}$. Example: ORG-Platform-2025", [name])
}

# ============================================================================
# RuleGroup Validations (alerting.grafana.crossplane.io/v1alpha1)
# Each rule inside the group must follow AlertRule naming convention
# ============================================================================

rule_group_violations[msg] {
    not input.spec.forProvider.folderUid
    not input.spec.forProvider.folderRef
    msg := "ERROR [RG-001]: RuleGroup spec.forProvider.folderUid or folderRef is required"
}

rule_group_violations[msg] {
    not input.spec.forProvider.organizationRef
    not input.spec.forProvider.orgId
    msg := "ERROR [RG-002]: RuleGroup spec.forProvider.organizationRef or orgId is required"
}

rule_group_violations[msg] {
    not input.spec.forProvider.rule
    msg := "ERROR [RG-003]: RuleGroup spec.forProvider.rule[] must contain at least one rule"
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    name := rule.name
    not re_match(`^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$`, name)
    msg := sprintf("ERROR [RG-004]: RuleGroup rule name '%v' violates naming convention. Pattern: ^[A-Z]{2,6}-[A-Z]+-(CRIT|WARN|INFO)-[a-z0-9-]+$", [name])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.labels.tier
    msg := sprintf("ERROR [RG-005]: RuleGroup rule '%v' missing labels.tier", [rule.name])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    tier := rule.labels.tier
    valid_tiers := {"ultra-rt", "real-time", "nrt", "standard", "degraded", "trend", "daily"}
    not tier in valid_tiers
    msg := sprintf("ERROR [RG-006]: RuleGroup rule '%v' has invalid tier '%v'", [rule.name, tier])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.labels.template_id
    msg := sprintf("ERROR [RG-007]: RuleGroup rule '%v' missing labels.template_id (e.g., TPL-ALERT-001)", [rule.name])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.annotations.summary
    msg := sprintf("ERROR [RG-008]: RuleGroup rule '%v' missing annotations.summary", [rule.name])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.annotations.runbook_url
    msg := sprintf("ERROR [RG-009]: RuleGroup rule '%v' missing annotations.runbook_url", [rule.name])
}

rule_group_violations[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.data
    msg := sprintf("ERROR [RG-010]: RuleGroup rule '%v' missing data[] query definitions", [rule.name])
}

rule_group_warnings[msg] {
    rule := input.spec.forProvider.rule[_]
    not rule.annotations.description
    msg := sprintf("WARN [RG-W001]: RuleGroup rule '%v' should have annotations.description", [rule.name])
}

# ============================================================================
# DataSource Validations
# Pattern: ^DS-[a-z]+-[a-z0-9-]+-[a-z]+(-(prod|stg|dev))?$
# ============================================================================

datasource_violations[msg] {
    name := input.spec.forProvider.name
    not re_match(`^DS-[a-z]+-[a-z0-9-]+-[a-z]+(-(prod|stg|dev))?$`, name)
    msg := sprintf("ERROR [DS-001]: DataSource name '%v' violates naming convention. Pattern: ^DS-[a-z]+-[a-z0-9-]+-[a-z]+(-(prod|stg|dev))?$. Example: DS-prom-payments-api-prod", [name])
}

# ============================================================================
# Common validations for all resource types
# ============================================================================

deny[msg] {
    not input.spec.providerConfigRef.name
    msg := "ERROR [COMMON-001]: spec.providerConfigRef.name is required for all Crossplane resources"
}

deny[msg] {
    not input.metadata.name
    msg := "ERROR [COMMON-002]: metadata.name is required"
}

deny[msg] {
    name := input.metadata.name
    not re_match(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`, name)
    msg := sprintf("ERROR [COMMON-003]: metadata.name '%v' must be a valid Kubernetes DNS label (lowercase, alphanumeric, hyphens, 3-63 chars)", [name])
}

terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "1.0.0"
    }
  }
}

provider "unifiedpolicy" {
  url          = "https://myinstance.jfrog.io"  # Your JFrog Platform URL
  access_token = var.access_token
}

variable "access_token" {
  description = "JFrog access token"
  type        = string
  sensitive   = true
}

locals {
  # Absolute path prefix — rego paths must be absolute at apply time
  abs = "${path.module}/"
}

# ============================================================================
# EXECUTION ORDER
# Templates → Rules → Lifecycle Policies
# ============================================================================

# ============================================================================
# TEMPLATES
# ============================================================================

# Minimal template — no description, no scanners, no parameters
resource "unifiedpolicy_template" "minimal" {
  name             = "Minimal Security Template"
  version          = "1.0.0"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/basic_policy.rego"
}

# Full-featured template — all optional fields set
resource "unifiedpolicy_template" "full_featured" {
  name             = "Full Featured Security Template"
  version          = "2.0.0"
  description      = "Comprehensive template with all fields populated"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/params_policy.rego"
  scanners         = ["sca", "secrets", "exposures", "contextual_analysis", "malicious_package"]

  parameters = [
    {
      name = "severity_threshold"
      type = "string"
    },
    {
      name = "max_count"
      type = "int"
    },
    {
      name = "enabled"
      type = "bool"
    }
  ]
}

# Template with noop data source type
resource "unifiedpolicy_template" "noop_template" {
  name             = "Noop Data Source Template"
  version          = "1.0.0"
  description      = "Template using noop data source type"
  category         = "quality"
  data_source_type = "noop"
  rego             = "${local.abs}policies/basic_policy.rego"
}

# Template with legal category
resource "unifiedpolicy_template" "legal_template" {
  name             = "Legal Compliance Template"
  version          = "1.0.0"
  description      = "Template for legal compliance checks"
  category         = "legal"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/basic_policy.rego"
}

# Template for high severity checks
resource "unifiedpolicy_template" "high_severity" {
  name             = "High Severity Check Template"
  version          = "1.0.0"
  description      = "Template for high severity vulnerability detection"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/params_severity_policy.rego"

  parameters = [
    {
      name = "severity_threshold"
      type = "string"
    }
  ]
}

# ============================================================================
# RULES
# ============================================================================

# Basic rule — no parameters
resource "unifiedpolicy_rule" "basic_rule" {
  name        = "Basic Security Rule"
  description = "Simple rule with no parameters"
  template_id = unifiedpolicy_template.minimal.id
  parameters  = []
}

# Rule with parameter values
resource "unifiedpolicy_rule" "parameterized_rule" {
  name        = "Parameterized Security Rule"
  description = "Rule with parameter values bound"
  template_id = unifiedpolicy_template.full_featured.id
  parameters = [
    {
      name  = "severity_threshold"
      value = "critical"
    },
    {
      name  = "max_count"
      value = "10"
    },
    {
      name  = "enabled"
      value = "true"
    }
  ]
}

# Rule with high severity threshold
resource "unifiedpolicy_rule" "high_severity_rule" {
  name        = "High Severity Rule"
  description = "Blocks on high severity findings"
  template_id = unifiedpolicy_template.high_severity.id
  parameters = [
    {
      name  = "severity_threshold"
      value = "high"
    }
  ]
}

# Rule for warning mode policies
resource "unifiedpolicy_rule" "warning_rule" {
  name        = "Warning Mode Rule"
  description = "Rule used in warning-mode policies"
  template_id = unifiedpolicy_template.minimal.id
  parameters  = []
}

# Rule for global scope policy
resource "unifiedpolicy_rule" "global_rule" {
  name        = "Global Policy Rule"
  description = "Rule applied globally across all projects"
  template_id = unifiedpolicy_template.minimal.id
  parameters  = []
}

# ============================================================================
# LIFECYCLE POLICIES
# ============================================================================

# Example 1: Project scope — single project key — block mode
resource "unifiedpolicy_lifecycle_policy" "project_single_key" {
  name        = "Project Single Key Policy"
  description = "Block promotion on critical CVEs in project aa"
  enabled     = true
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "PROD"
      gate = "release"
    }
  }

  scope {
    type         = "project"
    project_keys = ["aa"]
  }

  rule_ids = [unifiedpolicy_rule.basic_rule.id]
}

# Example 2: Project scope — multiple project keys (up to 10)
resource "unifiedpolicy_lifecycle_policy" "project_multi_keys" {
  name        = "Project Multi-Key Policy"
  description = "Block promotion across multiple projects"
  enabled     = true
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "PROD"
      gate = "release"
    }
  }

  scope {
    type         = "project"
    project_keys = ["aa", "bb", "cc"]
  }

  rule_ids = [unifiedpolicy_rule.parameterized_rule.id]
}

# Example 3: Application scope — application keys only
resource "unifiedpolicy_lifecycle_policy" "app_scope" {
  name        = "Application Scope Policy"
  description = "Warn on high severity CVEs in QA"
  enabled     = true
  mode        = "warning"

  action {
    type = "certify_to_gate"
    stage {
      key  = "QA"
      gate = "exit"
    }
  }

  scope {
    type             = "application"
    application_keys = ["aa"]
  }

  rule_ids = [unifiedpolicy_rule.warning_rule.id]
}

# Example 4: Application scope — with application labels
resource "unifiedpolicy_lifecycle_policy" "app_scope_with_labels" {
  name        = "Application Labels Policy"
  description = "Policy targeting specific application labels"
  enabled     = true
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "PROD"
      gate = "release"
    }
  }

  scope {
    type             = "application"
    application_keys = ["bb"]
    application_labels {
      key   = "environment"
      value = "production"
    }
    application_labels {
      key   = "team"
      value = "platform"
    }
  }

  rule_ids = [unifiedpolicy_rule.high_severity_rule.id]
}

# Example 5: Global scope — applies across all projects/applications
resource "unifiedpolicy_lifecycle_policy" "global_scope" {
  name        = "Global Security Policy"
  description = "Policy applied globally to all projects and applications"
  enabled     = true
  mode        = "warning"

  action {
    type = "certify_to_gate"
    stage {
      key  = "PROD"
      gate = "release"
    }
  }

  scope {
    type = "global"
  }

  rule_ids = [unifiedpolicy_rule.global_rule.id]
}

# Example 6: Disabled policy
resource "unifiedpolicy_lifecycle_policy" "disabled_policy" {
  name        = "Disabled Policy"
  description = "Policy defined but not yet active"
  enabled     = false
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "PROD"
      gate = "release"
    }
  }

  scope {
    type         = "project"
    project_keys = ["dd"]
  }

  rule_ids = [unifiedpolicy_rule.basic_rule.id]
}

# Example 7: Entry gate policy
resource "unifiedpolicy_lifecycle_policy" "entry_gate_policy" {
  name        = "Dev Entry Gate Policy"
  description = "Enforce security checks at development entry gate"
  enabled     = true
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "DEV"
      gate = "entry"
    }
  }

  scope {
    type         = "project"
    project_keys = ["aa"]
  }

  rule_ids = [unifiedpolicy_rule.basic_rule.id]
}

# ============================================================================
# DATA SOURCES
# ============================================================================

# Read a single template by ID
data "unifiedpolicy_template" "read_template" {
  id = unifiedpolicy_template.full_featured.id
}

# List all templates filtered by category
data "unifiedpolicy_templates" "security_templates" {
  category   = "security"
  sort_by    = "name"
  sort_order = "asc"
  limit      = 100
}

# List templates by multiple IDs
data "unifiedpolicy_templates" "specific_templates" {
  ids = [
    unifiedpolicy_template.minimal.id,
    unifiedpolicy_template.full_featured.id,
  ]
}

# Read a single rule by ID
data "unifiedpolicy_rule" "read_rule" {
  id = unifiedpolicy_rule.parameterized_rule.id
}

# List all rules filtered by name
data "unifiedpolicy_rules" "all_rules" {
  sort_by    = "name"
  sort_order = "asc"
}

# List rules filtered by data source type
data "unifiedpolicy_rules" "evidence_rules" {
  template_data_source = "evidence"
  limit                = 50
}

# Read a single lifecycle policy by ID
data "unifiedpolicy_lifecycle_policy" "read_policy" {
  id = unifiedpolicy_lifecycle_policy.project_single_key.id
}

# List all lifecycle policies
data "unifiedpolicy_lifecycle_policies" "all_policies" {
  sort_by    = "name"
  sort_order = "asc"
}

# List policies filtered by scope type (project)
data "unifiedpolicy_lifecycle_policies" "project_policies" {
  scope_type = "project"
  enabled    = true
  mode       = "block"
}

# List global policies
data "unifiedpolicy_lifecycle_policies" "global_policies" {
  scope_type = "global"
}

# List policies by project key with hierarchical flag
data "unifiedpolicy_lifecycle_policies" "hierarchical_policies" {
  project_key  = "aa"
  hierarchical = true
}

# ============================================================================
# OUTPUTS — Show computed audit fields
# ============================================================================

output "template_audit" {
  description = "Template audit information"
  value = {
    id         = unifiedpolicy_template.full_featured.id
    created_at = unifiedpolicy_template.full_featured.created_at
    created_by = unifiedpolicy_template.full_featured.created_by
    updated_at = unifiedpolicy_template.full_featured.updated_at
    updated_by = unifiedpolicy_template.full_featured.updated_by
  }
}

output "rule_audit" {
  description = "Rule audit information"
  value = {
    id         = unifiedpolicy_rule.parameterized_rule.id
    created_at = unifiedpolicy_rule.parameterized_rule.created_at
    created_by = unifiedpolicy_rule.parameterized_rule.created_by
    updated_at = unifiedpolicy_rule.parameterized_rule.updated_at
    updated_by = unifiedpolicy_rule.parameterized_rule.updated_by
  }
}

output "policy_audit" {
  description = "Lifecycle policy audit information"
  value = {
    id         = unifiedpolicy_lifecycle_policy.global_scope.id
    created_at = unifiedpolicy_lifecycle_policy.global_scope.created_at
    created_by = unifiedpolicy_lifecycle_policy.global_scope.created_by
    updated_at = unifiedpolicy_lifecycle_policy.global_scope.updated_at
    updated_by = unifiedpolicy_lifecycle_policy.global_scope.updated_by
  }
}

output "all_security_templates" {
  description = "All security templates from list datasource"
  value       = data.unifiedpolicy_templates.security_templates.templates
}

output "all_policies_count" {
  description = "Total number of policies returned"
  value       = data.unifiedpolicy_lifecycle_policies.all_policies.page_size
}

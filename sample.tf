terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "1.0.0"
    }
  }
}

provider "unifiedpolicy" {
  url          = "myinstance.jfrog.io/artifactory"  # Your Artifactory/Platform URL
  access_token = ""                                 # Set to a valid token, or use a variable (e.g. var.access_token) or env (TF_VAR_access_token)
}

# ============================================================================
# EXECUTION ORDER
# ============================================================================
# Terraform automatically resolves dependencies and executes resources in the
# correct order:
#   1. Templates (no dependencies) → created first
#   2. Rules (depend on templates via template_id) → created second
#   3. Lifecycle Policies (depend on rules via rule_ids) → created last
#
# The dependency chain is:
#   Templates → Rules → Lifecycle Policies
#
# You can verify the execution order by running: terraform plan
# ============================================================================

# ============================================================================
# TEMPLATES - Define reusable logic (Rego policies) for rules
# ============================================================================

locals {
  # Path to the directory containing the policies/ folder. Uses path.module so rego paths resolve to absolute paths at apply time.
  abs = "${path.module}/"
}

# Template for security vulnerability checks
resource "unifiedpolicy_template" "security_vulnerability" {
  name             = "Security Vulnerability Template"
  version          = "1.0.0"
  description      = "Template for checking security vulnerabilities (blocks critical severity)"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/security_vulnerability.rego"
  # parameters is optional and defaults to empty list []
  # scanners is optional and defaults to empty list []
}

# Template for high severity vulnerability checks (warning mode)
resource "unifiedpolicy_template" "high_severity_vulnerability" {
  name             = "High Severity Vulnerability Template"
  version          = "1.0.0"
  description      = "Template for checking high severity vulnerabilities"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/high_severity_vulnerability.rego"
  # parameters is optional and defaults to empty list []
  # scanners is optional and defaults to empty list []
}

# Template for development stage security checks
resource "unifiedpolicy_template" "dev_security_check" {
  name             = "Development Security Check Template"
  version          = "1.0.0"
  description      = "Template for development stage security validation"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${local.abs}policies/security_vulnerability.rego"
  # parameters is optional and defaults to empty list []
  # scanners is optional and defaults to empty list []
}

# ============================================================================
# RULES - Define specific parameter values based on templates
# ============================================================================

# Rule for production security (uses security_vulnerability template)
resource "unifiedpolicy_rule" "production_security_rule_1" {
  name        = "Production Security Rule 1"
  description = "Rule for blocking critical vulnerabilities in production"
  template_id = unifiedpolicy_template.security_vulnerability.id
  parameters  = []
}

resource "unifiedpolicy_rule" "production_security_rule_2" {
  name        = "Production Security Rule 2"
  description = "Additional rule for production security checks"
  template_id = unifiedpolicy_template.security_vulnerability.id
  parameters  = []
}

# Rule for QA warning (uses high_severity_vulnerability template)
resource "unifiedpolicy_rule" "qa_warning_rule" {
  name        = "QA Warning Rule"
  description = "Rule for warning on high severity CVEs in QA"
  template_id = unifiedpolicy_template.high_severity_vulnerability.id
  parameters  = []
}

# Rule for staging policy
resource "unifiedpolicy_rule" "staging_rule" {
  name        = "Staging Security Rule"
  description = "Rule for staging environment security checks"
  template_id = unifiedpolicy_template.security_vulnerability.id
  parameters  = []
}

# Rule for development policy
resource "unifiedpolicy_rule" "dev_security_rule" {
  name        = "Development Security Rule"
  description = "Rule for development entry security checks"
  template_id = unifiedpolicy_template.dev_security_check.id
  parameters  = []
}

# Rule for disabled policy
resource "unifiedpolicy_rule" "disabled_policy_rule" {
  name        = "Disabled Policy Rule"
  description = "Rule for disabled policy example"
  template_id = unifiedpolicy_template.security_vulnerability.id
  parameters  = []
}

# ============================================================================
# LIFECYCLE POLICIES - Define enforcement rules for SDLC stages
# ============================================================================

# Example 1: Lifecycle Policy with Project Scope - Block Mode
# This policy blocks promotion to production when critical CVEs are detected
resource "unifiedpolicy_lifecycle_policy" "production_security" {
  name        = "Production Security Policy"
  description = "Block promotion on Critical CVEs"
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
    project_keys = ["my-project"]  # Use a project key that exists in your instance; or use project.<name>.key if you use the jfrog/project provider
  }

  # NOTE: API currently limits rule_ids to exactly 1 rule per policy (maxItems: 1)
  # See: unified-policy/api/v1/pap.yaml PolicyRules schema
  rule_ids = [
    unifiedpolicy_rule.production_security_rule_1.id
    # unifiedpolicy_rule.production_security_rule_2.id  # API limitation: only 1 rule per policy allowed
  ]
}

# Example 2: Lifecycle Policy with Application Scope - Warning Mode
# This policy warns on high severity CVEs in QA stage but allows promotion
resource "unifiedpolicy_lifecycle_policy" "qa_warning" {
  name        = "QA Warning Policy"
  description = "Warn on High severity CVEs in QA stage"
  enabled     = true
  mode        = "warning"

  action {
    type = "certify_to_gate"
    stage {
      key  = "my-project-QA"  # Project-scoped stage: format is {projectKey}-{STAGE_NAME}
      gate = "exit"
    }
  }

  scope {
    type             = "application"
    application_keys = ["my-web-app"]
  }

  rule_ids = [unifiedpolicy_rule.qa_warning_rule.id]
}

# Example 3: Lifecycle Policy with Application Labels
# This policy uses application labels to target specific applications
# Note: application_keys is still required even when using labels
resource "unifiedpolicy_lifecycle_policy" "staging_policy" {
  name        = "Staging Policy"
  description = "Policy for staging environment applications"
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
    application_keys = ["my-app"]
    # application_labels {
    #   key   = "environment"
    #   value = "staging"
    # }
    # application_labels {
    #   key   = "team"
    #   value = "platform"
    # }
  }

  rule_ids = [unifiedpolicy_rule.staging_rule.id]
}

# Example 4: Lifecycle Policy for Development Stage
# This policy enforces rules at the entry gate of the development stage
resource "unifiedpolicy_lifecycle_policy" "dev_policy" {
  name        = "Development Entry Policy"
  description = "Enforce security checks at development entry"
  enabled     = true
  mode        = "warning"

  action {
    type = "certify_to_gate"
    stage {
      key  = "dev-project-DEV"  # Project-scoped stage: format is {projectKey}-{STAGE_NAME}
      gate = "entry"
    }
  }

  scope {
    type         = "project"
    project_keys = ["dev-project"]  # Use a project key that exists; or use project.<name>.key if you use the jfrog/project provider
  }

  rule_ids = [unifiedpolicy_rule.dev_security_rule.id]
}

# Example 5: Disabled Lifecycle Policy
# This policy is defined but not active
resource "unifiedpolicy_lifecycle_policy" "disabled_policy" {
  name        = "Disabled Policy"
  description = "This policy is currently disabled"
  enabled     = false
  mode        = "block"

  action {
    type = "certify_to_gate"
    stage {
      key  = "my-project-QA"  # Project-scoped stage: format is {projectKey}-{STAGE_NAME}
      gate = "exit"
    }
  }

  scope {
    type             = "application"
    application_keys = ["test-app"]
  }

  rule_ids = [unifiedpolicy_rule.disabled_policy_rule.id]
}


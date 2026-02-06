terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "1.0.0"
    }
  }
}

variable "jfrog_url" {
  type    = string
  default = "http://localhost:8081"
}

variable "jfrog_access_token" {
  type      = string
  default   = ""
  sensitive = true
}

provider "unifiedpolicy" {
  url          = var.jfrog_url
  access_token = var.jfrog_access_token
}

# Template (no dependencies)
resource "unifiedpolicy_template" "example" {
  name             = "Example Security Template"
  version          = "1.0.0"
  description      = "Example template for usage"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${path.module}/resources/templates/policy.rego"
}

# Rule (depends on template)
resource "unifiedpolicy_rule" "example" {
  name        = "Example Rule"
  description = "Example rule for usage"
  template_id = unifiedpolicy_template.example.id
  parameters  = []
}

# Lifecycle policy (depends on rule)
resource "unifiedpolicy_lifecycle_policy" "example" {
  name        = "Example Policy"
  description = "Example lifecycle policy"
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
    project_keys = ["my-project"]
  }

  rule_ids = [unifiedpolicy_rule.example.id]
}

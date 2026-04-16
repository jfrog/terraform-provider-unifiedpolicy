resource "unifiedpolicy_lifecycle_policy" "project_example" {
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
    project_keys = ["my-project"]
  }

  rule_ids = ["rule-12345"]
}

resource "unifiedpolicy_lifecycle_policy" "global_example" {
  name        = "Global Warning Policy"
  description = "Warn on all projects and applications globally"
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

  rule_ids = ["rule-67890"]
}

resource "unifiedpolicy_lifecycle_policy" "app_example" {
  name        = "Application Policy with Labels"
  description = "Block promotion for production applications"
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
    application_labels {
      key   = "environment"
      value = "production"
    }
  }

  rule_ids = ["rule-11111"]
}

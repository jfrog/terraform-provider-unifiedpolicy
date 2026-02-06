resource "unifiedpolicy_lifecycle_policy" "example" {
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

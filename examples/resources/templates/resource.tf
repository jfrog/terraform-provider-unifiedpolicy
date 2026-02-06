resource "unifiedpolicy_template" "example" {
  name             = "Example Security Template"
  version          = "1.0.0"
  description      = "Example template for import and usage"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${path.module}/policy.rego"
}

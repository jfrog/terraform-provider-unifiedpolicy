resource "unifiedpolicy_template" "example" {
  name             = "Example Security Template"
  version          = "1.0.0"
  description      = "Example template for security vulnerability checks"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${path.module}/policy.rego"
  scanners         = ["sca", "secrets"]

  parameters = [
    {
      name = "severity_threshold"
      type = "string"
    },
    {
      name = "max_count"
      type = "int"
    }
  ]
}

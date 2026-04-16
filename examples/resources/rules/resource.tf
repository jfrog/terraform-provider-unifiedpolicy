resource "unifiedpolicy_template" "example" {
  name             = "Example Security Template"
  version          = "1.0.0"
  description      = "Example template for security checks"
  category         = "security"
  data_source_type = "evidence"
  rego             = "${path.module}/policy.rego"

  parameters = [
    {
      name = "severity_threshold"
      type = "string"
    }
  ]
}

resource "unifiedpolicy_rule" "example" {
  name        = "Example Rule"
  description = "Example rule bound to the template above"
  template_id = unifiedpolicy_template.example.id

  parameters = [
    {
      name  = "severity_threshold"
      value = "critical"
    }
  ]
}

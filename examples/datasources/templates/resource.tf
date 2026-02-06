# Query a single template by ID
data "unifiedpolicy_template" "example" {
  id = "1005"
}

# Outputs (optional)
output "template_id" {
  value = data.unifiedpolicy_template.example.id
}

output "template_name" {
  value = data.unifiedpolicy_template.example.name
}

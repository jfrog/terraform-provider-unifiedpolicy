# Query a single rule by ID
data "unifiedpolicy_rule" "example" {
  id = "rule-12345"
}

# Outputs (optional)
output "rule_id" {
  value = data.unifiedpolicy_rule.example.id
}

output "rule_name" {
  value = data.unifiedpolicy_rule.example.name
}

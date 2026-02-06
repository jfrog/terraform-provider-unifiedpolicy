# Query a single lifecycle policy by ID
data "unifiedpolicy_lifecycle_policy" "example" {
  id = "policy-1001"
}

# Outputs (optional)
output "policy_id" {
  value = data.unifiedpolicy_lifecycle_policy.example.id
}

output "policy_name" {
  value = data.unifiedpolicy_lifecycle_policy.example.name
}

#!/usr/bin/env bash
# Usage: ./import.sh <policy_id>
# Example: ./import.sh policy-1001
terraform import unifiedpolicy_lifecycle_policy.example "$1"

#!/usr/bin/env bash
# Usage: ./import.sh <rule_id>
# Example: ./import.sh rule-1001
terraform import unifiedpolicy_rule.example "$1"

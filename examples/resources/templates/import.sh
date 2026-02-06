#!/usr/bin/env bash
# Usage: ./import.sh <template_id>
# Example: ./import.sh 1005
terraform import unifiedpolicy_template.example "$1"

## 1.0.0 (Feb 18, 2025). Tested on Artifactory 7.125.0 with Terraform 1.0+ and OpenTofu 1.0+

IMPROVEMENTS:

* GitHub: Add `.github` configuration for CI and community — release workflow, CLA Assistant, changelog check, Slack notifications (PRs and issues), Dependabot, issue templates (bug report, feature request), CODE_OF_CONDUCT, and release changelog categories.

FEATURES:

**Resources:**

* `unifiedpolicy_lifecycle_policy` - Manages lifecycle policies that define rules and enforcement actions for application versions at specific SDLC stages.
* `unifiedpolicy_template` - Manages templates: reusable logic (business rules) for policies using Rego policy language from a `.rego` file.
* `unifiedpolicy_rule` - Manages rules that define parameter values for policy evaluation and are based on rule templates.

**Data Sources:**

* `unifiedpolicy_lifecycle_policy` - Reads a single lifecycle policy by ID.
* `unifiedpolicy_lifecycle_policies` - Reads multiple lifecycle policies (with optional filters).
* `unifiedpolicy_template` - Reads a single template by ID.
* `unifiedpolicy_templates` - Reads multiple templates (with optional filters).
* `unifiedpolicy_rule` - Reads a single rule by ID.
* `unifiedpolicy_rules` - Reads multiple rules (with optional filters).

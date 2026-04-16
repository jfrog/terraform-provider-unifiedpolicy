## 1.0.2 (Apr 15, 2026). 

BUG FIXES:

* Data sources `unifiedpolicy_template` and `unifiedpolicy_lifecycle_policy` - `id` is now a string attribute to match API identifiers (previously modeled as an integer).

FEATURES:

**Resources:**

* `unifiedpolicy_lifecycle_policy` - `scope.type` may be `global`, `project`, or `application`; optional `scope.application_labels`; up to 10 `project_keys` and up to 10 `application_keys` per API limits; computed `created_at`, `created_by`, `updated_at`, `updated_by`.
* `unifiedpolicy_rule` - Computed `created_at`, `created_by`, `updated_at`, `updated_by`.
* `unifiedpolicy_template` - Computed `created_at`, `created_by`, `updated_at`, `updated_by`.

**Data Sources:**

* `unifiedpolicy_lifecycle_policies` - Optional filters `hierarchical` and `rule_names`; `sort_by` accepts `name`, `enabled`, `mode`, `resource`, `action`, and `created_at`.
* `unifiedpolicy_templates` - List entries include `created_at`, `created_by`, `updated_at`, `updated_by`.
* `unifiedpolicy_rules` - List entries include `created_at`, `created_by`, `updated_at`, `updated_by`.

IMPROVEMENTS:

* Documentation, examples (`lifecycle_policies`, `rules`, `templates`), and `sample.tf` updated for new attributes, scope types, and filters.
* Additional acceptance tests for lifecycle policies, templates, rules, and related data sources.

## 1.0.1 (Feb 23, 2026). Tested on Artifactory 7.125.0 with Terraform 1.0+ and OpenTofu 1.0+

IMPROVEMENTS:

* Provider documentation and templates aligned with other JFrog Terraform providers (index page, data source docs, examples README).

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

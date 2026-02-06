# Terraform Provider Unified Policy - Project Summary

## Overview

Terraform Provider for JFrog Unified Policy, providing resources and data sources to manage templates, rules, and lifecycle policies. Unified Policy is part of the JFrog Platform that provides lifecycle policy management capabilities for governing application versions at specific stages of the software development lifecycle (SDLC).

## Features Implemented

### Resources

1. **unifiedpolicy_lifecycle_policy**
   - Manages lifecycle policies that define rules and enforcement actions for application versions at specific SDLC stages
   - Supports enforcement mode, lifecycle actions (stage/gate), scope (project or application), and rule associations

2. **unifiedpolicy_template**
   - Manages templates: reusable logic (business rules) for policies using Rego policy language from a `.rego` file
   - Supports category, data_source_type, and Rego validation

3. **unifiedpolicy_rule**
   - Manages rules that define parameter values for policy evaluation and are based on rule templates
   - Supports template_id and parameters

### Data Sources

4. **unifiedpolicy_lifecycle_policy** - Reads a single lifecycle policy by ID.
5. **unifiedpolicy_lifecycle_policies** - Reads multiple lifecycle policies (with optional filters).
6. **unifiedpolicy_template** - Reads a single template by ID.
7. **unifiedpolicy_templates** - Reads multiple templates (with optional filters).
8. **unifiedpolicy_rule** - Reads a single rule by ID.
9. **unifiedpolicy_rules** - Reads multiple rules (with optional filters).

### Provider Configuration

The provider supports:
- Artifactory URL configuration
- Access Token authentication (recommended)
- API Key authentication (deprecated, for backward compatibility)
- Environment variable support for configuration
- Version compatibility checks for Artifactory and Xray

## Project Structure

```
terraform-provider-unifiedpolicy/
├── main.go                           # Provider entry point
├── go.mod                            # Go module definition
├── go.sum                            # Go module checksums
├── GNUmakefile                       # Build and test automation
├── LICENSE                           # Apache 2.0 license
├── NOTICE                            # Third-party attributions
├── README.md                         # User documentation
├── CHANGELOG.md                      # Version history
├── CODEOWNERS                        # Code ownership
├── CONTRIBUTING.md                   # Contribution guidelines (CLA, PR process)
├── CONTRIBUTIONS.md                  # Contribution guide (building, testing)
├── PROJECT_SUMMARY.md                # This file
├── RELEASE_PROCESS.md                # Release process documentation
├── releaseUnifiedPolicyProvider.sh   # Release automation script
├── sample.tf                         # Sample Terraform configuration
├── terraform-registry-manifest.json  # Terraform registry metadata
├── pkg/unifiedpolicy/
│   ├── unifiedpolicy.go              # Package-level utilities
│   ├── provider/
│   │   ├── framework.go              # Provider framework implementation
│   │   └── provider.go               # Provider version and constants
│   ├── resource/                     # Resource implementations
│   │   ├── resource_lifecycle_policy.go
│   │   ├── resource_template.go
│   │   ├── resource_rule.go
│   │   └── *_test.go
│   ├── datasource/                   # Data source implementations
│   │   ├── data_source_lifecycle_policy.go
│   │   ├── data_source_lifecycle_policies.go
│   │   ├── data_source_template.go
│   │   ├── data_source_templates.go
│   │   ├── data_source_rule.go
│   │   ├── data_source_rules.go
│   │   └── *_test.go
│   └── acctest/
│       └── test.go                   # Acceptance test helpers
├── docs/
│   ├── index.md                      # Provider documentation
│   ├── data-sources/                 # Data source documentation
│   └── resources/                    # Resource documentation
├── templates/
│   ├── index.md.tmpl                 # Provider doc template
│   ├── data-sources/                 # Data source doc templates
│   └── resources/                    # Resource doc templates
├── examples/
│   ├── provider/
│   ├── resources/
│   └── datasources/
└── tools/
    └── tools.go                      # Build tools
```

## Provider Configuration

The provider supports multiple authentication methods:

1. **Access Token** (Recommended) - Via configuration or `JFROG_ACCESS_TOKEN` / `ARTIFACTORY_ACCESS_TOKEN` environment variable
2. **API Key** (Deprecated) - For backward compatibility

Example configuration:

```terraform
terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "~> 1.0"
    }
  }
}

provider "unifiedpolicy" {
  url          = "https://myinstance.jfrog.io/artifactory"
  access_token = var.jfrog_access_token
}
```

## Building the Provider

```bash
# Initialize dependencies
go mod tidy

# Build the provider
make build

# Install locally for testing
make install

# Run tests
make test

# Run acceptance tests
make acceptance

# Generate documentation
make doc
```

## Key Dependencies

| Dependency | Purpose |
|------------|---------|
| terraform-plugin-framework | Terraform provider framework |
| terraform-plugin-framework-validators | Schema validators |
| terraform-plugin-testing | Acceptance testing |
| terraform-provider-shared | JFrog shared utilities |
| go-resty/resty | HTTP client |
| samber/lo | Go utilities |
| open-policy-agent/opa | Rego validation for templates |

## OpenTofu Support

This provider is compatible with OpenTofu. Releases are published to both:
- Terraform Registry: `registry.terraform.io/jfrog/unifiedpolicy`
- OpenTofu Registry: `registry.opentofu.org/jfrog/unifiedpolicy`

## Development Notes

- Built with Terraform Plugin Framework
- Uses JFrog shared library for common functionality
- Compatible with Go 1.24+
- Supports Terraform 1.0+ and OpenTofu 1.0+
- All source files include Apache 2.0 copyright headers

## Current Version

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## License

Apache 2.0 - Copyright (c) 2025 JFrog Ltd

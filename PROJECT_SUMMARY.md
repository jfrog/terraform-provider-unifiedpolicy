# Terraform Provider Unified Policy - Project Summary

## Overview

A Terraform provider for managing JFrog Unified Policy lifecycle policies using Infrastructure as Code. Unified Policy is part of the JFrog Platform that provides lifecycle policy management capabilities for governing application versions at specific stages of the software development lifecycle (SDLC).

## Features Implemented

### Provider Configuration

The provider supports:
- Artifactory URL configuration
- Access Token authentication (recommended)
- API Key authentication (deprecated, for backward compatibility)
- Environment variable support for configuration
- Version compatibility checks for Artifactory and Xray

### Minimum Requirements

- **Artifactory**: 7.125.0 or later
- **Xray**: 3.130.5 or later
- **License**: Enterprise Plus (E+) with AppTrust entitlements
- **Terraform**: 1.0 or later

## Project Structure

```
terraform-provider-unifiedpolicy/
├── main.go                           # Provider entry point
├── go.mod                            # Go module definition
├── go.sum                            # Go module checksums
├── GNUmakefile                       # Build and test automation
├── LICENSE                           # Apache 2.0 license
├── README.md                         # User documentation
├── CHANGELOG.md                      # Version history
├── CODEOWNERS                        # Code ownership
├── CONTRIBUTING.md                   # Contribution guidelines
├── CONTRIBUTIONS.md                  # Contribution guidelines (runtime pattern)
├── NOTICE                            # Third-party attributions
├── PROJECT_SUMMARY.md                # This file
├── RELEASE_PROCESS.md                # Release process documentation
├── releaseUnifiedPolicyProvider.sh    # Release automation script
├── sample.tf                         # Sample Terraform configuration
├── terraform-registry-manifest.json  # Terraform registry metadata
├── pkg/unifiedpolicy/
│   ├── unifiedpolicy.go              # Package-level utilities
│   ├── provider/
│   │   ├── framework.go              # Provider framework implementation
│   │   └── provider.go               # Provider version and constants
│   ├── resource/                     # Resource implementations
│   └── datasource/                   # Data source implementations
├── docs/
│   ├── index.md                      # Provider documentation
│   ├── data-sources/                 # Data source documentation
│   └── resources/                    # Resource documentation
├── templates/
│   ├── index.md.tmpl                 # Documentation template
│   └── resources/                    # Resource templates
└── tools/
    └── tools.go                      # Build tools
```

## Provider Configuration

The provider supports multiple authentication methods:

1. **Access Token** (Recommended) - Via configuration or environment variable
2. **API Key** (Deprecated) - For backward compatibility

Example configuration:

```terraform
provider "unifiedpolicy" {
  url          = "https://your-instance.jfrog.io/artifactory"
  access_token = "my-access-token"
}
```

Environment variables:
- `JFROG_URL` or `ARTIFACTORY_URL` - Artifactory URL
- `JFROG_ACCESS_TOKEN` or `ARTIFACTORY_ACCESS_TOKEN` - Access token
- `ARTIFACTORY_API_KEY` or `JFROG_API_KEY` - API key (deprecated)

## API Endpoints

The provider interacts with the Unified Policy API through the Artifactory REST API:

- `POST /unifiedpolicy/api/v1/policies` - Create lifecycle policy
- `GET /unifiedpolicy/api/v1/policies` - List lifecycle policies
- `GET /unifiedpolicy/api/v1/policies/{policyId}` - Get lifecycle policy
- `PUT /unifiedpolicy/api/v1/policies/{policyId}` - Update lifecycle policy
- `DELETE /unifiedpolicy/api/v1/policies/{policyId}` - Delete lifecycle policy

### Lifecycle Policy Management

Lifecycle policies are governance controls that define:
- **Conditions** to check (e.g., CVEs, licenses, evidence requirements)
- **Actions** to take when conditions are met (`block` to fail promotion, `warning` to allow with violation)
- **Scope** (project-level or application-level)
- **Lifecycle gates** (entry, exit, release) at specific stages

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
```

## Usage Examples

### Basic Provider Configuration

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
  url          = "https://your-instance.jfrog.io/artifactory"
  access_token = var.access_token
}
```

### Example Resource (when implemented)

```terraform
resource "unifiedpolicy_lifecycle_policy" "example" {
  name        = "Production Security Policy"
  description = "Block promotion on Critical CVEs"
  enabled     = true
  mode        = "block"
  
  action {
    type = "certify_to_gate"
    stage {
      key  = "production"
      gate = "entry"
    }
  }
  
  scope {
    type         = "project"
    project_keys = ["my-project"]
  }
  
  rule_ids = ["rule-12345", "rule-67890"]
}
```

## Security Considerations

1. **License Requirements**: Unified Policy requires Enterprise Plus license with AppTrust entitlements
2. **Sensitive Data**: Access tokens and API keys are marked as sensitive in Terraform
3. **Version Compatibility**: The provider validates minimum Artifactory and Xray versions
4. **TLS Verification**: Can be bypassed for testing using `JFROG_BYPASS_TLS_VERIFICATION` environment variable (not recommended for production)

## Development Notes

- Built with Terraform Plugin Framework (v1.16.1)
- Uses JFrog shared library (v1.30.6) for common functionality
- Follows patterns established by other JFrog Terraform providers
- Compatible with Go 1.24.0+
- Supports Terraform 1.0+
- Uses Terraform Protocol v6.0

## Version

Current version: 1.0.0

## Dependencies

Key dependencies:
- github.com/hashicorp/terraform-plugin-framework v1.16.1
- github.com/jfrog/terraform-provider-shared v1.30.6
- github.com/hashicorp/terraform-plugin-docs v0.24.0
- github.com/hashicorp/terraform-plugin-framework-validators v0.19.0

## Next Steps

1. Implement Unified Policy resources (lifecycle policies)
2. Implement Unified Policy data sources
3. Add unit tests for resources and data sources
4. Add acceptance tests
5. Set up CI/CD pipeline
6. Prepare for Terraform Registry publication
7. Add additional Unified Policy API endpoints as needed

## License

Apache 2.0 - Copyright (c) 2025 JFrog Ltd


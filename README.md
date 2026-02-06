# Terraform Provider for JFrog Unified Policy

## Quick Start

Create a new Terraform file with `unifiedpolicy` provider:

### HCL Example

```terraform
# Required for Terraform 1.0 and later
terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "1.0.0"
    }
  }
}

provider "unifiedpolicy" {
  url = "https://myinstance.jfrog.io/artifactory"
  // supply JFROG_ACCESS_TOKEN (Identity Token with Admin privileges) as env var
}
```

Initialize Terraform:
```sh
$ terraform init
```

Plan (or Apply):
```sh
$ terraform plan
```

Detailed documentation of resources and attributes will be available on [Terraform Registry](https://registry.terraform.io/providers/jfrog/unifiedpolicy/latest/docs).

## Resources and Data Sources

Resources and data sources will be documented here as they are implemented.

### Planned Resources

- **unifiedpolicy_lifecycle_policy**: Manages lifecycle policies that define rules and enforcement actions for application versions at specific SDLC stages.

## Local Development

For local development, you can use `dev_overrides` to test the provider without publishing it to the registry.

### Quick Setup

1. **Set up dev_overrides** (one-time setup):
   ```bash
   ./setup-dev-overrides.sh
   ```
   Or manually create/update `~/.terraformrc`:
   ```hcl
   provider_installation {
     dev_overrides {
       "jfrog/unifiedpolicy" = "/absolute/path/to/terraform-provider-unifiedpolicy"
     }
     direct {}
   }
   ```

2. **Build and install the provider**:
   ```bash
   make dev-install
   ```

3. **Use Terraform commands directly** (no need for `terraform init`):
   ```bash
   terraform validate
   terraform plan
   terraform apply
   ```

See [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for contribution guidelines and troubleshooting.

## Prerequisites

Before creating lifecycle policies, you must have the following resources in your JFrog Platform instance:

1. **Templates** - Define the logic (Rego policies) for rules
2. **Rules** - Reference templates and are enforced by policies
3. **Projects** - Required for project-scoped policies
4. **Applications** - Required for application-scoped policies
5. **Lifecycle Stages** - Stages referenced in policy actions (e.g., PROD, qa, DEV)
6. **Lifecycle Gates** - Gates for each stage (entry, exit, release)

**📖 See the [Terraform Registry documentation](https://registry.terraform.io/providers/jfrog/unifiedpolicy/latest/docs) for setup and examples.**

## Requirements

- Terraform 1.0+
- Artifactory 7.125.0 or later
- Xray 3.130.5 or later
- Enterprise Plus license with AppTrust entitlements
- Access Token with Admin privileges

## Authentication

The provider supports the following authentication methods:

1. **Access Token** (recommended): Set via `access_token` attribute or `JFROG_ACCESS_TOKEN` or `ARTIFACTORY_ACCESS_TOKEN` environment variable
2. **API Key** (deprecated): Set via `api_key` attribute or `ARTIFACTORY_API_KEY` or `JFROG_API_KEY` environment variable

## API Endpoints

This provider uses the JFrog Unified Policy API (`/unifiedpolicy/api/v1/policies`) to manage lifecycle policies. Lifecycle policies define the rules and enforcement actions that apply to applications at specific stages of the software development lifecycle (SDLC).

### Lifecycle Policy Management

Lifecycle policies are governance controls that define:
- **Conditions** to check (e.g., CVEs, licenses, evidence requirements)
- **Actions** to take when conditions are met (`block` to fail promotion, `warning` to allow with violation)
- **Scope** (project-level or application-level)
- **Lifecycle gates** (entry, exit, release) at specific stages

## Versioning

In general, this project follows [semver](https://semver.org/) as closely as we can for tagging releases of the package. We've adopted the following versioning policy:

* We increment the **major version** with any incompatible change to functionality, including changes to the exported Go API surface or behavior of the API.
* We increment the **minor version** with any backwards-compatible changes to functionality.
* We increment the **patch version** with any backwards-compatible bug fixes.

## License

Copyright (c) 2025 JFrog.

Apache 2.0 licensed, see [LICENSE][LICENSE] file.

[LICENSE]: ./LICENSE


# Release Process for Terraform Provider Unified Policy

## Overview

The `releaseUnifiedPolicyProvider.sh` script automates the process of creating a new release for the terraform-provider-unifiedpolicy.

## Prerequisites

- Clean working tree (no uncommitted changes)
- Access to push to the repository
- Git configured with appropriate credentials

## Usage

### Interactive Mode (Recommended)

```bash
./releaseUnifiedPolicyProvider.sh
```

The script will:
1. Fetch and display the latest version from GitHub
2. Prompt you to enter the new version number
3. Ask for confirmation at each step

### Non-Interactive Mode

For CI/CD or automation:

```bash
NEW_VERSION=1.0.1 ./releaseUnifiedPolicyProvider.sh -y
```

or

```bash
export NEW_VERSION=1.0.1
./releaseUnifiedPolicyProvider.sh -y
```

The `-y` flag automatically answers "yes" to all prompts.

## What the Script Does

The script performs the following steps:

1. **Version Check**: Fetches the latest stable version from GitHub
2. **Input Validation**: Validates the new version follows SemVer (e.g., 1.2.3)
3. **Safety Checks**:
   - Ensures working tree is clean
   - Verifies the tag doesn't already exist
4. **Git Workflow**:
   - Checks out the default branch (main)
   - Pulls the latest code
   - Creates a new release branch (e.g., `v1.0.1`)
   - Pushes the branch to origin
   - Creates a new tag (e.g., `v1.0.1`)
   - Pushes the tag to origin

## Version Format

Versions must follow SemVer format: `MAJOR.MINOR.PATCH`

Examples:
- ✅ `1.0.0`
- ✅ `v1.0.0` (will be normalized to `v1.0.0`)
- ✅ `1.2.3`
- ❌ `1.0` (missing patch version)
- ❌ `1.0.0-beta` (pre-release versions not supported by this script)

## Release Workflow

Once the tag is pushed, the GitHub Actions workflow (`.github/workflows/release.yml`) will:

1. Trigger automatically on tag push
2. Build the provider for multiple platforms
3. Sign the release with GPG
4. Create a GitHub release
5. Upload artifacts to the release

## Example Session

```bash
$ ./releaseUnifiedPolicyProvider.sh

--- Fetching Latest Stable Provider Versions ---
Latest version for terraform-provider-unifiedpolicy: v1.0.0
-------------------------------------

Using provider: terraform-provider-unifiedpolicy
Please enter the new version number (e.g., 1.2.3): 1.0.1

--- Starting release process for provider 'terraform-provider-unifiedpolicy' and version v1.0.1 ---

About to checkout branch 'main'...
Proceed to checkout 'main'? (y/n) y

About to pull latest code from 'main'...
Proceed to pull from 'main'? (y/n) y

About to create and checkout new release branch: v1.0.1...
Proceed to create branch 'v1.0.1'? (y/n) y

About to push new branch to origin: v1.0.1...
Proceed to push branch 'v1.0.1' to origin? (y/n) y

About to create new tag: v1.0.1...
Proceed to create tag 'v1.0.1'? (y/n) y

About to push new tag to origin: v1.0.1...
Proceed to push tag 'v1.0.1' to origin? (y/n) y

--- Release process completed successfully for terraform-provider-unifiedpolicy! ---
```

## Troubleshooting

### Working Tree Has Uncommitted Changes

**Error**: "Your working tree has uncommitted changes."

**Solution**: 
- Commit or stash your changes
- Or answer "y" when prompted to proceed anyway (not recommended)

### Tag Already Exists

**Error**: "Tag v1.0.1 already exists locally or on origin."

**Solution**:
- Choose a different version number
- Or delete the existing tag if it was created in error:
  ```bash
  git tag -d v1.0.1
  git push origin :refs/tags/v1.0.1
  ```

### Permission Denied

**Error**: Unable to push to origin

**Solution**:
- Verify you have push access to the repository
- Check your Git credentials
- Ensure you're authenticated with GitHub

## Manual Release (Alternative)

If you prefer to do it manually without the script:

```bash
# 1. Checkout and update main branch
git checkout main
git pull --ff-only

# 2. Create release branch
git checkout -b v1.0.1

# 3. Push branch
git push -u origin v1.0.1

# 4. Create and push tag
git tag v1.0.1
git push origin tag v1.0.1
```

## Post-Release

After the release is created:

1. Monitor the GitHub Actions workflow for successful completion
2. Verify the release appears on the [Releases page](https://github.com/jfrog/terraform-provider-unifiedpolicy/releases)
3. Update documentation if needed
4. Announce the release to stakeholders

## Notes

- The script auto-detects the default branch (main or master)
- Each step requires confirmation unless `-y` flag is used
- The script will exit immediately if any command fails (set -e)
- Tags pushed to GitHub trigger the automated release workflow


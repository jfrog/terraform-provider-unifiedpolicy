# Contribution Guide

## Contributors

Pull requests, issues and comments are welcomed. For pull requests:

* Add tests for new features and bug fixes
* Follow the existing style
* Separate unrelated changes into multiple pull requests

See the existing issues for things to start contributing.

For bigger changes, make sure you start a discussion first by creating an issue and explaining the intended change.

JFrog requires contributors to sign a Contributor License Agreement, known as a CLA. This serves as a record stating that the contributor is entitled to contribute the code/documentation/translation to the project and is willing to have it used in distributions and derivative works (or is willing to transfer ownership).

## Building

Simply run `make install` - this will compile the provider and install it to `~/.terraform.d`. When running this, it will take the current tag and bump it 1 patch version. It does not actually create a new tag. If you wish to use the locally installed provider, make sure your TF script refers to the new version number.

Requirements:
- [Terraform](https://www.terraform.io/downloads.html) 1.0+
- [Go](https://golang.org/doc/install) 1.24+ (to build the provider plugin)

## Debugging

See [debugging wiki](https://github.com/jfrog/terraform-provider-artifactory/wiki/Debugging).

## Testing

First, you need a running instance of the JFrog Platform with Unified Policy (Artifactory 7.125.0+, Xray 3.130.5+, Enterprise Plus with AppTrust).

Then, you have to set some environment variables as this is how the acceptance tests pick up their config.

```sh
JFROG_URL=https://myinstance.jfrog.io/artifactory
JFROG_ACCESS_TOKEN=<your_access_token>
TF_ACC=true
```

A crucial env var to set is `TF_ACC=true` - you can literally set `TF_ACC` to anything you want, so long as it's set. The acceptance tests use terraform testing libraries that, if this flag isn't set, will skip all tests.

You can then run the tests as

```sh
$ go test -v -p 1 ./pkg/...
```

Or

```sh
$ make acceptance
```

**DO NOT** remove the `-v` - terraform testing needs this. This will recursively run all tests, including acceptance tests.

## Releasing

Please create a pull request against the master branch. Each pull request will be reviewed by a member of the JFrog team.

#### Thank you for contributing!

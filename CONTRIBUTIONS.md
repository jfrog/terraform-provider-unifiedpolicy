# How to Contribute

We'd love to accept your patches and contributions to this project. There are just a few guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License Agreement. You (or your employer) retain the copyright to your contribution; this simply gives us permission to use and redistribute your contributions as part of the project. Head over to <https://cla.jfrog.com/> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for a different project), you probably don't need to do it again.

## Building The Provider

Clone repository to: `$GOPATH/src/github.com/jfrog/terraform-provider-unifiedpolicy`

```sh
$ mkdir -p $GOPATH/src/github.com/jfrog
$ cd $GOPATH/src/github.com/jfrog
$ git clone git@github.com:jfrog/terraform-provider-unifiedpolicy
```

Enter the provider directory and build the provider

```sh
$ cd $GOPATH/src/github.com/jfrog/terraform-provider-unifiedpolicy
$ make build
```

## Testing

To run the full suite of Acceptance tests, run `make acceptance`.

*Note:* Acceptance tests create real resources, and often cost money to run. You should expect that the full acceptance test suite will take hours to run.

```sh
$ make acceptance
```

## Generating Documentation

To generate documentation, run:

```sh
$ make doc
```

## Code reviews

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.


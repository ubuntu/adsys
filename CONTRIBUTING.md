# Contributing to ADSys

A big welcome and thank you for considering contributing to ADSys and Ubuntu! It’s people like you that make it a reality for users in our community.

Reading and following these guidelines will help us make the contribution process easy and effective for everyone involved. It also communicates that you agree to respect the time of the developers managing and developing this project. In return, we will reciprocate that respect by addressing your issue, assessing changes, and helping you finalize your pull requests.

These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Quicklinks

* [Code of Conduct](#code-of-conduct)
* [Getting Started](#getting-started)
* [Issues](#issues)
* [Pull Requests](#pull-requests)
* [Getting Help](#getting-help)

## Code of Conduct

We take our community seriously and hold ourselves and other contributors to high standards of communication. By participating and contributing to this project, you agree to uphold our [Code of Conduct](https://ubuntu.com/community/code-of-conduct).

## Getting Started

Contributions are made to this project via Issues and Pull Requests (PRs). A few general guidelines that cover both:

* To report security vulnerabilities, please use [launchpad ADSys private bugs](https://bugs.launchpad.net/ubuntu/+source/adsys/+filebug) which is monitored by our security team. On ubuntu machine, it’s best to use `ubuntu-bug adsys` to collect relevant information.
* Search for existing Issues and PRs before creating your own.
* We work hard to makes sure issues are handled in a timely manner but, depending on the impact, it could take a while to investigate the root cause. A friendly ping in the comment thread to the submitter or a contributor can help draw attention if your issue is blocking.
* If you've never contributed before, see [this Ubuntu discourse post](https://discourse.ubuntu.com/t/contribute/26) for resources and tips on how to get started.

### Issues

Issues should be used to report problems with the software, request a new feature, or to discuss potential changes before a PR is created. When you create a new Issue, a template will be loaded that will guide you through collecting and providing the information we need to investigate.

If you find an Issue that addresses the problem you're having, please add your own reproduction information to the existing issue rather than creating a new one. Adding a [reaction](https://github.blog/2016-03-10-add-reactions-to-pull-requests-issues-and-comments/) can also help be indicating to our maintainers that a particular problem is affecting more than just the reporter.

### Pull Requests

PRs to our project are always welcome and can be a quick way to get your fix or improvement slated for the next release. In general, PRs should:

* Only fix/add the functionality in question **OR** address wide-spread whitespace/style issues, not both.
* Add unit or integration tests for fixed or changed functionality.
* Address a single concern in the least number of changed lines as possible.
* Include documentation in the repo or on our [docs site](https://github.com/ubuntu/adsys/wiki).
* Be accompanied by a complete Pull Request template (loaded automatically when a PR is created).

For changes that address core functionality or would require breaking changes (e.g. a major release), it's best to open an Issue to discuss your proposal first. This is not required but can save time creating and reviewing changes.

In general, we follow the ["fork-and-pull" Git workflow](https://github.com/susam/gitpr)

1. Fork the repository to your own Github account
1. Clone the project to your machine
1. Create a branch locally with a succinct but descriptive name
1. Commit changes to the branch
1. Following any formatting and testing guidelines specific to this repo
1. Push changes to your fork
1. Open a PR in our repository and follow the PR template so that we can efficiently review the changes.

> PRs will trigger unit and integration tests with and without race detection, linting and formatting validations, static and security checks, freshness of generated files verification. All the tests must pass before merging in main branch.

Once merged to the main branch, `po` files, `README.md` with the command line reference and any documentation change will be automatically updated. Those are thus not necessary in the pull request itself to minimize diff review.

## Contributing to the documentation

You can also contribute to the documentation. It uses [GitHub Markdown Format](https://docs.github.com/en/github/writing-on-github/getting-started-with-writing-and-formatting-on-github).

You can propose modifications in 2 ways:

* Directly on the repo, in the `doc/` directory. Once merged, this will update the repository wiki automatically.
* Via the [edit wiki link](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages#editing-wiki-pages) of this repository. Once merged, this will update the main repository automatically.

Each page is a different chapter, ordered with numbers, which is available with the command `adsysctl doc`.

## Contributing to the code

### Required dependencies

The project requires the following dependencies:

* Samba C library and Python bindings.
* PAM library.
* C Dbus library and executables.

On Ubuntu system, you can refer to `debian/control` and install them with `apt build-dep .` in the root directory of the project.

### Building and running the binaries

You can build adsys with `go build ./cmd/adsysd`. This will create an `adsysd` for the daemon. Create a symlink named `adsysctl` pointing to it to get the client (`ln -s adsysd adsysctl`).

As you will generally not run on a system connected to a real Active Directory system, you can use the sample configuration file `conf.example/adsys.yaml` to avoid a functional Kerberos and SSSD configuration. (`--config conf.example/adsys.yaml`). This configuration doesn’t require the `adsysd` daemon to run as root.

You can try an updated shell completion with your local command:

```sh
PATH=.:$PATH
. <(adsysd completion)
. <(adsysctl completion)
```

### Building the PAM module

```sh
$ cd pam/
$ go generate .
```

The PAM module will be built and copied in `<project_root>/generated/lib/security/`.

### About the testsuite

The project includes a comprehensive testsuite made of unit and integration tests. All the tests must pass with and without the race detector.

You can run all tests with: `go test ./...` (add `-race` for race detection).

Every packages have a suite of at least package-level tests. They may integrate more granular unit tests for complex functionalities. Integration tests are located in `cmd/adsys/integration_tests/`.

The test suite must pass before merging the PR to our main branch. Any new feature, change or fix must be covered by corresponding tests.

## Contributor Licence Agreement

It is required to sign the [Contributor Licence Agreement](https://ubuntu.com/legal/contributors) in order to contribute to this project.

An automated test is executed on PRs to check if it has been accepted.

This project is covered by [GPL-3.0 License](LICENSE).

## Getting Help

Join us in the [Ubuntu Community](https://discourse.ubuntu.com/c/desktop/8) and post your question there with a descriptive tag.

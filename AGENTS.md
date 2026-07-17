# ADSys AI Coding Instructions

## Project Overview

ADSys is the Active Directory Group Policy client for Ubuntu. It complements
SSSD or Winbind: those components handle domain enrollment and authentication,
while ADSys fetches, parses, and applies GPOs to Ubuntu machines and users.

The project is primarily Go, with a small C PAM module, Python helpers, Debian
packaging, and a Windows companion service.

- **`adsysd` / `adsysctl`** (`cmd/adsysd/`): one Go binary acting as either the
  privileged daemon or the CLI according to its executable name.
- **`adwatchd`** (`cmd/adwatchd/`): Windows and Linux service and TUI that watch
  policy asset changes and update the corresponding `GPT.ini` version.
- **`admxgen`** (`cmd/admxgen/`): generates ADMX/ADML policy definitions.
- **PAM module** (`pam/`): triggers policy updates during authentication.

See `docs/explanation/adsys-ref-arch.md` for the user-facing architecture.

## Architecture Fundamentals

### Policy flow

1. SSSD or Winbind authenticates a domain user.
2. The PAM integration invokes `adsysctl`, which asks `adsysd` to update policy
   over the gRPC API defined in `adsys.proto`.
3. `internal/ad/` determines the applicable GPOs, downloads SYSVOL policy files
   and assets, and caches them.
4. `internal/policies/` parses the GPOs and delegates application to policy
   managers such as dconf, privilege, scripts, mount, GDM, AppArmor, proxy, and
   certificate.

ADSys applies configuration; it does not continuously enforce all configured
subsystems. Follow the failure semantics documented at the top of
`internal/policies/manager.go`: failures to parse or install policy generally
block authentication, while failures in the configured workload generally
warn the user.

### Key directories

- `internal/ad/`: AD access, SSSD/Winbind backends, GPO download and registry
  parsing.
- `internal/adsysservice/`: gRPC service implementation and policy operations.
- `internal/policies/`: policy orchestration and individual policy managers.
- `internal/grpc/`: shared gRPC interceptors, logging, and connection helpers.
- `internal/testutils/`: common fixtures, mocks, golden files, and system test
  helpers.
- `policies/`: Ubuntu policy definition sources.
- `generated/`: generated PAM, completion, manpage, and policy artifacts.
- `docs/`: Sphinx/MyST documentation; much of `docs/reference/` is generated.
- `debian/`: package metadata, build rules, and autopkgtests.
- `e2e/`: Azure-backed end-to-end image and test tooling.

## Building and Generating

Install native build dependencies on Ubuntu with:

```bash
sudo apt build-dep .
```

This requires source package repositories (`deb-src`) to be enabled; they are
off by default on recent Ubuntu releases.

Use the Go and toolchain versions declared in `go.mod`. Everyday builds use the
Go module cache; the `vendor/` directory is `.gitignore`d and generated only at
Debian source-package build time (see `debian/rules`).

```bash
go build ./...             # Build all packages for the current platform
go build ./cmd/adsysd      # Build the Linux daemon/client binary
ln -s adsysd adsysctl      # Select client behavior through argv[0]
```

The sample configuration at `conf.example/adsys.yaml` permits local development
without a functional AD, Kerberos, or SSSD setup:

```bash
./adsysd --config conf.example/adsys.yaml
```

### Code generation

Run generation for the affected surface and inspect the resulting diff:

```bash
go generate .                         # Root protobuf API
go generate ./cmd/adsysd              # Completions, manpages, and CLI docs
go generate -x -tags=tools ./pam      # PAM module in generated/lib/security/
```

Other packages contain targeted `go:generate` directives. Do not hand-edit
generated protobuf files or artifacts under `generated/`. Do not directly edit
generated reference documentation; change its Go or YAML source instead.
`CONTRIBUTING.md` documents which generated documentation is refreshed after
merge. In particular, do not include post-merge updates to `po/`, `README.md`,
or generated documentation in a routine pull request.

When changing dependencies, update `go.mod` and `go.sum` (for example with
`go mod tidy`). Do not create or commit a `vendor/` directory: it is
`.gitignore`d and regenerated during packaging. Keep build tools in the
separate `tools` module.

## Testing

Run focused tests while iterating, then the broadest relevant suite:

```bash
go test -run TestName ./internal/policies/...   # Focused package/test
go test ./...
go test -race ./...
```

Some integration tests require native services, the system-daemons container,
or root. CI runs the root-required package list from
`debian/tests/.sudo-packages` with:

```bash
sudo -E "$(which go)" test ./cmd/adwatchd/integration_tests ./internal/watchdtui
```

Set `ADSYS_SKIP_INTEGRATION_TESTS=1` only when the environment cannot support
integration tests; state explicitly which tests were skipped. Windows CI also
uses this variable to omit integration tests under the race detector because
of external named-pipe failures.

### Testing conventions

- Add unit or integration coverage for every behavioral fix or feature.
- Prefer table-driven tests and the existing `testify` style in the package.
- Reuse helpers and mocks from `internal/testutils/`.
- Put test-only exports in `export_test.go`; do not expand production APIs only
  to make code testable.
- Golden files are managed by `internal/testutils/golden.go`. Update them with
  `TESTS_UPDATE_GOLDEN=1 go test <affected-packages>`, then review every changed
  fixture rather than accepting updates blindly.
- Preserve cross-platform behavior. Linux-only code needs appropriate build
  constraints; changes to `adwatchd`, `watchdservice`, `watchdtui`, `watcher`,
  or `config/watchd` must account for Windows.

The full end-to-end suite provisions real infrastructure and is not a routine
local validation step. See `e2e/README.md`.

## Code Style and Linting

- Follow idiomatic Go and existing package patterns.
- Run `gofmt`/`go fmt` on Go changes. Import grouping is enforced by `gci`.
- Run `golangci-lint run ./...` using the version tracked in `tools/go.mod`.
- Run `clang-format` on changed C and header files under `pam/`.
- Every `//nolint` directive must name the linter and explain the exception, as
  required by `.golangci.yaml`.
- Wrap errors with useful operational context and preserve errors for
  inspection where appropriate.
- Use the existing `internal/grpc/logstreamer` logging path for daemon/client
  operations where callers need streamed logs.
- Wrap user-facing strings with the repository's `gotext` localization pattern.

## Project-Specific Guidance

### Privileged and security-sensitive behavior

ADSys writes system configuration and runs as a privileged daemon. Treat paths,
file modes, ownership, symlinks, downloaded assets, command execution, and
Kerberos material as security boundaries. Reuse existing safe path and
filesystem helpers, and do not weaken validation to make a test pass.

Policy application is serialized per target object. Preserve the locking and
cache invariants in `internal/ad/` and `internal/policies/`; avoid holding broad
locks across network access, parsing, or external commands.

### Documentation and policy definitions

For changes under [`docs/`](docs/), follow the scoped
[documentation agent guide](docs/AGENTS.md).

Update documentation when user-visible behavior changes. Build or lint docs
with the targets in `docs/Makefile`, for example:

```bash
make -C docs html
make -C docs lint-md
```

Policy changes may affect YAML sources, generated ADMX/ADML output, embedded
documentation, and policy build checks. Trace the relevant generator rather
than patching only its output.

### Debugging

Use the sample configuration for development without AD. Increase CLI verbosity
with `-v`, `-vv`, or `-vvv`. Stream daemon and client logs with:

```bash
adsysctl service cat -vvv
```

For system-service failures, inspect the current boot and unit directly:

```bash
journalctl -b 0 -u adsysd.service
systemctl status adsysd.service
```

### Scope discipline

Follow `CONTRIBUTING.md`: keep a pull request focused on one concern, minimize
unrelated changes, and do not combine functional work with broad formatting.
Do not update `debian/changelog` unless the task is specifically release or
packaging work.

## Git Usage

Always disable pagers for Git commands that may invoke one:

```bash
git --no-pager diff
git --no-pager show
git --no-pager log
```

Leave agent-authored changes uncommitted unless the user explicitly asks for a
commit. Never discard or overwrite unrelated worktree changes.

When asked to commit, make each commit one coherent, self-contained logical
change. Explain why rather than narrating the diff:

- For bug fixes, describe the observable symptom before the root cause.
- Document non-obvious decisions and rejected alternatives.
- Keep the subject at 72 characters or fewer and wrap body lines at 72
  characters, except for indivisible URLs.
- Use `git commit -F -` for multiline messages so wrapping is explicit.

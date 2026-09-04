## Overview

This project is the `sssd` charm, a subordinate Juju machine charm that
automates the full lifecycle of the `sssd` service on Charmed HPC
nodes that need to be enrolled with a remote LDAP server. The charm implements the
observer design pattern from UHPC010 using `charmed-hpc-libs`. Source lives in
`src/`; unit tests in `tests/unit/`; BDD integration tests in
`tests/integration/`; a CC008-compliant Terraform module in `terraform/`.

The source layout is:

```text
.
├── src
│   ├── charm.py                     # Entrypoint; defines SSSDCharm
│   ├── sssd.py                      # Workload manager (SSSDManager, SSSDConfigManager)
│   ├── state.py                     # refresh hook (check_sssd)
│   ├── constants.py                 # Integration names
│   ├── integrations/                # Integration observers (UHPC010)
│   │   ├── __init__.py
│   │   ├── ldap.py                  # ldap interface observer
│   │   └── certificate_transfer.py  # certificate_transfer interface observer
│   └── operations/                  # Operations observers (UHPC010)
│       ├── __init__.py
│       └── lifecycle.py             # install/stop observer
├── terraform                        # CC008-compliant Terraform module
├── tests
│   ├── unit
│   │   ├── conftest.py
│   │   ├── observers/               # Observer unit tests
│   │   ├── test_charm.py
│   │   ├── test_sssd.py
│   │   └── test_state.py
│   └── integration
│       ├── features                 # Auto-generated gherkin feature files
│       └── plans                    # gherkinator YAML test plans
```

The project uses:

- `uv` for dependency management and packaging.
- `just` as the task runner (see `justfile`).
- `ruff` for formatting and linting, `codespell` for spell checking.
- `pyright` for static type checking.
- `ops` (latest) and `charmed-hpc-libs` for charm primitives.
- `charmlibs-interfaces-ldap` and `charmlibs-interfaces-certificate-transfer`
  for integration interface implementations (replacing deprecated vendored
  charm libraries).
- `pydantic` v2 (transitive, via `charmlibs.interfaces.*` and
  `charmed-hpc-libs`).
- `ops.testing` for unit tests; `coverage.py` with branch coverage on
  `src/**/*.py`.
- `jubilant` + `gherkinator` + `pytest-jubilant-bdd` for BDD integration
  tests.
- `charmcraft` (with the `uv` plugin) to build the charm.

### Supported versions

- **Base:** Ubuntu 26.04.
- **Runtime:** Python 3.14.
- **`ops`:** latest stable. Do not pin to an older series.
- **`pydantic`:** v2 only. Do not introduce `pydantic` v1 patterns
  (`pydantic.BaseModel` `class Config:` inner classes, `v1` validator
  decorators, etc.).
- **Juju:** the charm `assumes` `juju >= 3.6`; integration tests run on
  `3.6/stable`.

## Architecture conventions

The charm follows the observer design pattern from specification UHPC010:

1. **`charm.py` is an entrypoint, not a handler dump.** All integration and
   charm-lifecycle event handlers live in observer classes under
   `src/integrations/` and `src/operations/`. `SSSDCharm.__init__` instantiates
   the `SSSDManager` workload manager and three observers (`LifecycleObserver`,
   `LdapObserver`, `CertificateTransferObserver`) — nothing else. No
   `framework.observe` calls live in `charm.py`; the observers register their
   own handlers.
2. **Workload logic is standalone.** `SSSDManager` (in `sssd.py`) inherits
   from `AptLifecycleManager` and owns the `sssd` apt lifecycle
   (install/remove/version), the `sssd` systemd service (via a
   `SystemctlServiceManager` `cached_property`), machine-level TLS certificate
   management (`add_tls_certs`/`remove_tls_certs`), and a `SSSDConfigManager`
   `cached_property` for `sssd.conf` file operations. It must be usable outside
   the context of a charm.
3. **Application config.** The charm currently defines no application config
   options in `charmcraft.yaml`. When config options are added, validate them
   with a frozen `pydantic.dataclasses.dataclass` in `config.py` and a
   `ConfigObserver` (UHPC 016) wired as `self.typed_config` in
   `SSSDCharm.__init__`; validation failures should raise `StopCharm` and set a
   `BlockedStatus` when a handler loads config. Defaults live in
   `charmcraft.yaml`, not in the dataclass.
4. **Integrations are observers.** Each relation (`ldap`, `receive-ca-cert`)
   has an observer under `src/integrations/` that wraps the corresponding
   interface implementation from `charmlibs.interfaces.*` (`LdapRequirer`,
   `CertificateTransferRequires`) and handles its custom events directly.
5. **Use `charmed-hpc-libs` primitives.** Prefer `AptLifecycleManager`,
   `SystemctlServiceManager`, `Observer`, `leader`, `StopCharm`, and the
   `refresh` decorator over hand-rolled equivalents. Integration interface
   implementations come from `charmlibs.interfaces.*` packages, not vendored
   charm libraries.

## Code style

Follow PEP 8 and PEP 257, plus:

### Imports

Three groups, alphabetized (`ruff format` handles ordering): standard
library, third-party (`ops`, `charmed_hpc_libs`, `charmlibs`, `pydantic`),
first-party (charm modules such as `sssd`, `state`, `constants`,
`integrations`, `operations`).

### Module naming

Flat module names — `charm.py`, `sssd.py`, `state.py`, `constants.py`.
Observer packages use `integrations/` and `operations/` with `__init__.py`
re-exporting the public observer classes. Do **not** use the `_`-prefix
convention; the public API of each module is its top-level surface.

### Docstrings

Every public module, class, and function must have a PEP 257 docstring.
Document `Args`, `Returns`, and `Raises` sections for non-trivial functions
in the house style of `sssd-operator`'s `sssd.py` module.

### Type annotations

All function signatures must have explicit type annotations. `just typecheck`
(pyright) validates them.

If a typing issue is found in production code (`src/`), STOP and
propose a resolution to the human-in-the-loop before editing production code:

1. Describe the issue, its location, and the impact.
2. Propose a concrete fix.
3. Ask whether to proceed with the proposed fix or to research alternative
   resolutions.

Do not edit production code until the user explicitly approves the fix.

### Avoid inline error handling

Use explicit `raise` statements and intermediate variables for error
handling rather than burying logic in one-liners or ternary expressions.
Define a charm-specific exception class (for example,
`SSSDOpsError`, `InvalidConfigError`) and raise it with a descriptive
message — do not allow `subprocess.CalledProcessError`to leak out of `sssd.py`.

### Comments

Do __not__ add generic one-off comments throughout the main codebase. Do add
comments in test files to provide justifications for assertions, mocks, and
workarounds.

### License headers

Every new source file must carry the Apache 2.0 license header at the top.
Set the copyright owner to the organization you are contributing on behalf
of and the year to the current year. When editing an existing file whose
copyright year is stale, extend the range (for example, `2023` →
`2023-2026`). See `CONTRIBUTING.md` for the exact header text.

## Build commands

```bash
just setup               # Create the uv dev environment (uv sync --all-groups).
just build               # Pack the charm with charmcraft -v pack.
just clean               # Remove coverage data, caches, build artifacts, *.charm.
just lock                # Regenerate uv.lock.
just upgrade             # Upgrade uv.lock with the latest dependencies.
just generate-charmhub-token  # Export a Charmhub release token to .charmhub.secret.
```

## Testing

```bash
just check           # Run static checks (lint, typecheck).
just unit            # Run unit tests with a coverage report.
just integration     # Validate + generate Gherkin features, then run integration tests.
just test            # Run all test suites (unit + integration).
just test <target>   # Run a specific test target.
just fmt             # Format with ruff and apply auto-fixes.
just lint            # codespell + ruff check + ruff format --check --diff.
just typecheck       # Static type checking with pyright.
```

### Unit tests

Use `ops.testing.Context` (the `Harness` is deprecated) to drive the charm
and its observers. Observer unit tests live in `tests/unit/observers/`. Mock
the workload (`SSSDManager`/`SSSDConfigManager`) via the `mock_sssd` fixture
in `tests/unit/conftest.py`, which patches `AptOpsManager` methods and
replaces the `service`/`config` `cached_property`s with `Mock` objects —
never call real `subprocess`, `systemctl`, or `apt` code from unit tests. Each
observer and each `SSSDManager`/`SSSDConfigManager` method must have
dedicated unit tests.

### Integration tests

Integration tests are Behavior-Driven. Author YAML test plans under
`tests/integration/plans/`; `gherkinator validate` and `gherkinator generate`
produce the Gherkin `.feature` files consumed by `pytest-jubilant-bdd`. The
`just integration` recipe runs both steps automatically. Integration tests
require Juju 3.6+ and LXD.

### Coverage

The target is **85% branch coverage** on `src/**/*.py`.
Do __not__ write unit tests for code paths that are impossible to reach in production.

## Terraform

The `terraform/` directory contains a CC008-compliant Terraform module that
allows the `sssd` charm to be deployed via Terraform in addition to the
Juju CLI. When creating, reviewing, or restructuring this module, follow
the
[create-charm-terraform-module SKILL.md](https://github.com/canonical/hpc-team/blob/main/.agents/skills/create-charm-terraform-module/SKILL.md)
— it codifies the required file structure (`README.md`, `providers.tf`,
`terraform.tf`, `main.tf`, `variables.tf`, `outputs.tf`, `locals.tf`),
mandatory/optional inputs and outputs, the README structure, versioning
conventions (`tf-X.Y.Z` for a co-located module), and validation
(`terraform fmt` + `terraform validate`).

Because `sssd` is a subordinate charm, the `units` and `constraints`
variables **must not** be defined. The `requires` output (`juju-info`,
`ldap`, `receive-ca-cert`) **must** be present in `outputs.tf`. There is no
`provides` output because the charm defines no `provides` endpoints.

## Development workflow

1. Implement charm logic in `src/` following the architecture conventions
   above — new event handlers go in observers, new workload operations go in
   `sssd.py`.
2. Write matching unit tests in `tests/unit/`.
3. Run `just unit` — ensure all tests pass and coverage meets the 85%
   branch coverage threshold.
4. Format: `just fmt`.
5. Lint: `just lint` (codespell + ruff). Fix all linter errors.
6. Typecheck: `just typecheck` (pyright). Fix all typing errors. If a
   typing issue is in production code, follow the human-in-the-loop protocol
   in the Code style section above.
7. If adding or changing BDD scenarios, edit the YAML plans under
   `tests/integration/plans/` and run `just integration` locally (requires
   Juju + LXD). You may be editing on a machine that does not have Juju or LXD available.
   1. Ask for explicit approval to run `just integration` if previous instructions
      do not explicitly state whether to run the integration tests or not.
   2. If in plan mode, explicitly ask the human-in-the-loop if they want to
      skip running the integration tests with `just integration`.
8. Repeat for each new or modified file.

Pipe the output of shell commands to either `head` or `tail` to capture
`stdout` and/or `stderr`.

Ask questions to the human-in-the-loop if you require additional context
or further information before beginning work on non-trivial tasks.

## Commit conventions

Use Conventional Commits prefixes for commit messages:

- `feat:` — New user-facing feature.
- `fix:` — Bug fix.
- `test:` — Add or modify tests only.
- `chore:` — Maintenance tasks (formatting, dependency updates, etc.).
- `docs:` — Documentation only.
- `refactor:` — Code change that neither fixes a bug nor adds a feature.
- `ci:` — CI/CD pipeline changes.

Scopes are allowed (for example, `chore(deps):`, `chore(fmt):`,
`feat(ldap):`).

### Commit trailers

- Commits must be signed off (`Signed-off-by:` trailer) **by the human**.
  Agents must never add a `Signed-off-by:` trailer on the human's behalf.
- Agents must include an `Assisted-by:` trailer identifying the agent and
  model.
- Order trailers as: `Assisted-by:` first, then the human's
  `Signed-off-by:` last (added by the human).

Format:

    Assisted-by: AGENT_NAME:MODEL_VERSION[:MODEL_VARIANT]

- `AGENT_NAME`: The AI tool (for example, `opencode`).
- `MODEL_VERSION`: The specific model version used.
- `MODEL_VARIANT`: The variant of the model version used (for example,
  `low`, `medium`, or `high`). Optional.

Other rules:

- Commit messages must be ASCII only.
- Keep PRs small and focused.
- Maintain a linear git history.
- All pre-commit checks must pass.
- Do not create new commits or open pull requests unless you are explicitly 
  granted approval by the human-in-the-loop.

### Constraints

- Do __not__ add new dependencies beyond what is already in
  `pyproject.toml` without approval.
- Do __not__ pin `ops` below the latest stable series, and do __not__
  introduce `pydantic` v1.
- Do __not__ install anything with `apt` or `snap` on the development
  machine. The charm may install `sssd` through `AptLifecycleManager` at
  runtime on the Juju unit — that is unrelated.
- Do __not__ run commands that require `sudo`.
- Do __not__ edit production code (`src/`) without explicit user
  approval when the change originates from a typing issue — propose the fix
  first and wait for approval (see the human-in-the-loop protocol above).
- All errors must be handled explicitly in Python code — no bare
  `subprocess.run(..., check=True)` outside a `try/except` that raises a
  charm-specific error class.

## Further information

- [Specification UHPC016 — Charm configuration observer](https://github.com/canonical/hpc-specs/blob/main/specs/UHPC%20016%20-%20Charm%20configuration%20observer/uhpc016.md)
- [Specification UHPC010 — Observer design pattern in HPC charms](https://github.com/canonical/hpc-specs/blob/main/specs/UHPC%20010%20-%20Observer%20design%20pattern%20in%20HPC%20charms/uhpc010.md)
- [Specification CC008 — Charm Terraform Standards](https://github.com/canonical/hpc-team/blob/main/.agents/skills/create-charm-terraform-module/SKILL.md)
- [`charmed-hpc-libs`](https://github.com/canonical/charmed-hpc-libs) — shared charm primitives (`AptLifecycleManager`, `SystemctlServiceManager`, `Observer`, `leader`, `StopCharm`, `refresh`).
- [`charmlibs`](https://github.com/canonical/charmlibs) — integration interface packages (`charmlibs.interfaces.ldap`, `charmlibs.interfaces.certificate_transfer`).

# System tests

Test plans for the SSSD system test suite, written in [FMF](https://fmf.readthedocs.io/)
and executed by [tmt](https://tmt.readthedocs.io/) on
[Testing Farm](https://docs.testing-farm.io/).

* `plans/` -- FMF plans, discovered and run by tmt.

The plans' `prepare` step fetches
[sssd-ci-containers](https://github.com/pbrezina/sssd-ci-containers)`/tmt/setup.sh`,
which brings up the test containers and installs reusable `ci-*` helper commands
(`ci-exec`, `ci-install-copr`, `ci-select-tests`) used throughout the plans.

## Environment variables

All environment variables the plan uses are declared, with their defaults,
in the `environment` key at the top of
[plans/system-tests.fmf](plans/system-tests.fmf) (visible via `tmt plan
show`). Override them with `-e KEY=VALUE` (`testing-farm request`), `--env
KEY=VALUE` (`/packit test`), or `tmt run -e KEY=VALUE` locally.

* `SSSD_CI_CONTAINERS` -- repository and branch of
  [sssd-ci-containers](https://github.com/SSSD/sssd-ci-containers) to use,
  as `owner/repo@branch`. Default: `SSSD/sssd-ci-containers@master`.
* `SSSD_TEST_FRAMEWORK` -- repository and branch of
  [sssd-test-framework](https://github.com/SSSD/sssd-test-framework), as
  `owner/repo@branch`. Default: `SSSD/sssd-test-framework@master`.
* `PYTEST_MH` -- repository and branch of
  [pytest-mh](https://github.com/next-actions/pytest-mh), as `owner/repo@branch`.
  Default: `next-actions/pytest-mh@master`.
* `TAG` -- sssd-ci-containers image tag to pull, consumed by
  `sssd-ci-containers/tmt/setup.sh`. Default empty (= autodetect).
* `PACKIT_COPR_PROJECT` -- COPR project to install SSSD from, set by Packit for
  PR/branch builds.
* `PACKIT_COPR_RPMS` -- package name pattern to install from the COPR
  project, set by Packit for PR/branch builds.
* `SELECT_TESTS` -- `pytest -k` expression limiting which tests run. Default
  empty (= autodetect).
* `PYTEST_ARGS` -- additional command-line arguments passed to `pytest`. Default
  empty.
* `PYLIBSSH_DEBUG` -- whether to enable pytest-mh's libssh debug logging.
  Default `0` (disabled); set to `1` to enable.

## How it runs via Packit

See [.packit.yaml](../.packit.yaml), job `tests`. On every pull request, once
the `copr_build` job finishes, Packit submits the plans in this directory to
Testing Farm for each configured target.

### Rebuilding / rechecking from a pull request

If a run fails because of infrastructure flakiness, or you just pushed a fix,
retrigger jobs with a PR comment instead of pushing an empty commit:

```
/packit build   # rebuild the COPR package for every target
/packit test    # rerun the `tests` job (waits for a successful build first)
```

Useful variants:

* `/packit build --identifier <id>` / `/packit test --identifier <id>` -- only
  run the job with the given identifier.
* `/packit test --env KEY=VALUE` -- pass extra environment variables to
  Testing Farm (repeat the flag for multiple variables).
* `/packit help` -- list all available commands and options.

You can also re-run an individual check from the GitHub PR "Checks" tab
(*Details* -> *Re-run*). See the
[Packit retriggering docs](https://packit.dev/docs/retriggering) for the full
command reference.

## Testing against in-development dependencies

To validate a PR against unreleased changes in `sssd-ci-containers`,
`sssd-test-framework`, or `pytest-mh` (e.g. a container or framework fix that
hasn't landed yet), you can temporarily point the automatic Packit-triggered
test runs at your own fork/branch by adding an `env:` override to the `tests`
job in [.packit.yaml](../.packit.yaml):

```yaml
- job: tests
  trigger: pull_request
  ...
  env:
    SSSD_CI_CONTAINERS: myfork/sssd-ci-containers@mybranch
    SSSD_TEST_FRAMEWORK: myfork/sssd-test-framework@mybranch
    PYTEST_MH: myfork/pytest-mh@mybranch
```

Packit reads `.packit.yaml` from the pull request's own branch, so this
override applies to every push to that PR automatically -- no need to repeat
`--env` on every `/packit test` comment.

**Be careful not to merge this change.** It's meant as a throwaway override
to validate the PR against in-development dependencies. Remove it again
before the branch is merged -- otherwise every future PR and commit build
will silently keep testing against your fork/branch instead of the default
in [plans/system-tests.fmf](plans/system-tests.fmf).

## Running locally

Install the CLI (see the
[CLI docs](https://docs.testing-farm.io/Testing%20Farm/0.1/cli.html) for
alternatives) and set up your
[API token](https://docs.testing-farm.io/Testing%20Farm/0.1/onboarding.html):

```
dnf copr enable @testing-farm/stable
dnf install testing-farm
export TESTING_FARM_API_TOKEN=<your-token>
```

### Request a run

Run from a checkout of the branch you want tested. The branch must be pushed to
a remote reachable by Testing Farm (e.g. your fork) -- it clones `url`/`ref` on
its own infrastructure, it does not see your local working tree. Uncommitted or
unpushed changes are not tested.

```
git checkout <branch>
testing-farm request --compose Fedora-latest --git-url https://github.com/SSSD/sssd.git --git-ref master
```

To request a run using specific COPR repository, sssd-ci-container image, or
a fork/branch of sssd-ci-containers, sssd-test-framework or pytest-mh, use
`-e KEY=VALUE` to set environment variables for the command (see
[Environment variables](#environment-variables) above for the full list).

```
testing-farm request --compose Fedora-latest \
  --git-url https://github.com/SSSD/sssd.git \
  --git-ref master                           \
  -e PACKIT_COPR_PROJECT=@sssd/nightly       \ # Set COPR repository
  -e PACKIT_COPR_RPMS='sssd*'                \ # Set packages to install on client and ipa container
  -e TAG=centos-10                           \ # Set sssd-ci-containers TAG
  -e SSSD_TEST_FRAMEWORK=myfork/sssd-test-framework@mybranch # Use a fork/branch of sssd-ci-containers
```

It is possible to use `--reserve` parameter to get access to the machine when
the tests are finished for post-mortem debugging.

### Watch / list requests

```
testing-farm watch --id <request-id>
testing-farm list
testing-farm list --state running
```

### Reserve a machine

Get an interactive box matching the test environment, e.g. to debug a
failure manually:

```
testing-farm reserve --compose Fedora-latest
```

`testing-farm --help` and `testing-farm <command> --help` cover the rest.

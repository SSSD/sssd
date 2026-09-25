# System tests

Test plans for the SSSD system test suite, written in [FMF](https://fmf.readthedocs.io/)
and executed by [tmt](https://tmt.readthedocs.io/) on
[Testing Farm](https://docs.testing-farm.io/).

* `plans/` -- FMF plans, discovered and run by tmt.

The plans' `prepare` step fetches
[sssd-ci-containers](https://github.com/pbrezina/sssd-ci-containers)`/tmt/setup.sh`,
which brings up the test containers and installs reusable `ci-*` helper commands
(`ci-exec`, `ci-install-copr`, `ci-select-tests`) used throughout the plans.

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

To request a run using specific COPR repository on specific sssd-ci-container
image use `-e KEY=VALUE` to set environment variables for the command.

```
testing-farm request --compose Fedora-latest \
  --git-url https://github.com/SSSD/sssd.git \
  --git-ref master                           \
  -e PACKIT_COPR_PROJECT=@sssd/nightly       \ # Set COPR repository
  -e PACKIT_COPR_RPMS='sssd*'                \ # Setp packages to install on client and ipa container
  -e TAG=centos-10                           \ # Set sssd-ci-containers TAG
```

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

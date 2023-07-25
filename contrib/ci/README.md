Continuous integration
======================

The executables and modules in this directory implement continuous integration
(CI) tests, which can be run to verify SSSD code quality and validity.

Supported host distros are Fedora 20 and later, RHEL 6.5 and later, and Debian
Testing.

The tests are executed by running `contrib/ci/run` from the source tree root.
It accepts options to choose from two test sets: "essential", "moderate"
(-e/-m), with the essential set selected by default.

Essential tests include building everything and running the built-in test
suite under Valgrind, completing in under 5 minutes.

Moderate tests include essential tests, plus a distcheck target build. They
complete in about 15 minutes.

Use `contrib/ci/clean` to remove test results from the source tree.


Setup
-----

CI requires `lsb_release` command to be available in order to determine host
distro version. On Red Hat distros it is contained in the `redhat-lsb-core`
package and on Debian in `lsb-release`.

The rest of the required packages CI will attempt to install itself, using
the distribution's package manager invoked through sudo.

A sudo rule can be employed to selectively avoid password prompts on RHEL
distros:

    <USER> ALL=(ALL:ALL) NOPASSWD: /usr/bin/yum --assumeyes install -- *

on Fedora distros:

    # With dnf >= 2.0
    <USER> ALL=(ALL:ALL) NOPASSWD: /usr/bin/dnf --assumeyes --best --setopt=install_weak_deps=False install -- *
    # We need to use yum-deprecated on Fedora because of BZ1215208.
    <USER> ALL=(ALL:ALL) NOPASSWD: /usr/bin/yum-deprecated --assumeyes install -- *

and Debian-based distros:

    <USER> ALL=(ALL:ALL) NOPASSWD: /usr/bin/apt-get --yes install -- *

Where `<USER>` is the user invoking CI.

You may also want to allow passing DEBIAN_FRONTEND environment variable to
apt-get on Debian, so CI can request non-interactive package installation:

    Defaults!/usr/bin/apt-get env_keep += "DEBIAN_FRONTEND"

Package installation can be disabled with the -n/--no-deps option, e.g.  for
manual dependency management, or for shaving off a few seconds of execution
time, when dependency changes are not expected.

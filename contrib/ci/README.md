Continuous integration
======================

The executables and modules in this directory implement continuous integration
(CI) tests, which can be run to verify SSSD code quality and validity.

Supported host distros are Fedora 20 and later, RHEL 6.5 and later, and Debian
Testing.

The tests are executed by running `contrib/ci/run` from the source tree root.
It accepts options to choose from three test sets: "essential", "moderate" and
"rigorous" (-e/-m/-r), with the essential set selected by default.

Essential tests include building everything and running the built-in test
suite under Valgrind, completing in under 5 minutes.

Moderate tests include essential tests, plus a distcheck target build and mock
package builds for Fedora and RHEL on Red Hat distros. They complete in about
15 minutes.

Rigorous tests include moderate tests, plus a pass with Clang static analyzer
over the whole build and test execution with code coverage collection and
verification, completing in 30 minutes. Static analyzer failures are ignored
for now.

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

On Red Hat distros a repository carrying dependencies missing from some
distros needs to be added to yum configuration. See instructions on the
[Copr project page](http://copr-fe.cloud.fedoraproject.org/coprs/lslebodn/sssd-deps/).
That repository is also automatically used by CI during mock builds.

Package installation can be disabled with the -n/--no-deps option, e.g.  for
manual dependency management, or for shaving off a few seconds of execution
time, when dependency changes are not expected.

On Red Hat distros, where mock builds are ran, it is better to have the
invoking user added to the `mock` group. Otherwise mock builds will be
executed through sudo.

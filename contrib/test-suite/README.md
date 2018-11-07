# Run SSSD Test Suite

Script `run.sh` will run all available SSSD test on a set of virtual machines created by vagrant. These virtual machines are part of separate project located at `https://github.com/SSSD/sssd-test-suite`.

## Automated Testing

These test are run automatically when you submit a Pull Request to SSSD project. Status report together with logs will be available in the Pull Request when testing is finished.

## Steps to run the tests manually

1. Checkout `https://github.com/SSSD/sssd-test-suite`
2. Configure and setup SSSD test suite per instructions located at project readme.
3. Make sssd-test-suite use already provisioned boxes (either manually created or maintained by SSSD team at https://app.vagrantup.com/sssd-vagrant).
4. Run `run.sh`, please note that this script will call `vagrant destroy` and it will thus destroy your existing guests.

```
run.sh SSSD-SOURCE-DIR TEST-SUITE-DIR ARTIFACTS-DIR CONFIG-FILE
  SSSD-SOURCE-DIR Path to SSSD source directory.
  TEST-SUITE-DIR  Path to sssd-test-suite_dir directory.
  ARTIFACTS-DIR   Path to directory where artifacts should be stored.
  CONFIG-FILE     Path to sssd-test-suite_dir configuration file to use.
```

At this moment only `client` guest is required. We need to expand our test cases to test agains FreeIPA and Active Directory.

## SSSD CI Architecture

Jenkins master polls github for new branches and pull requests. When it discovers new pull request or branch or changes to existing pull request or branch it will allocate a jenkins agent and executes pipeline defined in `./Jenkinsfile` (in SSSD source) on this agent.

The pipeline executes `./contrib/test-suite/run.sh` and archives logs when testing is finished. Script `./contrib/test-suite/run.sh` prepares sssd-test-suite, starts the vagrant machines and copy SSSD source code to the client machine. Then it calls `./contrib/test-suite/run-client.sh` on the client machine which runs continuous integration tests.

### Extending current tests
To extend current testing capabilities, modify `./contrib/test-suite/run.sh` and `./contrib/test-suite/run-client.sh` to new requirements. These files can be modified by anyone but are considered untrusted from contributor that is not an administrator of SSSD repository. This means that if a public contributor submits a pull request that changes those files, Jenkins will refuse to run tests.

### Adding additional distribution to test on
You need to modify `./Jenkinsfile`. Simply copy, paste and amend existing Fedora 28 stage. This file is also considered untrusted so only administrators can modify it within a pull request.

You also need to extend `sssd-test-suite` and prepare vagrant boxes for this distro.

# SSSD Test Suite

SSSD Test Suite is set of test that are being run automatically as part of Pull Request CI.

## Steps to run the tests manually on local machine

You need to clone and configure `sssd-test-suite` project to run these test manually on your local machine.

1. Checkout `https://github.com/SSSD/sssd-test-suite`
2. Configure and setup SSSD test suite per instructions located at project readme.
3. Make sssd-test-suite use already provisioned boxes (either manually created or maintained by SSSD team at https://app.vagrantup.com/sssd-vagrant).
4. Run the tests with `sssd-test-suite` command line interface

```bash
$ git clone https://github.com/SSSD/sssd-test-suite
$ cd sssd-test-suite
$ cp ./configs/sssd-f30.json ./config.json
$ ./sssd-test-suite run --sssd $path-to-sssd --artifacts /tmp/sssd-artifacts
```

See [sssd-test-suite documentation](https://github.com/SSSD/sssd-test-suite/blob/master/readme.md) for more information.
See [running the tests documentation](https://github.com/SSSD/sssd-test-suite/blob/master/docs/running-tests.md) for more information about the process.

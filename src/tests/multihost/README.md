# Instructions on executing tests

Multihost tests uses the `python-multihost` framework to execute test commands
on remote machines. The tests themselves are run locally via pytest.

## Install requirements

```
sudo pip3 install -r src/tests/multihost/requirements.txt
```

You can also install them in virtual environment using the virtualenv command
if you wish.

## Prepare remote machines

Existing tests currently requires only one remote machine where the SSSD version
that you want to test is installed. The machine must be Fedora or RHEL so it can
be correctly provisioned. The **tests will modify the machine** so use something
disposable.

It is recommended to use [sssd-test-suite] project to create such machine. The
multihost tests can run out of the box using [sssd-test-suite] without any
further changes.

[sssd-test-suite]: https://github.com/SSSD/sssd-test-suite

## Prepare multihost configuration

Edit `src/tests/multihost/basic/mhc.yaml`:

```yaml
root_password: 'vagrant' # use remote machine root password
domains:
- name: tier0.tests
  type: sssd
  hosts:
  - name: client
    external_hostname: master.client.vm # your machine fully qualified name
    role: master
```

Note: You can skip this step if you use machines from sssd-test-suite.

## Run the tests

```
pytest-3 -s --multihost-config=src/tests/multihost/basic/mhc.yaml src/tests/multihost/basic
```

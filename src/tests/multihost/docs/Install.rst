Install
=======
* sssd.testlib is a python library which contains shared functions to be used with
  py.test to automate System Services Security Daemon (SSSD).

Dependencies
------------
sssd.testlib requires the following packages:

1. python-paramiko
2. python-pytest-multihost
3. PyYAML
4. pytest

RHEL7
-----
To install above dependencies on RHEL7.4 get the:

* python-paramiko package (available at Extras repo)

* `pytest-multihost copr repo(epel7) <https://copr.fedorainfracloud.org/coprs/mrniranjan/python-pytest-multihost/repo/epel-7/mrniranjan-python-pytest-multihost-epel-7.repo>`_ file::

    $ wget -O /etc/yum.repos.d/pytest-multihost.repo \
    https://copr.fedorainfracloud.org/coprs/mrniranjan/python-pytest-multihost/repo/epel-7/mrniranjan-python-pytest-multihost-epel-7.repo
    $ yum install python-pytest-multihost

* `sssd-testlib copr repo(epel7) <https://copr.fedorainfracloud.org/coprs/mrniranjan/sssd-testlib/repo/epel-7/mrniranjan-sssd-testlib-epel-7.repo>`_ file::

    $ wget -O /etc/yum.repos.d/sssd-testlib.repo \
    https://copr.fedorainfracloud.org/coprs/mrniranjan/sssd-testlib/repo/epel-7/mrniranjan-sssd-testlib-epel-7.repo
    $ yum install sssd-testlib

Fedora
------
To install the above dependencies on Fedora get the:

* `pytest-multihost copr repo(F26) <https://copr.fedorainfracloud.org/coprs/mrniranjan/python-pytest-multihost/repo/fedora-26/mrniranjan-python-pytest-multihost-fedora-26.repo>`_ file::

    $ wget -O /etc/yum.repos.d/pytest-multihost.repo \
    https://copr.fedorainfracloud.org/coprs/mrniranjan/python-pytest-multihost/repo/fedora-24/mrniranjan-python-pytest-multihost-fedora-24.repo
    $ dnf install python-pytest-multihost

* `sssd-testlib copr repo(f26) <https://copr.fedorainfracloud.org/coprs/mrniranjan/sssd-testlib/repo/fedora-26/mrniranjan-sssd-testlib-fedora-26.repo>`_ file::

    $ wget -O /etc/yum.repos.d/sssd-testlib.repo \
    https://copr.fedorainfracloud.org/coprs/mrniranjan/sssd-testlib/repo/fedora-24/mrniranjan-sssd-testlib-fedora-24.repo
    $ dnf install sssd-testlib

.. _setup-virtualenv:

Setup Python Virtual Environment
================================

Fedora 35
*********

* On Fedora 35, install below packages using **dnf**::

    [user@host ~]$ sudo dnf install python3-pip python3-virtualenv openldap-devel
    python3-pyyaml python3-ldap python3-pytest-multihost gcc git

* Clone the upstream sssd using **git** tool::

    [user@host ~]$ git clone https://github.com/SSSD/sssd.git

* Default branch when sssd is cloned is the master branch::

    [user@host ~]$ cd sssd
    [user@host sssd]$ git branch
    * master

* Create a Isolated Python Environment::

    [user@host sssd]$ virtualenv ~/sssd-env

* Activate the Virtual environment::

    [user@host sssd]$ source ~/sssd-env/bin/activate
    (sssd-env) [user@host sssd]$

* Install a few more dependencies using **pip**::

    (sssd-env) [user@host sssd]$ sudo pip install -r src/tests/multihost/requirements.txt


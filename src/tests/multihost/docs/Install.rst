.. _setup-virtualenv:

Setup Python Virtual Environment
================================

Fedora 35
*********

* On Fedora 35, Install below packages using **dnf**::

    $ sudo dnf install python3-pip python3-virtualenv gcc git openldap-devel
     python3-pyyaml python3-ldap python3-paramiko python3-pytest-multihost

* Clone the upstream sssd using **git** tool::

    $ git clone https://github.com/SSSD/sssd.git

* Default branch when sssd is cloned is the master branch::

   $ [testuser@dhcp201-228 sssd]$ git branch
   * master

* Create a Isolated Python Environment::

    $ [testuser@dhcp201-228 ~]$ virtualenv ~/sssd-env

* Activate the Virtual environment::

    $ [testuser@dhcp201-228 ~]$ source ~/sssd-env/bin/activate
    $ (sssd-env) [testuser@dhcp201-228 ~]$


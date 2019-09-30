# Instructions on executing tests

This Directory contains test written with pytest framework using pytest-multihost plugin.


## Requirements

1. Controller Node/Jumphost from where pytest is invoked. pytest and pytest-multihost plugin needs
to be installed.

2. Another Fedora/RHEL8 system(SUT/System under test) on which the actual commands specified in tests are run.

## Steps:

1. Setup required on Controller Node/Jumphost

* On Fedora 30 , Install below packages using dnf:

   ```$ dnf install python3-pip nss-tools python3-virtualenv gcc git openldap-devel```

* Clone sssd using **git**::

    ```$ git clone https://github.com/SSSD/sssd/```

* Create a Isolated Virtual Python Environment::

    ```$ virtualenv /tmp/abc```

* Activate the Virtual environment::

     ```
     $ source /tmp/abc/bin/activate
     $ (abc) [root@master-7740 bin]#
     ```

* Install the sssd-testlib on your virtualenv::

   ```
   $ cd sssd/src/tests/python
   $ python setup.py install
   ```
* Install **pytest, pytest-multihost, python-ldap, paramiko, PyYAML**::

  ```$ pip install pytest pytest-multihost paramiko python-ldap PyYAML```

2. Setup required on Fedora/RHEL8 system (SUT).

*  Setup a FQDN Hostname for example **idm1.example.test**::

   ```
   $ hostnamectl set-hostname idm1.example.test
   ```

*  Add the ipv4 ipaddress and the hostname to have local resolution in /etc/hosts

   ```
   $ cat /etc/hosts
   127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
   ::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
   192.168.122.7 idm1.example.test
   ```

3. On the Controller Node/Jump Host verify **idm1.example.test** is resolvable by
adding the SUT ipaddress and hostname in **/etc/hosts**

   ```
   $ ping -c 5 idm1.example.test
   PING idm1.example.test (192.168.122.7) 56(84) bytes of data.
   64 bytes from idm1.example.test (192.168.122.7): icmp_seq=1 ttl=64 time=0.258 ms
   64 bytes from idm1.example.test (192.168.122.7): icmp_seq=2 ttl=64 time=0.295 ms
   64 bytes from idm1.example.test (192.168.122.7): icmp_seq=3 ttl=64 time=0.230 ms
   64 bytes from idm1.example.test (192.168.122.7): icmp_seq=4 ttl=64 time=0.081 ms
   64 bytes from idm1.example.test (192.168.122.7): icmp_seq=5 ttl=64 time=0.120 ms
   ```


4.  Pytest Multihost plugin requires a configuration file in yaml format.
This configuration file contains the hosts and the roles the hosts are
playing required for a test suite.

* Below is the example multihost configuration for a single host. Since
all the tests in multihost/basic directory are single hosts tests that sets
up the ldap(389-ds), kerberos server and also configures client to authenticate against
the ldap and kerberos on the same system.

In the below example file **mhc.yaml**, multihost plugin connects to host *idm1.example.com*
using ssh and password **redhat*\::

```
    root_password: 'redhat'
    domains:
        - name: example.test
          type: sssd
          hosts:
            - name: idm1.example.test
              external_hostname: idm1.example.test
              ip: 192.168.122.7
	      role: master
```

5. Execute pytest::

   ```$ pytest  -s -v --multihost-config=mhc.yaml sssd/src/tests/multihost/basic/```

* To execute only specific test case::

   ```$ pytest -s -v --multihost-config=mhc.yaml sssd/src/tests/multihost/basic/test_kcm.py```

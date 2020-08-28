running
=======
* Running Tests

Prerequisites
-------------
* pytest-multihost-plugin

  To execute tests with multiple tests, pytest-multihost plugin is required.
  Refer to Install section for installing the plugin.

* SSSD pytest framework

  SSSD pytest framework is mostly set of shared functions that is used in test cases for common tasks like authconfig, setting up DS, Kerberos, IPA, etc.
  sssd-testlib is the module provided by the framework.

Getting Started
---------------
* Functional Tests mostly written for SSSD require multiple hosts. Each of the hosts take a particular role. Below are the predefined roles used:

  - master: Node on which we have Directory Server/OpenLDAP Server/krb5 Server/IPA Server is running
  - replica: Node on which is replica of Directory/OpenLDAP Server/krb5 server
  - client: Node on which sssd-client is configured
  - ad: Node on which Microsoft Active Directory is running
  - atomic: Atomic host Node

config
------
* To run multihosts tests using pytest, we have to define the infrastructure containing RHEL and Windows systems in a file. Check Example config file::

        root_password: 'redhat'
        test_dir: '/root/multihost'
        windows_test_dir: '/home/administrator'
        domains:
          - name: testrealm.test
            type: sssd
            hosts:
              - name: hostname1
                ip: 192.168.122.1
                role: master
              - name: hostname2
                ip: 192.168.122.2
                role: replica
              - name: hostname3:
                ip: 192.168.122.3
                role: client
              - name: hostname4:
                ip: 192.168.122.4
                role: ad
                username: Administrator
                password: Secret123

Brief description of the above lines:

    **root_password** is the root password of the systems, it's better to have common password of the RHEL systems that you would like to connect.
    Instead of password, you can use ssh keys, in which the parameter is **ssh_key_filename: ~/.ssh/id_rsa**

    **test_dir** directory to store test-specific data in, defaults to **/root/multihost_tests**

    **windows_test_dir** Directory to store test-specific data on Windows hosts, defaults to **/home/Administrator**

    **Domains** is a list of domains under which the hosts that will run the commands reside. Domains are a way of classifying hosts.

    **name(under Domains)** is the name of the domain, can be any name (resolvable/non-resolvable)

    **type(under Domains)** is the type of hosts, a string specifying the type of the domain ('default' by default)

    **hosts(under Domains)** is a placeholder for list of hosts

    **name(under hosts)**  is a hostname to which multihost needs to connect, can be a short name in which case the FQDN will be formed by combining name and domain
    name specified under domains.

    **ip** is the IP address of the system

    **role** is the role that the host will be taking, like master/slave/replica/ad/atomic

    **username** (optional) each host can have its specific username to connect to. For example for connecting to Windows systems we use username 'Administrator'

    **password**  password to connect to

Executing Tests
---------------
* To execute existing tests clone sssd-qe-tests repo and run py.test against any specific test suite directory.

  - On RHEL7.2::

     $ git clone git://git.app.eng.bos.redhat.com/sssd-qe-tests.git
     $ cd sssd-qe-tests/pytest
     $ py.test --multihost-config=<multihost-template> <test-suite-directory>

* Before executing any tests, it's required to create a config file as specified in `config` section.

  - Executing test suite::

                $ cd sssd-qe-tests/pytest/
                $ py.test --junit-xml=/tmp/junit.xml \
                        --multihost-config=mh_cfg.yaml \
                        -v <test_suite_dir>

  - Executing Individual Test sub-suite (module)::

                $ cd sssd-qe-tests/pytest/
                $ py.test --junit-xml=/tmp/junit.xml \
                        --multihost-config=mh_cfg.yaml \
                        -v <test_suite_dir/test_module.py>

  - Executing individual Test cases::

                $ cd sssd-qe-tests/pytest/
                $ py.test --junit.xml=/tmp/junit.xml \
                        --multihosts-config=mh_cfg.yaml \
                        -v <test_suite_dir>/<test_module>.py::<TestClass>::<test_case>

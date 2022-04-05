Running the Tests
=================

* Running Tests


Prerequisites
-------------

    * pytest-multihost-plugin: To execute tests with multiple tests,
      pytest-multihost plugin is required.
      Refer to Install section for installing the plugins.

    * sssd pytest framework: sssd pytest framework is mostly set of shared
      functions that is used in test cases for common tasks like
      authconfig/authselect, setting up DS, kerberos, ipa, etc.
      sssd-testlib is the module provided by the framework.


Getting Started
----------------
* Functional Tests mostly written for SSSD require multiple hosts. Each of the hosts take a particular role. Below are the predifined roles used:

        * master: Node on which we have Direcory Server/Openldap Server/krb5 Server/IPA Server is running
        * replica: Node on which is replica of Directory/Openldap Server/krb5 server
        * client: Node on which sssd-client is configured
        * ad: Node on which Microsoft Active Directory is running
        * atomic: Atomic host Node


config
------

 * To run multihosts tests using pytest, we have to define the infrastructure containing RHEL and Windows systems in a file. Check Example config file::

    root_password: 'redhat'
    ad_admin_name: Administrator
    ad_admin_password: Secret123
    ad_hostname: ad1-tbgr
    ad_ip: 10.0.189.34
    ad_top_domain: domain-tbgr.com
    admin_name: admin
    admin_password: Secret.123
    dirman_dn: cn=Directory Manager
    dirman_password: Secret.123
    dns_forwarder: 10.11.5.19
    domains:
    - hosts:
      name: domain.com
      type: sssd
      - external_hostname: hostname.master.com
        ip: 10.0.189.241
        name: hostname1
        role: master
      - external_hostname: hostname.client.com
        ip: 10.0.189.224
        name: hostname2
        role: client
    - hosts:
      name: domain-tbgr.com
      type: ad
      - external_hostname: hostname.ad.com
        host_type: windows
        ip: 10.0.189.34
        name: ad1-tbgr
        password: Secret123
        role: ad
        username: Administrator



    **Brief description of the above lines:**

    **root_password** is the root password of the systems, it's better to have
    common password of the RHEL systems that you would like to connect.
    Instead of password, One can use ssh keys, in which the parameter is
    **ssh_key_filename: ~/.ssh/id_rsa**.

    **ad_admin_name** (optional) is the AD admin default name. We can also
    add default name under host as a 'username'. Both ways it works.

    **ad_admin_password** (optional) is the default AD admin password. We
    can also add it under host as a 'password'. Both ways it works.

    **ad_hostname** (optional) is hostname of AD.

    **ad_ip** (optional) is IP of AD server.

    **ad_top_domain** (optional) is Top domain of AD if we use forest or
    parent/clild of AD server.

    **admin_name** (optional) is name of admin while configuring IPA server.

    **admin_password** (optional) is a admin's password of IPA server.

    **dirman_dn** (optional) Directory manager while configuring IPA server.

    **dirman_password** (optional) Directory Manager's password.

    **dns_forwarder** (optional) DNS forwarder while configuring IPA server.

    **domains** is a list of domains under which the hosts that will run the
    commands reside, Domains are way of classifying hosts.

    **hosts(under Domains)** is a placeholder for list of hosts.

    **name(Under Domains)** is the name of the domain, can be any name
    (resolvable/non-resolvable)

    **type(under Domains)** is the type of hosts, a string specifying the
    type of the domain like sssd, ad or IPA.

    **name(under hosts)**  is a hostname to which multihost needs to
    connect, can be a short name in which case FQDN will be formed by
    combining name and domain name specified under domains.

    **ip(under hosts)** is the ipaddress of the system

    **role(under hosts)** is the role that the host will be taking, like
    client/master/slave/replica/ad/atomic

    **external_hostname(under hosts)** hostname of the system to connect
    remote system using openssh.

    **username** (optional) each host can have it's specific username to
    connect to, Example for connecting Windows systems we use username
    'Administrator' **password**  password to connect to

Executing Tests
---------------
* To execute existing tests clone sssd-qe-tests repo and run py.test against
  any specific test suite directory::

    $ git clone https://github.com/SSSD/sssd.git
    $ cd sssd/src/tests/multihost/{ad/adsite/admultidomain/alltests/ipa}
    $ py.test --multihost-config=<multihost-template> <test-suite-directory>

* Before executing any tests, it's required to create a config file
  as specified in `config` section.

        * Only collect tests, do not execute::

                $ cd sssd/src/tests/multihost/ipa
                $ pytest -s -v --multihost-config=mhc.yaml -v test_hbac.py \
                --collect-only
                ====================== test session starts ===============
                collected 6 items
                <Module 'test_hbac.py'>
                  <Class 'Testipahbac'>
                    <Instance '()'>
                      <Function 'test_sssctl_sshd'>
                      <Function 'test_hbac_changes'>
                      <Function 'test_hbac_refresh_time'>
                      <Function 'test_multiple_hbac_rules'>
                      <Function 'test_nested_groups'>
                      <Function 'test_auto_private_group'>
                ========== no tests ran in 0.01 seconds ==============

        * Executing test suite::

                $ cd sssd/src/tests/multihost/ipa
                $ pytest -s -v --multihost-config=mhc.yaml <test_suite_dir>

        * Executing Individual Test sub-suite (module)::

                $ cd sssd/src/tests/multihost
                $ pytest -s -v --multihost-config=mhc.yaml \
                <test_suite_dir/test_module.py>

        * Executing individual Test cases::

                $ cd sssd/src/tests/multihost/ipa
                $ pytest -s -v --multihosts-config=mhc.yaml \
                <test_suite_dir>/<test_module>.py::<TestClass>::<test_case>

        * Executing test with markers::

                $ cd sssd/src/tests/multihost/ipa
                $ pytest -s -v --multihosts-config=mhc.yaml -m \
                <mark_expression>


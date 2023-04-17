LDAP provider, KRB provider, sanity and  proxy provider
=======================================================

This directory contains test automation of LDAP provider,
KRB provider, proxy provider and sanity

Markers Definition
==================
Following are the pytest markers used

* tier1: Tier1 test cases
* tier2: Tier2 test cases
* tier3: Tier3 test cases
* automount: Test cases related to autofs responder
* configmerge: Tests related to Config merge
* configvalidation: Tests related to sssd config validation
* cache_performance: Tests related to cache performance testing
* misc: Tests related to misc bugs automation
* hostmap: Tests related to hostmap and network map
* journald: Tests related to journald
* krb5: Tests related to krb5
* kcm: Tests related to kcm
* krbaccessprovider: Tests related to kerberos access provider
* krbfastprincipal: Tests related to kerberos fast principal
* ldapextraattrs: Tests related to Ldap Extra attributes
* localoverrides: Tests related to Local Overrides
* multidomain: Tests related to SSSD Multiple Domains
* netgroup: Tests related to netgroup
* nsaccountlock: Tests related to nsaccountlock
* offline: Tests related to ldap offline suite
* services: Tests related to SSSD sanity services
* sssctl: Tests related to sssctl tool
* failover: Tests related to failover
* sudo: Tests related to sudo
* krbldapconnection: Tests related to kerberos ldap connection
* passwordcheck: Tests related to password check while updating password of user
* proxy: Tests related to sssd-proxy
* rfc2307: Tests related to rfc2307
* rfc2307bis: Tests related to rfc2307bis
* fips: Tests related to fips when auth_provider is krb5
* ssh: Tests related to ssh responder
* tier1: tier1 test cases
* tier2: tier2 test cases
* tier3: tier3 test cases



Test systems and roles
======================
* Roles:

  **master:** System under master role is used to configure
  ldap, kerberos and nfs server

  **client:** system under client role is configured sssd client

To run all the tests maximum of 3 systems are required of which 2 systems
should be on master role and 1 system should be on client role. Below is the
sample multihost configuration

.. code-block:: yaml

    root_password: 'redhat'
    domains:
       - name: example.test
         type: sssd
         hosts:
           - name: vm-10-0-154-49.hosted.upshift.rdu2.redhat.com
             external_hostname: vm-10-0-154-49.hosted.upshift.rdu2.redhat.com
             role: client
           - name: vm-10-0-154-50.hosted.upshift.rdu2.redhat.com
             external_hostname: vm-10-0-154-50.hosted.upshift.rdu2.redhat.com
             role: master
           - name: vm-10-0-154-51.hosted.upshift.rdu2.redhat.com
             external_hostname: vm-10-0-154-51.hosted.upshift.rdu2.redhat.com
             role: master

Purpose of pytest fixture
========================
The purpose of test fixtures is to provide a fixed baseline
upon which tests can reliably and repeatedly execute. pytest
fixtures offer dramatic improvements over the classic xUnit
style of setup/teardown functions.

Specifying Fixture Scope
========================
Fixtures include an optional parameter called scope,
which controls how often a fixture gets set up and torn down.
The scope parameter to @pytest.fixture() can have the values
of function,class, module, or session. The default scope is
function.


*scope='function'
======================
Run once per test function. The setup portion is run before
each test using the fixture. The teardown portion is run
after each test using the fixture. This is the default scope
used when no scope parameter is specified.

we have following function scope fixtures in conftest.py
========================
* multidomain_sssd
    Create sssd.conf for multidomain test suite. This fixture creates
    uses indirect parametrization where it takes parameters passed
    from test case to setup sssd.conf by enabling proxy, ldap and files
    domain depending upon the test case.
* localusers
    Create local users with username user5000, user5001
* backupsssdconf
    Take backup of sssd.conf and restore it.
* enable_sss_sudo_nsswitch
    enable sss backend to sudoers in /etc/nsswitch.conf
* set_dslimits
     Modify nsslapd-lookthroughlimit and nsslapd-pagedlookthroughlimit
     and set the value to 10.
* add_nisobject
     Add auto.direct map entry in ldap server. This fixture uses
     indirect parametrization where **request.param** value contains
     the name of the project folder which is used to create a directory
     in nfs-server and add map entry in ldap server.
* create_etc_exports
     Remove and recate /etc/exports file on NFS Server(master)
* indirect_nismaps
     Create indirect maps and adds 20 map keys from
     **/projects/foo1** to **/projects/foo20**
* set_autofs_search_base
     Enable autofs responder on sssd.conf and set
     **ldap_autofs_search_base** parameter in domains
     section of sssd.conf
* set_ldap_uri
     Replace ldaps uri in sssd.conf to ldap uri. This
     is used specifically to capture packets using
     **tcpdump**
* create_ssh_keys
     Generates ssh keys and adds the ssh keys to
     predefined user **uid=foo1,ou=People,dc=example,dc=test**
* enable_multiple_responders
     Enable multiple sssd responders in sssd section of sssd.conf
     Enable **'nss, pam, sudo, autofs, ssh, pac, ifp'** responders
     in sssd.conf


*scope='class'
==============
Run once per test class, regardless of how many test
methods are in that class. The teardown portion is run
after that class.

We have following class scope fixtures in conftest.py
====================================================
* setupds
    Setup directory server with secured connection.
* multipleds
    Setup two directory servers with secured connection.
* multipleds_failover
    Setups Multiple directory server on 2 servers(masters)
    for failover testcases
* posix_users_multidomain
    Add posix users for multidomain test suite.
* sssdproxyldap
    Create sssdproxyldap config file.
* nslcd
    Create nslcd.conf and start nslcd service.
* template_sssdconf
    Copy template sssd conf for multidomain tests.
* setup_kerberos
    Setup kerberos with **EXAMPLE.TEST** domain.
* setup_ds_sasl
    Enable sasl on Directory server. A keytab
    **/etc/dirsrv/krb5.keytab** is created and sets
    up /etc/sysconfig-dirsrv-<instancename> with
    path of keytab file.
* setup_sssd
    Configure sssd.conf with one domain section. This
    fixture sets up sssd.conf with auth_provider as ldap

    .. code-block:: python

        [sssd]
        config_file_version = 2
        services = nss, pam, example1

        [domains/example1]
        id_provider = ldap
        auth_provider = ldap
        ldap_user_home_directory = /home/%u
        ldap_uri = <ldap-server>
        ldap_tls_cacert = /etc/openldap/cacerts/cacert.pem
        use_fully_qualified_names = True
        debug_level = 9

* setup_sssd_krb
    Calls **setup_sssd** fixture and modifies sssd.conf
    to use auth_provider as krb5

    .. code-block:: python

        [sssd]
        config_file_version = 2
        services = nss, pam, example1

        [domains/example1]
        id_provider = ldap
        auth_provider = krb5
        ldap_user_home_directory = /home/%u
        ldap_uri = <ldap-server>
        ldap_tls_cacert = /etc/openldap/cacerts/cacert.pem
        use_fully_qualified_names = True
        debug_level = 9
        krb5_realm = EXAMPLE.TEST
        krb5_server = <kerberos-server-hostname>


* create_host_keytab
    Creates host keytab file on client system.
* setup_sssd_gssapi
    Calls **setup_sssd**, **setup_ds_sasl**, **create_host_keytab**
    fixtures and configures sssd.conf on client system with

    .. code-block:: python

       auth_provider = krb5
       ldap_sasl_mech = GSSAPI
       krb5_realm = EXAMPLE.TEST
       use_fully_qualified_names = False
       krb5_server = <kerber-server-hostname>

* multihots
    Multihost fixture to be used by tests.
* create_posix_usersgroups
    Create posix groups and users.
* create_posix_usersgroups_failover
    Creates posix groups and users on 2 Directory servers
* netgroups
    Create Netgroups organisational unit and add netgroup
    users.
* write_journalsssd
    Create /etc/sysconfig/sssd and start systemd-journald
    service for journald test suite.
* update_journald_conf
    Update /etc/systemd/journald.conf to turn off any kind
    of rate limiting for journald test suite.
* enable_autofs_schema
    Enable autofs schema(rfc2307) on Windows AD
* enable_autofs_service
    Enable autofs responder on sssd.conf
* default_sssd
    Setup default sssd.conf as shown below:

    .. code-block:: python

       [sssd]
       config_file_version = 2
       services = nss, pam

* krb_connection_timeout
    Creates host keytab for client.
    Note: This fixture will be replaced in future
* create_host_user
    Add host entry in ldap for SASL and GSSAPI Authentication
* enable_ssh_schema
    Enable OpenSSH lpk  schema in directory server
* setup_sshd_authorized_keys
    Configuring OpenSSH to Use SSSD for User Key. i.e
    edits /etc/ssh/sshd_config file and sets up

    .. code-block:: python

       AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
       AuthorizedKeysCommandUser nobody

* enable_ssh_responder
    Enable ssh responder in sssd.conf

*scope='session'
=======================
Run once per session

We have followinf session scope fixtures in conftest.py
========================
* default_sssd
    Create the sssd section with default parameters
* setup_session
    Setup session

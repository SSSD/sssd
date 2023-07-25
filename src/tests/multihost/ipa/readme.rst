IPA Provider
============

This directory contains test automation related to IPA Provider

Markers Definition
==================
Following are the pytest markers used

* tier1: Tier1 test cases
* hbac: Tests related to hbac test cases (Non-AD)
* trust: Tests related to AD Trust
* adhbac: Tests related HBAC in AD Trus Environment

Test systems and roles
======================
* Roles:

  **master:** System under master role is used to configure
  IPA Server. The IPA Server is configured using ansible.
  The following playbooks configure IPA-Server and AD-Trust.

  `Setup IPA Server
  <https://gitlab.cee.redhat.com/identity-management/idm-ci/blob/master/playbooks/prep/ipa-server-install.yaml>`_
  `Install AD-Trust packages
  <https://gitlab.cee.redhat.com/identity-management/idm-ci/blob/master/playbooks/prep/ipa-adtrust-install.yaml>`_
  `Setup AD-Trust
  <https://gitlab.cee.redhat.com/sssd/sssd-qe/-/blob/RHEL8.4/playbooks/ad-trust.yaml>`_

  **client:** system under client role is configured IPA Client

  **ad:** Windows Active Directory Domain Controller

To run all the tests maximum of 3 systems are required of which 1 systems
should be on master role and 1 system should be on client role and 1 AD.
Below is the sample multihost configuration

.. code-block:: yaml

    root_password: 'redhat'
    domains:
       - name: testrealm.test
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
       - name: t1adpy12r82g.com
         type: ad
         hosts:
           - name: adpy1282t1.t1adpy12r82g.com
             external_hostname: adpy1282t1.t1adpy12r82g.com
             ip: 10.0.104.184
             password: Secret123
             role: ad
             username: Administrator
             host_type: 'windows'


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
========================================================
* hbac_sshd_rule
    Setup hbac rule for service sshd which allows user foobar1 to ssh from
    client host.
* create_aduser_group
    Create AD User testuser<randomnumber> and also create a group
    testgroup<randomnumber> and makes the testuser<randomnumber> member of
    testgroup<randomnumber> . This fixture returns the username and groupname
    to be consumed in the test function

*scope='class'
==============
Run once per test class, regardless of how many test
methods are in that class. The teardown portion is run
after that class.

We have following class scope fixtures in conftest.py
====================================================
* default_ipa_users
    This fixture creates 10 users foobar0 to foobar9 in ipa server to be used
    in test cases. This fixture also has teardown function which deletes these
    users. All the users are created with initial password **RedHat@123**
* reset_password
    This fixture uses kinit to reset the password of users created from *default_ipa_users*
    from **RedHat@123** to **Secret123**
* disable_allow_all_hbac
    This fixture disables the default **allow_all** hbac rule. The teardown
    function enables the hbac rule.
* multihost
    This fixture converts the session scoped multihost plugin/module/ to class
    scoped to be used in test case functions
* create_ad_users
    Creates AD Users defined in users.csv. These users are created using
    powershell script *add-users.ps1* and teardown function calls
    *remove_users.ps1* which will delete these users from AD.
    The fixture first copies the *users.csv*, *add-users.ps1* ,
    *remove-users.ps1* to AD and executes the powershell scripts.

*scope='session'
=======================
Run once per session

We have following session scope fixtures in conftest.py
=======================================================
* setup_ipa_client
    Configures the client to be ipa client to the ipa server. The teardown
    function runs *ipa-client-install --uninstall -U*.

SSSD System Tests
=================

Tests are written in Python using our `SSSD <https://tests.sssd.io/en/latest/>`__ framework and `pytest <https://docs.pytest.org/en/stable/>`__ framework and most notably `pytest mh <https://github.com/next-actions/pytest-mh>`__  plug-in amongst others. For more information please visit our `SSSD framework wiki <https://tests.sssd.io/en/latest/>`__.

.. note::

    We are in the progress of overhauling our tests, with the emphasis on providing excellent test coverage, clear concise documentation, consistent and maintainable test code. This system test folder, does contain more types of test than the folder name suggests. Sanity and integration tests are included and will have a pytest marker indicating the difference.

Test Categories
***************
Tests can be written for a specific identity provider; IPA, LDAP, KRB, Samba or AD. When possible, they should be written using a generic provider which will execute the test against all providers. Tests are organized by user scenarios, depending on the case, they can be organized by providers or feature.

* test_authentication.py, contains password policies tests, and tests with different auth mechanisms password, GSSAPI or certificates.
* test_passkey.py, contains authentication tests, using virtual passkeys.
* test_smartcards.py, contains authentication tests, using virtual smart cards.
* test_identity.py, contains tests resolving users, groups, group memberships and the object attributes.
* test_lookup.py, similar to identity tests but the tests focus on the client configuration.
* test_netgroup.py, contains all tests related to netgroups.
* test_access_control_simple.py, contains simple access control tests.
* test_access_control_ldap_filter.py, contains parameterized LDAP and AD access control filter tests.
* test_gpo.py, contains access control tests managed by group policy objects (gpo) in AD.
* test_cache.py, contains LDB cache tests.
* test_memcache.py, contains in-memory cache tests.
* test_proxy.py, proxy provider tests.
* test_failover.py, any provider resolution and connectivity tests.
* test_ldap.py, any test that is specific to LDAP.
* test_ad.py, any test that is specific to AD.
* test_ipa.py, any test that is specific to IPA.
* test_ipa_trust.py, any IPA trust test
* test_krb.py, any test that is specific to kerberos.
* test_service.py, any test that is checking the SSSD service, process and child processes.
* test_kcm.py, contains kerberos cache manager tests.
* test_autofs.py, contains auto file system (autofs) or automount tests.
* test_sudo.py, contains sudo privilege escalation tests.
* test_tools.py, contains any cli tool tests, like sss_obfuscate.
* test_sss_override.py, contains sss_override CLI tests.
* test_sssctl.py, contains sssctl CLI tests.
* test_infopipe.py, contains any d-bus infopipe tests.
* test_python_modules.py, contains integration tests for sss python modules.
* test_services.py, contains tests specific to the SSSD and processes.
* test_responders.py, contains responders tests, NSS, PAM and others.
* test_oidc_child.py, contains tests for the oidc_child helper utility.

.. note::

    Samba Active Directory is the only AD topology used when testing upstream. Please use 'AnyAD' topology if early testing is needed.

Test Scope
**********

Tests are written to check a specific user scenario, parameter, issue or bug. Often it will be faster to merge tests into one, or when test cases overlap. For simplicity, every test case is small and covers a specific case.

Test Naming
***********

Pytest requires that tests names and file names are pre-fixed with *test_*. Test names have been standardize to then contain the file name and describe what the test code does and may not match related bugs, issues or tickets.

Docstrings
**********

Each test is required to contain the following docstring fields.

* title: Required, descriptive abbreviated test name, the name should give you a good idea of what it covers.
* description: Optional, provide more detail about the test if necessary.
* setup: Required, incremented list of steps needed before the test scenario can be executed.
* steps: Required, incremented list of the test steps, beginning with the test scenario.
* expectedresults: Required, incremented list of the results, matching the chronological order of test steps.
* customerscenario: Required, true or false.
* requirement: Required, test requirement or None.

.. code-block::

    def test_authentication__with_default_settings(
        client: Client, provider: GenericProvider, method, str, sssd_service_user: str):
        """
        :title: Authenticate user with default settings
        :setup:
            1. Create user
            2. Start SSSD
        :steps:
            1. Authenticate user with correct password
            2. Authenticate user with incorrect password
        :expectedresults:
            1. Authentication is successful
            2. Authentication is unsuccessful
        :customerscenario: False
        """
        provider.user("user1").add(password="Secret123")

        client.sssd.start(service_user=sssd_service_user)

        assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"
        assert not client.auth.parametrize(method).password(
            "user1", "NOTSecret123"
        ), "User logged in with an invalid password!"


.. note::

    Test code should follow the steps in order, making it easy to follow. Strip anything that is not relevant to the test, like extra configuration parameters, unused users or groups. Exceptions are fine, kindly comment the reason. Generally, language should be clear and short enough to comprehend the case but should be reduced if it becomes overly complicated with detail.

Parameterization
****************

    Tests can be parameterized to reduce the volume of test cases. In the following example, a total of four scenarios will be executed from this single test: 'su:root, su:sssd, ssh:root, ssh:sssd'. Previously, four test cases would have been written to provide the same coverage.

.. code-block::

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    @pytest.mark.parametrize("method", ["su", "ssh"])
    @pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))

Look for opportunities to reduce the amount of test cases and test code to ease maintenance.

For more detail in our coding styles and concepts, please visit `writing system tests <https://tests.sssd.io/en/latest/concepts.html>`__ page.

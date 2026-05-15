""" AD-Provider AD Login Attributes tests ported from bash

:requirement: ad_login_attr
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:caseautomation: Automated
:testtype: functional
"""


import pytest
from pexpect import pxssh
from sssd.testlib.common.utils import sssdTools


@pytest.fixture(scope="function", name="sssd_domain")
def fixture_sssd_domain(session_multihost, request):
    """Change domain to sssd_domain"""
    session_multihost.client[0].run_command(
        'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.sssd_domain',
        raiseonerr=False
    )
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    dom_section = f'domain/{client.get_domain_section_name()}'
    session_multihost.client[0].run_command(
        f'sed -i  "s|{dom_section}|domain/sssd_domain|g" /etc/sssd/sssd.conf',
        raiseonerr=False
    )
    client.sssd_conf('sssd', {'domains': 'sssd_domain', })

    def remove_sssd_domain():
        """ Remove sssd_domain"""
        session_multihost.client[0].run_command(
            'mv -f /etc/sssd/sssd.conf.sssd_domain /etc/sssd/sssd.conf',
            raiseonerr=False
        )
    request.addfinalizer(remove_sssd_domain)


@pytest.mark.tier1_3
@pytest.mark.adloginattr
@pytest.mark.usefixtures("joinad")
class TestADLoginAttributes:
    """Automated Test Cases for AD Login Attributes ported from bash"""

    @staticmethod
    def test_0001_login_by_samaccountname(multihost, create_aduser_group):
        """test_0001_login_by_samaccountname

        :title: IDM-SSSD-TC: ad_provider: ad_login_attr: Default behaviour
          by login with sAMAccountName
        :id: ba681368-eefe-459f-906e-1b32d405d496
        :setup:
          1. Configure sssd with ldap_user_principal = userPrincipalName
        :steps:
          1. Run getent passwd for the user.
          2. Run su for the user with short name (without domain).
          3. Run ssh for the user with short name (without domain).
        :expectedresults:
          1. User is found.
          2. Su command succeeds.
          3. Ssh command succeeds.
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'use_fully_qualified_names': 'False',
            'debug_level': '9',
            'id_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_schema': 'ad',
            'ldap_user_principal': 'userPrincipalName',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}',
            raiseonerr=False
        )

        # Run su command
        su_result = client.su_success(aduser)
        # Run ssh command
        ssh_result = client.auth_from_client(aduser, 'Secret123') == 3

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_result, "The su command failed!"
        assert ssh_result, "The ssh login failed!"

    @staticmethod
    def test_0002_login_by_userprincipalname(multihost, create_aduser_group):
        """test_0002_login_by_userprincipalname

        :title: IDM-SSSD-TC: ad_provider: ad_login_attr: Verify user login
         with userPrincipalName
        :id: 589f4fb3-ef62-42c1-827a-77d73129b879
        :setup:
          1. Configure sssd with ldap_user_principal = userPrincipalName
        :steps:
          1. Run su for the user with fully qualified name.
          2. Run ssh for the user with fully qualified name.
        :expectedresults:
          1. Su command succeeds.
          3. Ssh command succeeds.
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        ad_realm = multihost.ad[0].domainname.upper()
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'False',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_schema': 'ad',
            'ldap_user_principal': 'userPrincipalName',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Run su command
        su_result = client.su_success(f'{aduser}@{ad_realm}')
        # Run ssh command
        ssh_result = client.auth_from_client(
            f'{aduser}@{ad_realm}', 'Secret123') == 3
        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert su_result, "The su command failed!"
        assert ssh_result, "The ssh login failed!"

    @staticmethod
    @pytest.mark.usefixtures("sssd_domain")
    def test_0003_login_sssd_domain(multihost, create_aduser_group):
        """test_0003_login_sssd_domain

        :title: IDM-SSSD-TC: ad_provider: ad_login_attr: Verify user login
         using sssd domain name
        :id: 6b40310f-c1a8-4179-b41a-69b3eecde4ff
        :setup:
          1. Configure sssd with sssd_domain
        :steps:
          1. Run su for the user with sssd_domain.
          2. Run ssh for the user with sssd_domain.
        :expectedresults:
          1. Su command succeeds.
          2. Ssh command succeeds.
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = 'domain/sssd_domain'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'False',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_schema': 'ad',
            'ldap_user_principal': 'userPrincipalName',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Run su command
        su_result = client.su_success(f'{aduser}@sssd_domain')
        # Run ssh command
        ssh_result = client.auth_from_client(
            f'{aduser}@sssd_domain', 'Secret123') == 3
        # Evaluate test results
        assert su_result, "The su command failed!"
        assert ssh_result, "The ssh login failed!"

    @staticmethod
    @pytest.mark.usefixtures("sssd_domain")
    def test_0004_login_sssd_domain_fqn(multihost, create_aduser_group):
        """test_0004_login_sssd_domain_fqn

        :title: IDM-SSSD-TC: ad_provider: ad_login_attr: Verify login
         attributes with fully qualified name
        :id: 536ff920-e1c1-4948-b0ce-4fc024e1c5ba
        :setup:
          1. Configure sssd with sssd_domain and userPrincipalName
          2. Configure full_name_format to %1$s@%2$s
        :steps:
          1. Run su for the user with sssd domain.
          2. Run su for the user with fully qualified name.
          3. Run ssh for the user with sssd domain.
          4. Run ssh for the user with fully qualified name.
        :expectedresults:
          1. Su command succeeds
          2. Su command succeeds
          3. Ssh command succeeds
          4. Ssh command succeeds
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        ad_realm = multihost.ad[0].domainname.upper()
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dom_section = 'domain/sssd_domain'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'True',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_schema': 'ad',
            'full_name_format': '%1$s@%2$s',
            'ldap_user_principal': 'userPrincipalName',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Run su command
        su_result_plain = client.su_success(f'{aduser}')
        su_result_sssd = client.su_success(f'{aduser}@sssd_domain')
        su_result_fqn = client.su_success(
            f'{aduser}@{ad_realm}')
        # Run ssh command
        ssh_result = client.auth_from_client(
            f'{aduser}@sssd_domain', 'Secret123') == 3
        ssh_result_fqn = client.auth_from_client(
            f'{aduser}@{ad_realm}', 'Secret123') == 3
        # Evaluate test results
        assert not su_result_plain, "The su command did not fail!"
        assert su_result_sssd, "The su command failed for sssd_domain!"
        assert su_result_fqn, "The su command failed for fqn!"
        assert ssh_result, "The ssh login with sssd_domain failed!"
        assert ssh_result_fqn, "The ssh login with fqn failed!"

    @staticmethod
    def test_0005_login_sssd_domain_uppercase(
            multihost, create_aduser_group):
        """test_0005_login_sssd_domain_uppercase

        :title: IDM-SSSD-TC: ad_provider: ad_login_attr: Verify login
         attributes with upper case names
        :id: 03d198fd-96bc-4ea4-9ba3-dd37bae3def5
        :setup:
          1. Configure sssd with ldap_user_principal = userPrincipalName
        :steps:
          1. Run su for the user in uppercase without domain.
          2. Run su for the user in uppercase with domain.
          3. Run ssh for the user in uppercase with domain.
        :expectedresults:
          1. Su command fails.
          2. Su command succeeds.
          2. Ssh command succeeds.
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'True',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_schema': 'ad',
            'ldap_user_principal': 'userPrincipalName',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Run su command
        su_result_upper = client.su_success(f'{aduser.upper()}')
        su_result_fqn = client.su_success(
            f'{aduser.upper()}@{multihost.ad[0].domainname}')

        # Run ssh command
        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"})
        ssh.force_password = True
        ssh_result = True
        try:
            ssh.login(
                multihost.client[0].sys_hostname,
                f'{aduser.upper()}@{multihost.ad[0].domainname}', 'Secret123')
            ssh.prompt(timeout=5)
            ssh.logout()
        except pxssh.ExceptionPxssh:
            ssh_result = False

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert not su_result_upper, "The su command did not fail as expected!"
        assert su_result_fqn, "The su command failed for fqn!"
        assert ssh_result, "The ssh login failed!"

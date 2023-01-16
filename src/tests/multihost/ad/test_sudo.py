""" AD Sudo test cases

:requirement: ad_sudo
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import re
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('enable_ad_sudoschema',
                         'create_ad_sudousers',
                         'sudorules',
                         'joinad')
@pytest.mark.sudo
@pytest.mark.tier2
class TestSudo(object):
    """ Automation of BZ's related to Sudo with AD """

    @classmethod
    def class_setup(cls, multihost):
        """ Set sudo provider to AD """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.sssd_conf('sssd', {'services': 'nss, pam, sudo'})
        params = {
            'use_fully_qualified_names': 'False',
            'sudo_provider': 'ad',
            'debug_level': '9'}
        client.sssd_conf(f'domain/{client.get_domain_section_name()}', params)
        enable_sssd = 'authselect select sssd with-sudo with-mkhomedir --force'
        multihost.client[0].run_command(enable_sssd, raiseonerr=False)
        client.clear_sssd_cache()

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__case_sensitive_false')
    def test_001_bz1380436(multihost):
        """test_001_bz1380436

        :title: IDM-SSSD-TC: ad_provider: ad_sudo: ignore case
         on case insenstive Domain
        :id: 6cc67f37-808a-4b2c-a2cc-e4e4812388f4
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=1622109
          https://bugzilla.redhat.com/show_bug.cgi?id=1519287
        :customerscenario: True
        :steps:
          1. Add sudo rules containing upper and lower case user names
          2. Login with lower and upper user case names
        :expectedresults:
          1. Should succeed
          2. Verify the the user when logged in with upper
             and lower case can fetch the sudo rules from AD
        :description: Sudo rules used in the fixture contain
          multiple sudoUser attributes.
        """
        realm = multihost.ad[0].realm
        adusers = ['sudo_idmuser1', 'SUDO_IDMUSER1', 'sudo_idmuser2',
                   f'sudo_idmuser3@{realm}', 'sudo_idmuser3', 'SUDO_IDMUSER3']
        failed = []
        for user in adusers:
            cmd = multihost.client[0].run_command(
                f'su - {user} -c "sudo -l"', raiseonerr=False)
            if cmd.returncode != 0 or \
                    '(root) NOPASSWD: /usr/bin/less' not in cmd.stdout_text:
                failed.append(user)

        assert not failed, f"Rules missing for users: {','.join(failed)}"

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__sudo_user_is_group')
    def test_002_bz1372440(multihost):
        """test_002_bz1372440

        :title: IDM-SSSD-TC: ad_provider: ad_sudo: AD managed sudo groups
         will not work with sssd
        :id: 56616411-d56a-4e3f-b732-a39a4fae8bbc
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1372440
        :steps:
          1. Add sudo rules with sudoUser attribute set to group names
             (%sudo_idmgroup1 which has member sudo_idmuser1)
          2. Add users to the group.
          3. Verify sudo_idmuser1 can fetch the sudo rule
          4. Run the required command as sudo
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        user = 'sudo_idmuser1'

        # Test ssh login
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ssh_result = client.auth_from_client(user, 'Secret123') == 3

        cmd = multihost.client[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)

        rule_result = cmd.returncode == 0 and \
            '(root) NOPASSWD: /usr/bin/less' in cmd.stdout_text

        cmd2 = multihost.client[0].run_command(
            f'su - {user} -c "sudo -n /usr/bin/less /etc/passwd"',
            raiseonerr=False)

        assert ssh_result, f"Ssh failed for user: {user}."
        assert rule_result, f"Rules missing for user: {user}."
        assert cmd2.returncode == 0, f"Sudo command failed for user: {user}!"

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__sudo_user_is_nonposix_group')
    def test_003_support_non_posix_group_in_sudorule(multihost):
        """test_003_support_non_posix_group_in_sudorule

        :title: IDM-SSSD-TC: ad_provider: ad_sudo: support non-posix
         groups in sudo rules
        :id: b2def0eb-772d-41b4-b496-f7b3cb61169d
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1826272
        :steps:
          1. Disable ldap_id_mapping on client
          2. Create a non-posix group in the AD and add an AD-user as a
             members to it
          3. Add a sudo rule in the /etc/sudoers file for this user with
             '%:<group_name>'
          4. List the sudo commands allowed for the user
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Verify sudo_userx can fetch the sudo rule and run
             the required command as sudo
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_sect = f'domain/{multihost.ad[0].domainname}'
        user = 'sudo_user1'
        client.sssd_conf(domain_sect, {'ldap_id_mapping': 'false'})
        client.clear_sssd_cache()

        # Test ssh login
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ssh_result = client.auth_from_client(user, 'Secret123') == 3

        cmd = multihost.client[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)

        test_result = cmd.returncode == 0
        test_result = test_result and '(root) NOPASSWD: /usr/bin/head' in\
            cmd.stdout_text

        client.sssd_conf(
            domain_sect, {'ldap_id_mapping': 'false'}, action='delete')
        client.clear_sssd_cache()
        assert ssh_result, f"Ssh failed for user: {user}."
        assert test_result, f"Rules missing for user: {user}."

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__runasuser_shortname')
    def test_004_sudorule_with_short_username(multihost):
        """test_004_sudorule_with_short_username

        :title: sssd should accept a short-username to sudoRunAs option
        :id:61b1abf2-310b-4cdf-8238-b32d235df9a9
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1910131
        :setup:
         1. Add sudo rules with sudoRunAs attribute value set to short-username
         2. Join a client, without fqdn, to the AD
         3. Set debug level to 2
        :steps:
          1. Run sudo command as AD-user for whom rule is created
        :expectedResuls:
          1. There should be no error in the sudo or domain log related
             to 'short-username or non-fqdn username'
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        params = {'debug_level': '2'}
        client.sssd_conf(domain_section, params)
        client.sssd_conf('sudo', params)
        multihost.client[0].service_sssd('restart')
        user = 'sudo_usera'
        client.clear_sssd_cache()
        sudo_log = '/var/log/sssd/sssd_sudo.log'
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        for file in sudo_log, domain_log:
            log = multihost.client[0].get_file_contents(file).decode('utf-8')
            msg = 'Unable to parse name (.*) The internal name format '\
                  'cannot be parsed'
            find = re.compile(r'%s' % msg)
            assert not find.search(log)

        # Test ssh login
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ssh_result = client.auth_from_client(user, 'Secret123') == 3

        cmd = multihost.client[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)

        test_result = cmd.returncode == 0
        test_result = \
            test_result and '(sudo_idmuser1) NOPASSWD: /usr/bin/head' in\
            cmd.stdout_text

        client.sssd_conf('sudo', params, action='delete')

        assert ssh_result, f"Ssh failed for user: {user}."
        assert test_result, f"Rules missing for user: {user}."

    @classmethod
    def class_teardown(cls, multihost):
        """ Remove sudo provider from Domain section """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_section = f'domain/{client.get_domain_section_name()}'
        client.sssd_conf('sssd', {'services': 'nss, pam'})
        params = {
            'use_fully_qualified_names': 'False',
            'sudo_provider': 'ad',
            'debug_level': '9'}
        client.sssd_conf(domain_section, params, action='delete')

        # Cleanup homes
        multihost.client[0].run_command(
            'rm -rf /home/{sudo,SUDO}_*', raiseonerr=False)

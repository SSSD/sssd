""" AD Sudo test cases

:requirement: ad_sudo
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import pytest
import paramiko
import time
import re
from sssd.testlib.common.utils import SSHClient
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
        services = {'services': 'nss, pam, sudo'}
        domain_name = client.get_domain_section_name()
        domain_section = 'domain/%s' % (domain_name)
        client.sssd_conf('sssd', services)
        params = {
            'use_fully_qualified_names': 'False',
            'sudo_provider': 'ad',
            'debug_level': '9'}
        client.sssd_conf(domain_section, params)
        enable_sssd = 'authselect select sssd with-sudo --force'
        multihost.client[0].run_command(enable_sssd, raiseonerr=False)
        client.clear_sssd_cache()

    def test_001_bz1380436(self, multihost):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_sudo: ignore case
         on case insenstive Domain
        :id: 6cc67f37-808a-4b2c-a2cc-e4e4812388f4
        :customerscenario: True
        :steps:
          1. Add sudo rules containing upper and lower case user names
          2. Login with lower and upper user case names
        :expectedresults:
          1. Should succeed
          2. Verify the the user when logged in with upper
             and lower case can fetch the sudo rules from AD
        Note: This test case also cover BZ-1622109 and BZ-bz1519287
        Sudo rules used in the fixture contains multiple
        sudoUser attributes added.
        """
        multihost.client[0].service_sssd('restart')
        realm = multihost.ad[0].realm
        adusers = ['sudo_idmuser1', 'SUDO_IDMUSER1', 'sudo_idmuser2',
                   'sudo_idmuser3@%s' % (realm), 'sudo_idmuser3',
                   'SUDO_IDMUSER3']
        for user in adusers:
            try:
                ssh = SSHClient(multihost.client[0].sys_hostname,
                                username=user, password='Secret123')

            except paramiko.ssh_exception.AuthenticationException:
                pytest.fail('%s failed to login' % user)
            else:
                (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
                assert exit_status == 0
                result = []
                assert exit_status == 0
                for line in stdout.readlines():
                    if 'NOPASSWD' in line:
                        line.strip()
                        result.append(line.strip('(root) NOPASSWD: '))
                        assert '/usr/bin/less\n' in result

    def test_002_bz1372440(self, multihost):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_sudo: AD managed sudo groups
         will not work with sssd
        :id: 56616411-d56a-4e3f-b732-a39a4fae8bbc
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
        multihost.client[0].service_sssd('restart')
        aduser = 'sudo_idmuser1'
        try:
            ssh = SSHClient(multihost.client[0].sys_hostname,
                            username=aduser, password='Secret123')

        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail('%s failed to login' % aduser)
        else:
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
            assert exit_status == 0
            result = []
            assert exit_status == 0
            for line in stdout.readlines():
                if 'NOPASSWD' in line:
                    line.strip()
                    result.append(line.strip('(root) NOPASSWD: '))
                    assert '/usr/bin/less\n' in result

    def test_003_support_non_posix_group_in_sudorule(self, multihost):
        """
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
             the required command  as sudo
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = multihost.ad[0].domainname
        ad_user = 'sudo_user1'
        domain_section = 'domain/%s' % (domain_name)
        params = {'ldap_id_mapping': 'false'}
        client.sssd_conf(domain_section, params)
        multihost.client[0].service_sssd('restart')
        time.sleep(5)
        try:
            ssh = SSHClient(multihost.client[0].sys_hostname,
                            username=ad_user, password='Secret123')

        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail('%s failed to login' % ad_user)
        else:
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
            assert exit_status == 0
            result = []
            for line in stdout.readlines():
                if 'NOPASSWD' in line:
                    line.strip()
                    result.append(line.strip('(root) NOPASSWD: '))
        params = {'ldap_id_mapping': 'false'}
        client.sssd_conf(domain_section, params, action='delete')
        assert '/usr/bin/head\n' in result

    def test_004_sudorule_with_short_username(self, multihost):
        """
        :title: sssd should accept a short-username to sudoRunAs option
        :id:61b1abf2-310b-4cdf-8238-b32d235df9a9
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1910131
        :setup:
        1. Add sudo rules with sudoRunAs attribute value set to short-username
        2. Join a client, without fqdn, to the AD
        3. Set debug level to 2

        :steps:
         1.Run sudo command as AD-user for whom rule is created
        :expectedResuls:
        1. There should be no error in the sudo or domain log related
           to 'short-username or non-fqdn username'
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = 'domain/%s' % (domain_name)
        params = {
            'debug_level': '2'}
        client.sssd_conf(domain_section, params)
        client.sssd_conf('sudo', params)
        multihost.client[0].service_sssd('restart')
        aduser = 'sudo_usera'
        user_as = 'sudo_idmuser1'
        client.clear_sssd_cache()
        sudo_log = '/var/log/sssd/sssd_sudo.log'
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        for file in sudo_log, domain_log:
            log = multihost.client[0].get_file_contents(file).decode('utf-8')
            msg = 'Unable to parse name (.*) The internal name format '\
                  'cannot be parsed'
            find = re.compile(r'%s' % msg)
            assert not find.search(log)
        try:
            ssh = SSHClient(multihost.client[0].sys_hostname,
                            username=aduser, password='Secret123')

        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail('%s failed to login' % aduser)
        else:
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
            assert exit_status == 0
            result = []
            assert exit_status == 0
            for line in stdout.readlines():
                if 'NOPASSWD' in line:
                    line.strip()
                    result.append(line.strip('(sudo_idmuser1) NOPASSWD: '))
                    assert '/usr/bin/head\n' in result
        client.sssd_conf('sudo', params, action='delete')

    @classmethod
    def class_teardown(cls, multihost):
        """ Remove sudo provider from Domain section """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = 'domain/%s' % (domain_name)
        services = {'services': 'nss, pam'}
        client.sssd_conf('sssd', services)
        params = {
            'use_fully_qualified_names': 'False',
            'sudo_provider': 'ad',
            'debug_level': '9'}
        client.sssd_conf(domain_section, params, action='delete')

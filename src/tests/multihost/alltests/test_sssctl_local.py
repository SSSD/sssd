""" Automation of sssctl suite

:requirement: IDM-SSSD-REQ: Status utility
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException


def client_version(multihost):
    if [int(s) for s in multihost.client[0].distro if s.isdigit()][0] >= 9:
        return True


@pytest.mark.usefixtures('default_sssd')
@pytest.mark.sssctl
class Testsssctl(object):
    """
    This is test case class for sssctl suite
    """
    @pytest.mark.converted('test_sssctl.py', 'test_sssctl__user_show_cache_expiration_time')
    @pytest.mark.tier1_2
    def test_0001_bz1640576(self, multihost,
                            backupsssdconf,
                            localusers):
        """
        :title: IDM-SSSD-TC: sssctl: sssctl reports incorrect
         information about local user's cache entry expiration time
        :id: 9315c119-8c69-4685-836d-0f71b5d0684c
        """
        users = localusers
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        sssd_param = {'domains': 'local'}
        tools.sssd_conf('sssd', sssd_param)
        param = {'id_provider': 'files',
                 'passwd_files': '/etc/passwd'}
        tools.sssd_conf('domain/local', param)
        multihost.client[0].service_sssd('start')
        for user in users.keys():
            sssctl_cmd = 'sssctl user-show %s' % user
            cmd = multihost.client[0].run_command(sssctl_cmd,
                                                  raiseonerr=False)
            assert 'Cache entry expiration time: Never'\
                   in cmd.stdout_text

    @pytest.mark.converted('test_sssctl.py', 'test_sssctl__handle_implicit_domain')
    @pytest.mark.tier1_2
    def test_0002_bz1599207(self, multihost,
                            backupsssdconf,
                            localusers):
        """
        :title: IDM-SSSD-TC: sssctl: sssd tools do not handle the implicit
         domain
        :id: b5ff4e8f-ce9f-4731-bbaa-bf2a8425dc15
        """
        users = localusers
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        tools.sssd_conf("sssd",
                        {'enable_files_domain': 'true'},
                        action='update')
        multihost.client[0].service_sssd('start')
        for user in users.keys():
            cmd = multihost.client[0].run_command('getent'
                                                  ' -s sss'
                                                  ' passwd %s '
                                                  '&& sssctl '
                                                  'user-show %s' %
                                                  (user, user),
                                                  raiseonerr=False)
            assert 'Cache entry creation date' in \
                   cmd.stdout_text and cmd.returncode == 0

    @pytest.mark.converted('test_sss_cache.py', 'test_sss_cache__cache_expire_message')
    @pytest.mark.tier1_2
    def test_0003_bz1661182(self, multihost,
                            backupsssdconf):
        """
        :title: sss_cache prints spurious error messages
         when invoked from shadow-utils on package install
        :id: 8f2868d2-1ece-11ec-ac6d-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1661182
        :steps:
          1. Configure sssd without any domain
          2. Restart sssd (sssd should not be running after this)
          3. Modify existing local user usermod -a -G wheel user1
          4. This message
             '[sss_cache] [confdb_get_domains] (0x0010):
             No domains configured, fatal error!'
             must not appear in console
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        ldap_params = {'enable_files_domain': 'false'}
        tools.sssd_conf('sssd', ldap_params)
        with pytest.raises(SSSDException):
            multihost.client[0].service_sssd('restart')
        ps_cmd = "> /var/log/sssd/sssd.log"
        multihost.client[0].run_command(ps_cmd)
        ps_cmd = "useradd user1_test"
        multihost.client[0].run_command(ps_cmd, raiseonerr=False)
        ps_cmd = "usermod -a -G wheel user1_test"
        cmd = multihost.client[0].run_command(ps_cmd)
        assert 'No domains configured, fatal error!' \
               not in cmd.stdout_text
        ps_cmd = "userdel user1_test"
        multihost.client[0].run_command(ps_cmd)
        for ps_cmd in ('sss_cache -U',
                       'sss_cache -G',
                       'sss_cache -E',
                       'sss_cache -u non-existinguser'):
            cmd = multihost.client[0].run_command(ps_cmd)
            assert 'No domains configured, fatal error!' \
                   not in cmd.stdout_text

""" Automation of sssctl suite"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF


@pytest.mark.usefixtures('default_sssd')
@pytest.mark.sssctl
class Testsssctl(object):
    """
    This is test case class for sssctl suite
    """
    @pytest.mark.tier1_2
    def test_0001_bz1640576(self, multihost, localusers):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl reports incorrect
        information about local user's cache entry expiration time
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
            cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
            assert 'Cache entry expiration time: Never' in cmd.stdout_text

    @pytest.mark.tier1_2
    def test_0002_bz1599207(self, multihost, backupsssdconf, localusers):
        """
        @Title: IDM-SSSD-TC: sssctl: sssd tools do not handle the implicit
        domain
        """
        users = localusers
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        rm_cmd = 'rm -f %s' % SSSD_DEFAULT_CONF
        multihost.client[0].run_command(rm_cmd, raiseonerr=False)
        multihost.client[0].service_sssd('start')
        for user in users.keys():
            cmd = 'getent -s sss passwd %s && sssctl user-show %s' % (
                user, user)
            cmd = multihost.client[0].run_command(cmd, raiseonerr=False)
            assert 'Cache entry creation date' in cmd.stdout_text and \
                   cmd.returncode == 0

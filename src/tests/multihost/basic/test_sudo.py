""" SUDO responder sanity Test Cases

:requirement: sudo
:casecomponent: sssd
:subsystemteam: sst_identity_management
:upstream: yes
"""
from sssd.testlib.common.utils import SSHClient
import paramiko
import pytest
import time


class TestSanitySudo(object):
    """ Basic Sanity Test cases for sudo service in sssd """
    def test_case_senitivity(self, multihost, case_sensitive_sudorule,
                             enable_sss_sudo_nsswitch,
                             set_case_sensitive_false):
        """
        :title: sudo: Verify case sensitivity in sudo responder
        :id: 64ab80be-17fd-4c3b-9d9b-7d07c6279975
        """
        # pylint: disable=unused-argument
        _pytest_fixtures = [case_sensitive_sudorule, enable_sss_sudo_nsswitch,
                            set_case_sensitive_false]
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='capsuser-1', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("%s failed to login" % 'capsuser-1')
        else:
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
            result = []
            assert exit_status == 0
            for line in stdout.readlines():
                if 'NOPASSWD' in line:
                    line.strip()
                    result.append(line.strip('(root) NOPASSWD: '))
            assert '/usr/bin/less\n' in result
            assert '/usr/bin/more\n' in result
            ssh.close()

    def test_refresh_expired_rule(self, multihost,
                                  enable_sss_sudo_nsswitch,
                                  generic_sudorule,
                                  set_entry_cache_sudo_timeout):
        """
        :title: sudo: Verify refreshing expired sudo rules
         do not crash sssd_sudo
        :id: 532513b2-15bc-46ac-8fc9-19fd0bf485c4
        """
        # pylint: disable=unused-argument
        _pytest_fixtures = [enable_sss_sudo_nsswitch, generic_sudorule,
                            set_entry_cache_sudo_timeout]
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo1', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("%s failed to login" % 'foo1')
        else:
            print("Executing %s command as %s user" % ('sudo -l', 'foo1'))
            (_, _, exit_status) = ssh.execute_cmd('sudo -l')
            assert exit_status == 0
            time.sleep(30)
            if exit_status != 0:
                journalctl_cmd = 'journalctl -x -n 100 --no-pager'
                multihost.master[0].run_command(journalctl_cmd)
                pytest.fail("%s cmd failed for user %s" % ('sudo -l', 'foo1'))
            ssh.close()

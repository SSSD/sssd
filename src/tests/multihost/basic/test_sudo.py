""" SUDO responder sanity Test Cases """
from sssd.testlib.common.utils import SSHClient
import paramiko
import pytest


class TestSanitySudo(object):
    """ Basic Sanity Test cases for sudo service in sssd """
    def test_case_senitivity(self, multihost, create_sudorule,
                             enable_sss_sudo_nsswitch,
                             set_case_sensitive_false):
        """ Verify case sensitivity in sudo responder """
        # pylint: disable=unused-argument
        _pytest_fixtures = [create_sudorule, enable_sss_sudo_nsswitch,
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

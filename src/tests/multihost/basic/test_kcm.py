""" KCM Responder Sanity Test Cases """
from sssd.testlib.common.utils import SSHClient
import paramiko
import pytest


class TestSanityKCM(object):
    """ KCM Sanity Test cases """
    def test_kinit_kcm(self, multihost):
        """ Run kinit with KRB5CCNAME=KCM: """
        start_kcm = 'systemctl start sssd-kcm'
        multihost.master[0].run_command(start_kcm)
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo3', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo3'))
        else:
            (_, _, exit_status) = ssh.execute_cmd('KRB5CCNAME=KCM:; kinit',
                                                  stdin='Secret123')
            assert exit_status == 0
            (stdout, _, _) = ssh.execute_cmd('KRB5CCNAME=KCM:;klist')
            for line in stdout.readlines():
                if 'Ticket cache: KCM:14583103' in str(line.strip()):
                    assert True
                    break
                else:
                    assert False
            assert exit_status == 0
            ssh.close()

    def test_ssh_login_kcm(self, multihost, enable_kcm):
        """ Verify ssh logins are successuful with kcm as default """
        # pylint: disable=unused-argument
        _pytest_fixture = [enable_kcm]
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo4', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            journalctl_cmd = 'journalctl -u sssd -n 50 --no-pager'
            multihost.master[0].run_command(journalctl_cmd)
            pytest.fail("Authentication Failed as user %s" % ('foo4'))
        else:
            assert True
            ssh.close()

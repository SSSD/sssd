""" KCM Responder Sanity Test Cases """
from sssd.testlib.common.utils import SSHClient
import paramiko
import pytest
import os
from utils_config import set_param, remove_section


class TestSanityKCM(object):
    """ KCM Sanity Test cases """
    def _kcm_service_op(self, multihost, svc_op):
        systemd_kcm_op = 'systemctl %s sssd-kcm' % (svc_op)
        multihost.master[0].run_command(systemd_kcm_op)

    def _start_kcm(self, multihost):
        self._kcm_service_op(multihost, 'start')

    def _stop_kcm(self, multihost):
        self._kcm_service_op(multihost, 'stop')

    def _restart_kcm(self, multihost):
        self._kcm_service_op(multihost, 'restart')

    def _remove_kcm_log_file(self, multihost):
        multihost.master[0].run_command('rm -f /var/log/sssd/sssd_kcm.log')

    def _kcm_log_length(self, multihost):
        basename = 'sssd_kcm.log'
        kcm_log_file = '/var/log/sssd/' + basename
        local_kcm_log_file = '/tmp/kcm.log'
        try:
            multihost.master[0].transport.get_file(kcm_log_file,
                                                   local_kcm_log_file)
        except FileNotFoundError:
            return 0

        nlines = sum(1 for line in open(local_kcm_log_file))
        os.remove(local_kcm_log_file)
        return nlines

    def test_kinit_kcm(self, multihost, enable_kcm):
        """ Run kinit with KRB5CCNAME=KCM: """
        self._start_kcm(multihost)
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

    def test_kcm_debug_level_set(self, multihost, enable_kcm):
        """
        Test that just adding a [kcm] section and restarting the kcm
        service enables debugging without having to restart the
        whole sssd
        """
        # Start from a known-good state where the configuration is refreshed
        # by the monitor and logging is completely disabled
        multihost.master[0].service_sssd('stop')
        self._stop_kcm(multihost)
        self._remove_kcm_log_file(multihost)
        set_param(multihost, 'kcm', 'debug_level', '0')
        multihost.master[0].service_sssd('start')
        self._start_kcm(multihost)

        log_lines_pre = self._kcm_log_length(multihost)

        # Debugging is disabled, kinit and make sure that no debug messages
        # were produced
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo3', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo3'))
        else:
            ssh.execute_cmd('kdestroy')
            ssh.close()

        log_lines_nodebug = self._kcm_log_length(multihost)
        assert log_lines_nodebug == log_lines_pre

        # Enable debugging, restart only the kcm service, make sure some
        # debug messages were produced
        set_param(multihost, 'kcm', 'debug_level', '9')
        self._restart_kcm(multihost)

        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo3', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo3'))
        else:
            ssh.execute_cmd('kdestroy')
            ssh.close()

        log_lines_debug = self._kcm_log_length(multihost)
        assert log_lines_debug > log_lines_pre + 100

    def test_kdestroy_retval(self, multihost, enable_kcm):
        """
        Test that destroying an empty cache does not return a non-zero
        return code.
        """
        ssh = SSHClient(multihost.master[0].sys_hostname,
                        username='foo3', password='Secret123')

        (_, _, exit_status) = ssh.execute_cmd('kdestroy')
        assert exit_status == 0
        # Run the command again in case there was something in the ccache
        # previously
        (_, _, exit_status) = ssh.execute_cmd('kdestroy')
        assert exit_status == 0

        ssh.close()

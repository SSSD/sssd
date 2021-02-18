""" KCM Responder Sanity Test Cases

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
:casecomponent: sssd
:subsystemteam: sst_identity_management
:upstream: yes
"""
from sssd.testlib.common.utils import SSHClient
import paramiko
import pytest
import os
import re
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

    def _remove_secret_db(self, multihost):
        multihost.master[0].run_command(
                'rm -f /var/lib/sss/secrets/secrets.ldb')
        self._restart_kcm(multihost)

    def test_kinit_kcm(self, multihost, enable_kcm):
        """
        :title: kcm: Run kinit with KRB5CCNAME=KCM
        :id: 245eecf6-04b9-4c9f-8685-681d184fbbcf
        """
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
        """
        :title: kcm: Verify ssh logins are successuful with kcm as default
        :id: 458ed1e4-b908-40d3-b2fd-392e8d2dcf4b
        """
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
        :title: kcm: After kcm section with debug
         level set restaring sssd-kcm service enables kcm debugging
        :id: 31c74bfc-69d5-46bd-aef8-a5581970832e
        :description: Test that just adding a [kcm] section and restarting
         the kcm service enables debugging without having to restart the
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
        :title: kcm: Test that destroying an empty cache does
         not return a non-zero return code
        :id: 2826097f-e6d7-4d99-ac85-3ee081aa681a
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

    def test_ssh_forward_creds(self, multihost, enable_kcm):
        """
        :title: kcm: Test that SSH can forward credentials with KCM
        :id: f4b0c785-a895-48a1-a55e-7519cf221393
        :ticket: https://github.com/SSSD/sssd/issues/4863
        """
        ssh = SSHClient(multihost.master[0].sys_hostname,
                        username='foo3', password='Secret123')

        (_, _, exit_status) = ssh.execute_cmd('kdestroy')
        assert exit_status == 0

        (_, _, exit_status) = ssh.execute_cmd('kinit foo9',
                                              stdin='Secret123')
        assert exit_status == 0

        ssh_k_cmd = 'ssh -oStrictHostKeyChecking=no -K -l foo9 ' + \
                    multihost.master[0].sys_hostname + \
                    ' klist'

        (stdout, _, exit_status) = ssh.execute_cmd(ssh_k_cmd)
        assert exit_status == 0

        has_cache = False
        for line in stdout.readlines():
            if 'KCM:14583109' in line:
                has_cache = True
        assert has_cache is True

    def test_kvno_display(self, multihost, enable_kcm):
        """
        :title: kcm: Test kvno correctly displays version numbers of principals
        :id: 7c9178e6-fea5-44a1-b473-76667624cee2
        :ticket: https://github.com/SSSD/sssd/issues/4763
        """
        ssh = SSHClient(multihost.master[0].sys_hostname,
                        username='foo4', password='Secret123')
        host_princ = 'host/%s@%s' % (multihost.master[0].sys_hostname,
                                     'EXAMPLE.TEST')
        kvno_cmd = 'kvno %s' % (host_princ)
        (stdout, _, exit_status) = ssh.execute_cmd(kvno_cmd)
        for line in stdout.readlines():
            kvno_check = re.search(r'%s: kvno = (\d+)' % host_princ, line)
            if kvno_check:
                print(kvno_check.group())
            else:
                pytest.fail("kvno display was improper")
        ssh.close()

    def test_kcm_peruid_quota(self,
                              multihost,
                              enable_kcm,
                              create_many_user_principals):
        """
        :title: kcm: Make sure the quota limits a client, but only that client
        :id: 3ac8f62e-05e4-4ca7-b588-145fd6258c2a
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)

        ssh_foo2 = SSHClient(multihost.master[0].sys_hostname,
                             username='foo2', password='Secret123')
        ssh_foo3 = SSHClient(multihost.master[0].sys_hostname,
                             username='foo3', password='Secret123')

        # The loop would request 63 users, plus there is foo3 we authenticated
        # earlier, so this should exactly deplete the quota, but should succeed
        for i in range(1, 64):
            username = "user%04d" % i
            (_, _, exit_status) = ssh_foo3.execute_cmd('kinit %s' % username,
                                                       stdin='Secret123')
            assert exit_status == 0

        # this kinit should be exactly one over the peruid limit
        (_, _, exit_status) = ssh_foo3.execute_cmd('kinit user0064',
                                                   stdin='Secret123')
        assert exit_status != 0

        # Since this is a per-uid limit, another user should be able to kinit
        # just fine
        (_, _, exit_status) = ssh_foo2.execute_cmd('kinit user0064',
                                                   stdin='Secret123')
        assert exit_status == 0

        # kdestroy as the original user, the quota should allow a subsequent
        # kinit
        ssh_foo3.execute_cmd('kdestroy -A')
        (_, _, exit_status) = ssh_foo3.execute_cmd('kinit user0064',
                                                   stdin='Secret123')
        assert exit_status == 0

        ssh_foo2.execute_cmd('kdestroy -A')
        ssh_foo2.close()
        ssh_foo3.execute_cmd('kdestroy -A')
        ssh_foo3.close()

    def test_kcm_peruid_quota_increase(self,
                                       multihost,
                                       enable_kcm,
                                       create_many_user_principals):
        """
        :title: kcm: Quota increase
        :id: 0b3cab49-befb-4ab2-bb12-b102d94249aa
        :description: Increasing the peruid quota allows a client to store
         more data
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)

        ssh_foo3 = SSHClient(multihost.master[0].sys_hostname,
                             username='foo3', password='Secret123')

        # The loop would request 63 users, plus there is foo3 we authenticated
        # earlier, so this should exactly deplete the quota, but should succeed
        for i in range(1, 64):
            username = "user%04d" % i
            (_, _, exit_status) = ssh_foo3.execute_cmd('kinit %s' % username,
                                                       stdin='Secret123')
            assert exit_status == 0

        # this kinit should be exactly one over the peruid limit
        (_, _, exit_status) = ssh_foo3.execute_cmd('kinit user0064',
                                                   stdin='Secret123')
        assert exit_status != 0

        set_param(multihost, 'kcm', 'max_uid_ccaches', '65')
        self._restart_kcm(multihost)

        # Now the kinit should work as we increased the limit
        (_, _, exit_status) = ssh_foo3.execute_cmd('kinit user0064',
                                                   stdin='Secret123')
        assert exit_status == 0

        ssh_foo3.execute_cmd('kdestroy -A')
        ssh_foo3.close()

    def test_kcm_payload_low_quota(self,
                                   multihost,
                                   enable_kcm):
        """
        :title: kcm: Quota enforcement
        :id: cb3daadb-c5e7-48f8-b419-11c616f0d602
        :description: Set a prohibitive quota for the per-ccache payload
         limit and make sure it gets enforced
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)

        ssh_foo3 = SSHClient(multihost.master[0].sys_hostname,
                             username='foo3', password='Secret123')
        ssh_foo3.execute_cmd('kdestroy -A')
        ssh_foo3.close()

        set_param(multihost, 'kcm', 'max_ccache_size', '1')
        self._restart_kcm(multihost)

        # We use kinit to exceed the maximum ccache size as it creates payload
        # of 1280 bytes by acquiring tgt and also some control credentials.
        # SSH authentication is not sufficient as it stores only tgt.
        ssh_foo3 = SSHClient(multihost.master[0].sys_hostname,
                             username='foo3', password='Secret123')
        (_, _, exit_status) = ssh_foo3.execute_cmd(
            'kinit foo3@EXAMPLE.TEST', 'Secret123'
        )
        assert exit_status != 0

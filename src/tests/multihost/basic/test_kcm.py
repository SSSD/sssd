""" KCM Responder Sanity Test Cases

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import os
import re
import pytest
from pexpect import pxssh
from utils_config import set_param
from sssd.testlib.common.utils import sssdTools


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
        except (FileNotFoundError, OSError):
            return 0

        nlines = sum(1 for line in open(local_kcm_log_file))
        os.remove(local_kcm_log_file)
        return nlines

    def _remove_secret_db(self, multihost):
        multihost.master[0].run_command(
            'rm -f /var/lib/sss/secrets/secrets.ldb')
        self._restart_kcm(multihost)

    @pytest.mark.usefixtures("enable_kcm")
    def test_kinit_kcm(self, multihost):
        """
        :title: kcm: Run kinit with KRB5CCNAME=KCM
        :id: 245eecf6-04b9-4c9f-8685-681d184fbbcf
        """
        self._start_kcm(multihost)

        user = 'foo3'
        cmd = multihost.master[0].run_command(
            f'su - {user} -c "KRB5CCNAME=KCM:; kinit"', stdin_text='Secret123',
            raiseonerr=False)
        assert cmd.returncode == 0, "kinit failed!"

        cmd2 = multihost.master[0].run_command(
            f'su - {user} -c "KRB5CCNAME=KCM:; klist"', raiseonerr=False)
        assert cmd2.returncode == 0, "klist failed!"
        assert 'Ticket cache: KCM:14583103' in cmd2.stdout_text

    @staticmethod
    @pytest.mark.usefixtures("enable_kcm")
    def test_ssh_login_kcm(multihost):
        """
        :title: kcm: Verify ssh logins are successuful with kcm as default
        :id: 458ed1e4-b908-40d3-b2fd-392e8d2dcf4b
        """
        # pylint: disable=unused-argument
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client("foo4", 'Secret123') == 3
        if not ssh0:
            multihost.master[0].run_command(
                'journalctl -u sssd -n 50 --no-pager')
        assert ssh0, "Authentication Failed as user foo4"

    @pytest.mark.usefixtures("enable_kcm")
    def test_kcm_debug_level_set(self, multihost):
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
        user = 'foo3'
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client(user, 'Secret123') == 3
        assert ssh0, f"Authentication Failed as user {user}."

        multihost.master[0].run_command(
            f'su - {user} -c "kdestroy"', raiseonerr=False)

        log_lines_nodebug = self._kcm_log_length(multihost)
        assert log_lines_nodebug == log_lines_pre

        # Enable debugging, restart only the kcm service, make sure some
        # debug messages were produced
        set_param(multihost, 'kcm', 'debug_level', '9')
        self._restart_kcm(multihost)

        ssh1 = client.auth_from_client(user, 'Secret123') == 3
        assert ssh1, f"Authentication Failed as user {user}."

        multihost.master[0].run_command(
            f'su - {user} -c "kdestroy"', raiseonerr=False)

        log_lines_debug = self._kcm_log_length(multihost)
        assert log_lines_debug > log_lines_pre + 100

    @staticmethod
    @pytest.mark.usefixtures("enable_kcm")
    def test_kdestroy_retval(multihost):
        """
        :title: kcm: Test that destroying an empty cache does
         not return a non-zero return code
        :id: 2826097f-e6d7-4d99-ac85-3ee081aa681a
        """

        user = 'foo3'
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client(user, 'Secret123') == 3
        assert ssh0, f"Authentication Failed as user {user}."

        kd1 = multihost.master[0].run_command(
            f'su -l {user} -c "kdestroy"', raiseonerr=False)
        assert kd1.returncode == 0, "First kdestroy failed!"

        # Run the command again in case there was something in the ccache
        # previously
        kd2 = multihost.master[0].run_command(
            f'su -l {user} -c "kdestroy"', raiseonerr=False)
        assert kd2.returncode == 0, "Second kdestroy failed!"

    @staticmethod
    @pytest.mark.usefixtures("enable_kcm")
    def test_ssh_forward_creds(multihost):
        """
        :title: kcm: Test that SSH can forward credentials with KCM
        :id: f4b0c785-a895-48a1-a55e-7519cf221393
        :ticket: https://github.com/SSSD/sssd/issues/4863
        """
        ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                          "UserKnownHostsFile": "/dev/null"})
        ssh.force_password = True
        try:
            ssh.login(multihost.master[0].sys_hostname, 'foo3', 'Secret123')
            ssh.sendline('kdestroy -A -q')
            ssh.prompt(timeout=5)
            ssh.sendline('kinit foo9')
            ssh.expect('Password for .*:', timeout=10)
            ssh.sendline('Secret123')
            ssh.prompt(timeout=5)
            ssh.sendline('klist')
            ssh.prompt(timeout=5)
            klist = str(ssh.before)
            ssh.sendline(f'ssh -v -o StrictHostKeyChecking=no -K -l foo9 '
                         f'{multihost.master[0].sys_hostname} klist')
            ssh.prompt(timeout=30)
            ssh_output = str(ssh.before)
            ssh.logout()
        except pxssh.ExceptionPxssh as ex:
            pytest.fail(ex)
        # Note: The cache is based on uid so for foo3 it is 14583103 and
        # for foo9 it is 14583109 (see create_posix_usersgroups fixture)
        assert 'KCM:14583103' in klist, "kinit did not work!"
        assert 'KCM:14583109' in ssh_output, "Ticket not forwarded!"

    @staticmethod
    @pytest.mark.usefixtures("enable_kcm")
    def test_kvno_display(multihost):
        """
        :title: kcm: Test kvno correctly displays version numbers of principals
        :id: 7c9178e6-fea5-44a1-b473-76667624cee2
        :ticket: https://github.com/SSSD/sssd/issues/4763
        """
        host_princ = f'host/{multihost.master[0].sys_hostname}@EXAMPLE.TEST'
        kvno_cmd = f'kvno {host_princ}'

        client = sssdTools(multihost.master[0])
        client.auth_from_client('foo4', 'Secret123')

        kvno = multihost.master[0].run_command(
            f'su -l foo4 -c "{kvno_cmd}"', raiseonerr=False)
        assert kvno.returncode == 0, "kvno failed!"

        for line in kvno.stdout_text.splitlines():
            kvno_check = re.search(r'%s: kvno = (\d+)' % host_princ, line)
            if kvno_check:
                print(kvno_check.group())
            else:
                pytest.fail("kvno display was improper")

    @pytest.mark.usefixtures("enable_kcm", "create_many_user_principals")
    def test_kcm_peruid_quota(self, multihost):
        """
        :title: kcm: Make sure the quota limits a client, but only that client
        :id: 3ac8f62e-05e4-4ca7-b588-145fd6258c2a
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)

        client = sssdTools(multihost.master[0])
        client.auth_from_client('foo2', 'Secret123')
        client.auth_from_client('foo3', 'Secret123')

        # The loop would request 63 users, plus there is foo3 we authenticated
        # earlier, so this should exactly deplete the quota, but should succeed
        for i in range(1, 64):
            username = "user%04d" % i
            kinit = multihost.master[0].run_command(
                f'su -l foo3 -c "kinit {username}"',
                stdin_text='Secret123', raiseonerr=False)
            assert kinit.returncode == 0

        # this kinit should be exactly one over the peruid limit
        kinit_f = multihost.master[0].run_command(
            'su -l foo3 -c "kinit user0064"',
            stdin_text='Secret123', raiseonerr=False)
        assert kinit_f.returncode != 0

        # Since this is a per-uid limit, another user should be able to kinit
        # just fine
        # this kinit should be exactly one over the peruid limit
        kinit_o = multihost.master[0].run_command(
            'su -l foo2 -c "kinit user0064"',
            stdin_text='Secret123', raiseonerr=False)
        assert kinit_o.returncode == 0

        # kdestroy as the original user, the quota should allow a subsequent
        # kinit
        multihost.master[0].run_command(
            'su -l foo3 -c "kdestroy -A"', raiseonerr=False)
        kinit_p = multihost.master[0].run_command(
            'su -l foo3 -c "kinit user0064"',
            stdin_text='Secret123', raiseonerr=False)
        assert kinit_p.returncode == 0

        multihost.master[0].run_command(
            'su -l foo2 -c "kdestroy -A"', raiseonerr=False)

        multihost.master[0].run_command(
            'su -l foo3 -c "kdestroy -A"', raiseonerr=False)

    @pytest.mark.usefixtures("enable_kcm", "create_many_user_principals")
    def test_kcm_peruid_quota_increase(self, multihost):
        """
        :title: kcm: Quota increase
        :id: 0b3cab49-befb-4ab2-bb12-b102d94249aa
        :description: Increasing the peruid quota allows a client to store
         more data
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)
        user = 'foo3'
        client = sssdTools(multihost.master[0])
        client.auth_from_client(user, 'Secret123')

        # The loop would request 63 users, plus there is foo3 we authenticated
        # earlier, so this should exactly deplete the quota, but should succeed
        for i in range(1, 64):
            username = "user%04d" % i
            kinit = multihost.master[0].run_command(
                f'su -l {user} -c "kinit {username}"',
                stdin_text='Secret123', raiseonerr=False)
            assert kinit.returncode == 0

        # this kinit should be exactly one over the peruid limit
        kinit_f = multihost.master[0].run_command(
            f'su -l {user} -c "kinit user0064"',
            stdin_text='Secret123', raiseonerr=False)
        assert kinit_f.returncode != 0

        set_param(multihost, 'kcm', 'max_uid_ccaches', '65')
        self._restart_kcm(multihost)

        # Now the kinit should work as we increased the limit
        kinit_p = multihost.master[0].run_command(
            f'su -l {user} -c "kinit user0064"',
            stdin_text='Secret123', raiseonerr=False)
        assert kinit_p.returncode == 0

        multihost.master[0].run_command(
            f'su -l {user} -c "kdestroy -A"', raiseonerr=False)

    @pytest.mark.usefixtures("enable_kcm")
    def test_kcm_payload_low_quota(self, multihost):
        """
        :title: kcm: Quota enforcement
        :id: cb3daadb-c5e7-48f8-b419-11c616f0d602
        :description: Set a prohibitive quota for the per-ccache payload
         limit and make sure it gets enforced
        """
        # It is easier to keep these tests stable and independent from others
        # if they start from a clean slate
        self._remove_secret_db(multihost)
        user = 'foo3'
        client = sssdTools(multihost.master[0])
        client.auth_from_client(user, 'Secret123')

        multihost.master[0].run_command(
            f'su -l {user} -c "kdestroy -A"', raiseonerr=False)

        set_param(multihost, 'kcm', 'max_ccache_size', '1')
        self._restart_kcm(multihost)

        # We use kinit to exceed the maximum ccache size as it creates payload
        # of 1280 bytes by acquiring tgt and also some control credentials.
        # SSH authentication is not sufficient as it stores only tgt.
        kv_p = multihost.master[0].run_command(
            f'su -l foo3 -c "kinit {user}@EXAMPLE.TEST"',
            stdin_text='Secret123', raiseonerr=False)
        assert kv_p.returncode != 0

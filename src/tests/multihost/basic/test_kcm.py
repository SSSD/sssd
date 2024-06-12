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

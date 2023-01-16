""" SUDO responder sanity Test Cases

:requirement: sudo
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import time
import pytest
from sssd.testlib.common.utils import sssdTools


class TestSanitySudo(object):
    """ Basic Sanity Test cases for sudo service in sssd """
    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__case_sensitive_false')
    @pytest.mark.usefixtures(
        "case_sensitive_sudorule", "enable_sss_sudo_nsswitch",
        "set_case_sensitive_false")
    def test_case_senitivity(multihost):
        """
        :title: sudo: Verify case sensitivity in sudo responder
        :id: 64ab80be-17fd-4c3b-9d9b-7d07c6279975
        """
        user = 'capsuser-1'
        # Test ssh login
        client = sssdTools(multihost.master[0])
        ssh_result = client.auth_from_client(user, 'Secret123') == 3
        cmd = multihost.master[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)
        rule_result = cmd.returncode == 0 and \
            '(root) NOPASSWD: /usr/bin/less' in cmd.stdout_text
        rule2_result = cmd.returncode == 0 and \
            '(root) NOPASSWD: /usr/bin/more' in cmd.stdout_text
        assert ssh_result, f"Ssh failed for user: {user}."
        assert rule_result, f"Rules missing for user: {user}."
        assert rule2_result, f"Rules missing for user: {user}."

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__rules_refresh')
    @pytest.mark.usefixtures("enable_sss_sudo_nsswitch", "generic_sudorule",
                             "set_entry_cache_sudo_timeout")
    def test_refresh_expired_rule(multihost):
        """
        :title: sudo: Verify refreshing expired sudo rules
         do not crash sssd_sudo
        :id: 532513b2-15bc-46ac-8fc9-19fd0bf485c4
        """

        user = 'foo1'
        # Test ssh login
        client = sssdTools(multihost.master[0])
        ssh_result = client.auth_from_client(user, 'Secret123') == 3
        cmd = multihost.master[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)
        time.sleep(30)
        cmd2 = multihost.master[0].run_command(
            f'su - {user} -c "sudo -l"', raiseonerr=False)

        assert ssh_result, f"Ssh failed for user: {user}."
        assert cmd.returncode == 0, \
            f"First sudo -l failed for user: {user}."
        assert cmd2.returncode == 0, \
            f"Second sudo -l failed for user: {user}."

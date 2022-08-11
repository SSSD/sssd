""" Automation of proxy provider suite

:requirement: IDM-SSSD-REQ : Proxy Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.usefixtures('setup_sssd_krb',
                         'create_posix_usersgroups',
                         'install_nslcd',
                         'sssdproxyldap',
                         'sssdproxyldap_test')
@pytest.mark.tier1_3
class TestProxy(object):
    """
    This is test case class for ldap proxy suite
    """
    @staticmethod
    @pytest.mark.usefixtures('backupsssdconf')
    def test_proxy_lookup(multihost):
        """
        :title: Proxy lookup and kerberos auth
        :id: 5c4c55b8-0cac-47d0-aa23-d057b790e18e
        :steps:
          1. Check ldap user has access to client machine
          2. Proxy lookup and kerberos auth
        :expectedresults:
          1. Should succeed
          2. Should succeed
        """
        # proxy lookup and kerberos auth
        tools = sssdTools(multihost.client[0])
        tools.clear_sssd_cache()
        ssh1 = tools.auth_from_client("foo2@example1", 'Secret123') == 3
        assert ssh1, "Ssh failed instead of passing!"
        assert "home/foo2:/bin/bash" in execute_cmd(multihost,
                                                    "getent -s "
                                                    "ldap passwd "
                                                    "foo2").stdout_text

    @staticmethod
    def test_expired_password(multihost):
        """
        :title: Change expired password
        :id: 60de31d3-82e8-4f35-999d-5f9f15e0caed
        :steps:
          1. Change expired password
        :expectedresults:
          1. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        # Change expired password
        multihost.master[0].run_command("kadmin.local "
                                        "-q 'modprinc -pwexpire "
                                        "now foo2@example1'")
        tools.clear_sssd_cache()
        multihost.client[0].run_command("yum install -y expect",
                                        raiseonerr=False)
        execute_cmd(multihost, "sh /tmp/sssdproxyldap.sh")
        multihost.master[0].run_command("kadmin.local -q "
                                        "'addprinc -pw Secret123 "
                                        "foo2@example1'")

    @staticmethod
    def test_server_access(multihost):
        """
        :title: Proxy server access
        :id: 5fe5839b-fbfb-48be-87de-18c1b0de209c
        :steps:
          1. Block server access
          2. User should not have access
          3. Unblock server access
          4. User should have access
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        tools.clear_sssd_cache()
        ssh0 = tools.auth_from_client("foo2@example1", 'Secret123') == 3
        # block_server_access
        execute_cmd(multihost, "systemctl start firewalld")
        execute_cmd(multihost, f"firewall-cmd --direct "
                               f"--add-rule ipv4 filter "
                               f"OUTPUT 0 -d {multihost.master[0].ip} "
                               f"-j DROP")

        ssh1 = tools.auth_from_client("foo2@example1", 'Secret123') == 3

        # unblock_server_access
        execute_cmd(multihost, "firewall-cmd  --reload")
        execute_cmd(multihost, "systemctl stop firewalld")
        tools.clear_sssd_cache()
        ssh2 = tools.auth_from_client("foo2@example1", 'Secret123') == 3

        assert ssh0, "Ssh failed instead of passing!"
        assert not ssh1, "Ssh passed instead of failing!"
        assert ssh2, "Ssh failed instead of passing!"

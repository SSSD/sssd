""" Automation of ldap_extra_attr suite

:requirement: ldap_extra_attrs
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import os
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import SSHClient


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.ldapextraattrs
class TestLdapExtraAttrs(object):
    """
    This is test case class for ldap ldap_extra_attr suite
    """
    @staticmethod
    @pytest.mark.tier1
    def test_bz847043(multihost, backupsssdconf):
        """
        :title: Thread issue can cause the application to not get
            any identity information bz847043
        :id: a3f5b5ea-9cc6-11ed-98f2-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=847043
        :setup:
            1. Clear sssd caches
            2. Compile the provided C test program and run it
        :steps:
            1. Log in via the ssh
            2. With the fixed version, the program should run to completion:
                ./client-hang
                Cancelling thread
                Joining...
                Joined, trying getpwuid_r call
                Never get here
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        client = multihost.client[0]
        tools.sssd_conf("nss", {'filter_groups': 'root',
                                'filter_users': 'root'},
                        action='update')
        tools.sssd_conf("domain/example1",
                        {'use_fully_qualified_names': False},
                        action='update')
        tools.clear_sssd_cache()
        file_location_c = '/script/sssd_client_hang.c'
        client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                                  + file_location_c,
                                  '/tmp/sssd_client_hang.c')
        client.run_command("touch /tmp/output")
        client.run_command("chown foo1 /tmp/output")
        client.run_command('gcc -lpthread /tmp/sssd_client_hang.c'
                           ' -o /tmp/client-hang')
        client.run_command("chown foo1 /tmp/client-hang")
        ssh = SSHClient(multihost.client[0].ip, 'foo1', 'Secret123')
        try:
            ssh.connect()
            ssh.execute_command('cd /tmp; ./client-hang > output')
        except Exception:
            pytest.fail("Ssh login failed.")
        time.sleep(2)
        log_str = multihost.client[0].get_file_contents("/tmp/output").decode('utf-8')
        assert "Never get here" in log_str

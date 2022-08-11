"""Automation for krb ldap connection

:requirement: krb_ldap_connection
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.krbldapconnection
@pytest.mark.tier1_3
@pytest.mark.usefixtures('setup_sssd_gssapi',
                         'create_posix_usersgroups')
class TestKrbConnectionTimeout(object):

    def test_timeoutkrb(self, multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_ldap_connection:
         Test for krb
        :id: b8b3e2ab-d24e-4da8-b750-e405f25c6908
        :expectedresults: In this case value of timeout depends upon
         max value of lifetime of ticket that is in our case is 120 seconds
         (2 mins). After that it should have to release the connection
        """
        cmd_mod_user = ["kadmin.local", "-q", "modprinc -maxlife 2mins foo1"]
        multihost.master[0].run_command(cmd_mod_user)
        cmd_mod = ["kadmin.local", "-q", "modprinc -maxlife 2mins krbtgt/EXAMPLE.TEST"]
        multihost.master[0].run_command(cmd_mod)
        multihost.client[0].log.info(
            '\n\n\nTesting for the case where timeout value is'
            'out of range (of integer). ldap_connection_expire_'
            'timeout = krb')
        domain_params = {'ldap_connection_expire_timeout': None}
        sssdTools(
            multihost.client[0]).sssd_conf(
            'domain/%s' %
            (ds_instance_name), domain_params, 'delete')
        cmd_restart = "systemctl restart sssd"
        multihost.client[0].run_command(cmd_restart)
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name
        sssdTools(multihost.client[0]).clear_sssd_cache()
        timeout = 120
        lookup_u = 'getent passwd foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(lookup_u)
        assert cmd.returncode == 0
        time.sleep(timeout + 5)
        lookup_u = 'getent passwd foo2@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(lookup_u)
        assert cmd.returncode == 0
        string = "Connection is about to expire, releasing it"
        file_content = multihost.client[0].get_file_contents(logfile)
        x = string.encode('utf-8') in file_content
        if x is True:
            assert True
        else:
            assert False
        cmd_remove_log = "rm /var/log/sssd/sssd_example1.log"
        multihost.client[0].run_command(cmd_remove_log)
        cmd_mod_user = ["kadmin.local", "-q", "modprinc -maxlife 1day foo1"]
        multihost.master[0].run_command(cmd_mod_user)
        cmd_mod = ["kadmin.local", "-q", "modprinc -maxlife 1day krbtgt/EXAMPLE.TEST"]
        multihost.master[0].run_command(cmd_mod)

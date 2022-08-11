""" Automation for sssd failover

:requirement: IDM-SSSD-REQ : Failover
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('multipleds_failover',
                         'create_posix_usersgroups_failover',
                         'setup_sssd_failover', )
@pytest.mark.failover
class TestFailover(object):
    """ Bug 1283798 failover automation
    :setup:
      1. Configure Directory servers on 2 Hosts (ldap1, ldap2)
      with TLS
      2. Configure sssd.conf on client with auth_provider: ldap
      3. specify ldaps in ldap_uri pointing to 2 directory servers
      example: ldap_uri: ldaps://ldap1, ldaps://ldap2
    """
    @staticmethod
    @pytest.mark.tier2
    def test_0001_getent(multihost):
        """
        :title: failover: Verify users can be queried from
         second directory server when first directory server is down
        :id: 0d145340-e147-4da7-acd0-f1c29891c397
        """
        # query ldap users when both ldaps servers are working
        user = 'foo0@%s' % ds_instance_name
        getent = 'getent passwd %s' % user
        cmd = multihost.client[0].run_command(getent)
        assert cmd.returncode == 0
        tools = sssdTools(multihost.client[0])
        # stop first directory server instance_name
        stop_ds1 = 'systemctl stop dirsrv@example'
        cmd = multihost.master[0].run_command(stop_ds1, raiseonerr=False)
        assert cmd.returncode == 0
        # query the new  user foo1
        user = 'foo1@%s' % ds_instance_name
        getent = 'getent passwd %s' % user
        cmd = multihost.client[0].run_command(getent)
        assert cmd.returncode == 0
        # clear the cache and query foo1 user again
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        multihost.client[0].service_sssd('start')
        cmd = multihost.client[0].run_command(getent)
        assert cmd.returncode == 0
        # start the first directory server
        start_ds1 = 'systemctl start dirsrv@example'
        cmd = multihost.master[0].run_command(start_ds1, raiseonerr=False)
        assert cmd.returncode == 0

    @staticmethod
    @pytest.mark.tier2
    def test_0002_login(multihost):
        """
        :title: failover: Verify users can login when the first
         ldap server is down
        :id: 9c0e0448-3fc2-44c7-96f8-9b8b44fa5cba
        """
        user = 'foo2@%s' % ds_instance_name
        stop_ds1 = 'systemctl stop dirsrv@example'
        cmd = multihost.master[0].run_command(stop_ds1, raiseonerr=False)
        assert cmd.returncode == 0
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        multihost.client[0].service_sssd('start')
        # login as user
        ssh = tools.auth_from_client(user, 'Secret123') == 3
        assert ssh, "Authentication failed!"
        start_ds1 = 'systemctl start dirsrv@example'
        cmd = multihost.master[0].run_command(start_ds1, raiseonerr=False)
        assert cmd.returncode == 0

    @staticmethod
    @pytest.mark.tier2
    def test_0003_stopsecondds(multihost):
        """
        :title: failover: Stop second ldap server and verify
         users are able to login from first ldap server
        :id: cf15aea7-a626-4ed2-a205-9180ddfe29b2
        """
        stop_ds2 = 'systemctl stop dirsrv@example'
        cmd = multihost.master[1].run_command(stop_ds2, raiseonerr=False)
        assert cmd.returncode == 0
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        multihost.client[0].service_sssd('start')
        user = 'foo3@%s' % ds_instance_name
        # login as user
        ssh = tools.auth_from_client(user, 'Secret123') == 3
        assert ssh, "Authentication failed!"
        start_ds1 = 'systemctl start dirsrv@example'
        cmd = multihost.master[0].run_command(start_ds1, raiseonerr=False)
        assert cmd.returncode == 0

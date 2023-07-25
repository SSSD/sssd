""" Automation for sssd failover  """
import pytest
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient
from constants import ds_instance_name


@pytest.mark.usefixtures('multipleds_failover',
                         'create_posix_usersgroups_failover',
                         'setup_sssd_failover', )
@pytest.mark.failover
class TestFailover(object):
    """ Bug 1283798 failover automation
    @Setup:
    1. Configure Directory servers on 2 Hosts (ldap1, ldap2)
    with TLS
    2. Configure sssd.conf on client with auth_provider: ldap
    3. specify ldaps in ldap_uri pointing to 2 directory servers
    example: ldap_uri: ldaps://ldap1, ldaps://ldap2
    """
    @pytest.mark.tier2
    def test_0001_getent(self, multihost):
        """
        @Title: failover: Verify users can be queried from
        second directory server when first directory server is down
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

    @pytest.mark.tier2
    def test_0002_login(self, multihost):
        """
        @Title: failover: Verify users can login when the first
        ldap server is down
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
        ssh = SSHClient(multihost.client[0].external_hostname,
                        username=user,
                        password='Secret123')
        assert ssh.connect
        ssh.close()
        # start the first directory server
        start_ds1 = 'systemctl start dirsrv@example'
        cmd = multihost.master[0].run_command(start_ds1, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier2
    def test_0003_stopsecondds(self, multihost):
        """
        @Title: failover: Stop second ldap server and verify
        users are able to login from first ldap server
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
        ssh = SSHClient(multihost.client[0].external_hostname,
                        username=user,
                        password='Secret123')
        assert ssh.connect
        ssh.close()
        # start the first directory server
        start_ds1 = 'systemctl start dirsrv@example'
        cmd = multihost.master[0].run_command(start_ds1, raiseonerr=False)
        assert cmd.returncode == 0

""" Automation of auto private groups"""
from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd',
                         'create_posix_usersgroups',
                         'create_posix_usersgroups_autoprivategroups')
@pytest.mark.autoprivategroup
class TestAutoPrivateGroups(object):
    @pytest.mark.tier1
    def test_0001_bz1695577(self, multihost, backupsssdconf):
        """
        :Title: user_private_group: auto_private_group set to hybrid
        uid equals to gid and group exists
        """
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        apg = {'auto_private_groups': 'hybrid'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), apg)
        section = "sssd"
        """
        enable_files_domain = false  is a workaround
        Remove that once original bz fixes it"""
        sssd_params = {'enable_files_domain': 'False'}
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf(section, sssd_params)
        start = multihost.client[0].service_sssd('start')
        for i in range(9):
            lkup = 'id foobar%d@%s' % (i, ds_instance_name)
            cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
            lkup = 'getent group foobar%d@%s' % (i, ds_instance_name)
            cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
            lkup = 'getent passwd foobar%d@%s' % (i, ds_instance_name)
            cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
            output = cmd.stdout_text.split(':')
            assert int(output[2]) == int(output[3])

    @pytest.mark.tier1
    def test_0002_bz1695577(self, multihost, backupsssdconf):
        """
        :Title: user_private_group: auto_private_group set to hybrid
        uid does not equals to gid and group does exists
        """
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        apg = {'auto_private_groups': 'hybrid'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), apg)
        section = "sssd"
        """
        enable_files_domain = false  is a workaround
        Remove that once original bz fixes it"""
        sssd_params = {'enable_files_domain': 'False'}
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf(section, sssd_params)
        start = multihost.client[0].service_sssd('start')
        lkup = 'getent passwd foobar11@%s' % (ds_instance_name)
        cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        output = cmd.stdout_text.split(':')
        assert int(output[2]) != int(output[3])


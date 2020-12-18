from __future__ import print_function
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.ldaplibdebuglevel
class TestLdapLibDebugLevel(object):
    """ Test ldap_library_debug_level option"""

    @pytest.mark.tier1_2
    def test_0001_bz1884207(self, multihost, backupsssdconf):
        """
        @Title: ldap_library_debug_level: Check ldap_library_debug_level
        option with config-check
        """
        section = "domain/%s" % ds_instance_name
        tools = sssdTools(multihost.client[0])
        domain_params = {'ldap_library_debug_level': '0'}
        tools.sssd_conf(section, domain_params)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier1_2
    def test_0002_bz1884207(self, multihost, backupsssdconf):
        """
        @Title: ldap_library_debug_level: Set ldap_library_debug_level to
        zero and check corresponding logs
        """
        section = "domain/%s" % ds_instance_name
        tools = sssdTools(multihost.client[0])
        domain_params = {'ldap_library_debug_level': '0'}
        tools.sssd_conf(section, domain_params)
        tools.clear_sssd_cache()
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name
        log_str = multihost.client[0].get_file_contents(logfile)
        find = re.compile(r'libldap')
        assert not find.search(log_str.decode())

    @pytest.mark.tier1_2
    def test_0003_bz1884207(self, multihost, backupsssdconf):
        """
        @Title: ldap_library_debug_level: Set ldap_library_debug_level to
        two and check corresponding logs
        """
        section = "domain/%s" % ds_instance_name
        tools = sssdTools(multihost.client[0])
        domain_params = {'ldap_library_debug_level': '2'}
        tools.sssd_conf(section, domain_params)
        tools.clear_sssd_cache()
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name
        log_str1 = multihost.client[0].get_file_contents(logfile)
        find = re.compile(r'libldap')
        assert find.search(log_str1.decode(errors='ignore'))

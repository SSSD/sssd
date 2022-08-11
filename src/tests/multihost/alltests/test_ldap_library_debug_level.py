"""Automation for ldap_library_debug_level

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
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
        :title: ldap_library_debug_level: Check ldap_library_debug_level
         option with config-check
        :id: b753a633-53ca-42ba-974e-cab6bfad17d2
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
        :title: ldap_library_debug_level: Set ldap_library_debug_level to
         zero and check corresponding logs
        :id: 6cf52e0f-594b-42b7-a933-6bf4257603c9
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
        :title: ldap_library_debug_level: Set ldap_library_debug_level to
         two and check corresponding logs
        :id: 97e03505-d5f3-45df-b6ed-f7ede1106f07
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

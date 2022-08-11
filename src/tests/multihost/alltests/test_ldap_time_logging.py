"""Automation for ldap_query_time_logging

:requirement: LDAP Query Time Logging
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
:bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1925559
"""
from __future__ import print_function
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.timelog
@pytest.mark.tier1_3
class TestLdapTimeLogging(object):
    """ Test ldap_time_logging """

    def test_0001_bz1925559(self, multihost, backupsssdconf):
        """
        :title: Check time logging is not enabled at debug_level 8"
        :description: Debug level of 8 and below does not enable time logging
        :id: 11379bae-99bd-4dd9-bee6-fa0dba28f4fe
        :steps:
          1. Set debug_level to 8 in sssd.conf
          2. Start sssd with cleared logs
          3. Lookup user
          4. Check logs in /var/log/sssd/
        :expectedresults:
          1. sssd should use default debug level 8
          2. sssd services start successfully
          3. Lookup user succeeds
          4. Log files has no time logged for ldap queries
        """
        section = f'domain/{ds_instance_name}'
        tools = sssdTools(multihost.client[0])
        domain_params = {'debug_level': '8'}
        tools.sssd_conf(section, domain_params)
        tools.clear_sssd_cache()

        user = f'foo9@{ds_instance_name}'
        get_user = f'getent passwd {user}'
        multihost.client[0].run_command(get_user, raiseonerr=False)
        log_list = ['sssd', f'sssd_{ds_instance_name}',
                    'sssd_nss', 'sssd_pam']
        for log in log_list:
            log = f'/var/log/sssd/{log}.log'
            log_str = multihost.client[0].get_file_contents(log).decode('utf-8')
            find = re.compile(r'milliseconds')
            assert not find.search(log_str)

    def test_0002_bz1925559(self, multihost, backupsssdconf):
        """
        :title: Time logging is enabled by bitmask 0x20000
        :description: 0x20000 is the bitmask to select the timing/statistical
         data. So time logging is only enabled when the bitmask is used directly
         or debug level is set to 9
        :id: 9fad8c34-bbac-43bd-81ae-fb1540075f2c
        :steps:
          1. Set debug_level to 9 in sssd.conf
          2. Start sssd with cleared logs
          3. Lookup user
          4. Check domain logs in /var/log/sssd/
          5. Repeat 1 - 4 with debug level 0x20000
        :expectedresults:
          1. sssd should use default debug level 9
          2. sssd services start successfully
          3. Lookup user succeeds
          4. Log files has time logged for ldap queries
          5. Should succeed
        """
        section = f'domain/{ds_instance_name}'
        tools = sssdTools(multihost.client[0])

        # Test with debug level 9
        domain_params = {'debug_level': '9'}
        tools.sssd_conf(section, domain_params)
        tools.clear_sssd_cache()
        user = f'foo3@{ds_instance_name}'
        get_user = f'getent passwd {user}'
        multihost.client[0].run_command(get_user, raiseonerr=False)
        log = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        log_str1 = multihost.client[0].get_file_contents(log).decode('utf-8')

        # Test with debug level 0x20000
        domain_params = {'debug_level': '0x20000'}
        tools.sssd_conf(section, domain_params)
        tools.clear_sssd_cache()
        multihost.client[0].run_command(get_user, raiseonerr=False)
        log_str2 = multihost.client[0].get_file_contents(log).decode('utf-8')

        find1 = re.compile(r'sdap_call_op_callback.*\[\d+[.]\d+\] milliseconds')
        find2 = re.compile(r'dp_req_done.*\[\d+[.]\d+\] milliseconds')
        assert find1.search(log_str1)
        assert find2.search(log_str1)
        assert find1.search(log_str2)
        assert find2.search(log_str2)

    def test_0003_bz1925559(self, multihost, backupsssdconf):
        """
        :title: Warning message for long queries without debug level set
        :id: 9280b9fa-e0b4-446a-92ad-258888195633
        :steps:
          1. Remove debug_level to enable default debug level
          2. Set delay to 800ms using tc on all interfaces of the client
          3. Set ldap_search_timeout to 1 second
          4. Start sssd with cleared logs
          5. Lookup user
          6. Check domain logs in /var/log/sssd/
        :expectedresults:
          1. sssd should use default debug level
          2. tc configures interfaces sucessfully
          3. Should succeed
          4. sssd services start successfully
          5. Lookup user succeeds with delay
          6. Domain log has a warning message for long query time
        """
        section = f'domain/{ds_instance_name}'
        tools = sssdTools(multihost.client[0])
        domain_params = {'debug_level': ''}
        tools.sssd_conf(section, domain_params, action="delete")
        domain_params = {'ldap_search_timeout': '1'}
        tools.sssd_conf(section, domain_params)

        get_intf = "nmcli device status | grep connected | awk '{print $1}'"
        intf = multihost.client[0].run_command(get_intf, raiseonerr=True)
        intf_list = intf.stdout_text.splitlines()
        print(f'List of interfaces - {intf_list}')
        pkgs = 'yum install -y iproute-tc kernel-modules-extra'
        multihost.client[0].run_command(pkgs, raiseonerr=True)
        for interface in intf_list:
            tc_rule = f'tc qdisc add dev {interface} root netem delay 800ms'
            multihost.client[0].run_command(tc_rule, raiseonerr=True)
            get_tc_rule = f'tc qdisc show dev {interface}'
            show_rule = multihost.client[0].run_command(get_tc_rule, raiseonerr=True)
            print(f'===tc rules for {interface}===:\n{show_rule.stdout_text}')
        tools.clear_sssd_cache()
        user = f'foo5@{ds_instance_name}'
        get_user = f'getent passwd {user}'
        multihost.client[0].run_command(get_user, raiseonerr=False)
        log = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        log_str = multihost.client[0].get_file_contents(log).decode('utf-8')
        for interface in intf_list:
            tc_rule = f'tc qdisc del dev {interface} root'
            multihost.client[0].run_command(tc_rule, raiseonerr=True)
        print(log_str)
        find = re.compile(r'sdap_call_op_callback.*more than 80% of timeout')
        assert find.search(log_str)

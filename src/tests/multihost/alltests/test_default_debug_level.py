"""Automation for default debug level

:requirement: SSSD - Default debug level
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import time
import pytest
from sssd.testlib.common.utils import sssdTools, LdapOperations
from sssd.testlib.common.ssh2_python import check_login_client_bool
from constants import ds_instance_name, ds_suffix, ds_rootpw, ds_rootdn


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.defaultdebuglevel
class TestDefaultDebugLevel(object):
    """ Check sssd default debug level """
    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_check')
    @pytest.mark.tier1_4
    def test_0001_check_default_debug_level(self, multihost, backupsssdconf):
        """
        :title: default debug logs: Check default debug level when sssd start
         successfully
        :id: 1f38b560-27dc-4144-895d-e667420b0467
        :steps:
          1. Remove debug_level from sssd.conf file
          2. Start sssd
          3. Check logs in /var/log/sssd
        :expectedresults:
          1. sssd should use default debug level with no level defined
          2. sssd services start successfully
          3. Log files has
             a. default level set to 0x0070
             b. 0x1f7c0 logs for "SSSDBG_IMPORTANT_INFO"
             c. Other logs could be <= 0x0040
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        # stop sssd, delete sssd logs and cache, start sssd
        tools.clear_sssd_cache()
        time.sleep(5)
        log_list = ['sssd', f'sssd_{ds_instance_name}',
                    'sssd_nss', 'sssd_pam']
        for log_filename in log_list:
            log = f'/var/log/sssd/{log_filename}.log'
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            print(f'\n{log_filename}\n+===++++++===+\n{log_str}\n')
            pattern1 = re.compile(r'Starting with debug level = 0x0070')
            default_debug = pattern1.search(log_str)
            assert default_debug is not None
            log_split = log_str.split("\n")
            for index in range(len(log_split) - 1):
                log_single_line = log_split[index]
                pattern2 = re.compile(r'\(0x\w+\)')
                debug_str1 = pattern2.search(log_single_line)
                assert debug_str1.group() == '(0x3f7c0)'

    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_check_with_login')
    @pytest.mark.tier1_4
    def test_0002_check_default_level_with_auth(self, multihost,
                                                backupsssdconf):
        """
        :title: default debug logs: Check successful login with default
         log level doesn't generate any logs
        :id: f40a7c66-6b5f-4f3c-8fcb-6aa12f415473
        :steps:
          1. Remove debug_level from sssd.conf file
          2. Add fallback_homedir (generates extra logs on
             user auth if not specified)
          3. Stop sssd, clear cache and logs, start sssd
          4. Check total log size before user auth
          5. Execute valid user authentication
          6. Check total log size after auth
          7. Log sizes before and after auth are the same
        :expectedresults:
          1. sssd should use default debug level with no level defined
          2. Succeeds
          3. sssd services start successfully
          4. Succeeds
          5. Succeeds
          6. Succeeds
          7. Succeeds
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        domain_params = {'fallback_homedir': '/home/%u'}
        tools.sssd_conf(section, domain_params)
        # stop sssd, delete logs and cache, start sssd
        tools.clear_sssd_cache()
        multihost.client[0].run_command('cat /etc/sssd/sssd.conf')
        check_log_size = "du -c /var/log/sssd/ | awk '/total/ {print $1}'"
        blog_size = multihost.client[0].run_command(check_log_size,
                                                    raiseonerr=False)
        print("before auth:", blog_size.stdout_text)
        user = f'foo1@{ds_instance_name}'
        # Authenticate user
        ssh = check_login_client_bool(multihost, user, 'Secret123')
        alog_size = multihost.client[0].run_command(check_log_size,
                                                    raiseonerr=False)
        print("after auth:", alog_size.stdout_text)
        assert ssh, f'{user} is not able to login'
        assert alog_size.stdout_text == blog_size.stdout_text

    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_fatal_and_critical_failures')
    @pytest.mark.tier2
    def test_0003_bz1893159(self, multihost, backupsssdconf):
        """
        :title: default debug logs: Check that messages with levels 0 and 1
         are printed with default log level
        :id: 79411fe9-99d6-430b-90fd-3eff1807975f
        :steps:
          1. Remove debug_level from sssd.conf
          2. chmod sssd.conf with 444 permissions
          3. Start sssd
          4. Check logs
        :expectedresults:
          1. sssd should use default debug level with no level defined
          2. Succeeds
          3. sssd fails to start
          4. Logs have both 'Fatal failures' (level 0) and
             'Critical failures' (level 1)
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        multihost.client[0].service_sssd('stop')
        chmod_cmd = 'chmod 444 /etc/sssd/sssd.conf'
        cmd = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        tools.remove_sss_cache('/var/log/sssd')
        multihost.client[0].run_command('systemctl start sssd',
                                        raiseonerr=False)
        slog = '/var/log/sssd/sssd.log'
        log_str = multihost.client[0].get_file_contents(slog).decode('utf-8')
        find1 = re.compile(r'0x0020')
        find2 = re.compile(r'0x0010')
        restore_sssd = 'chmod 600 /etc/sssd/sssd.conf'
        multihost.client[0].run_command(restore_sssd, raiseonerr=False)
        # Check that both 'Fatal failures' and 'Critical failures'
        # messages are in the logs
        if not find1.search(log_str) and not find2.search(log_str):
            assert False

    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_cannot_load_sssd_config')
    @pytest.mark.tier1_4
    def test_0004_bz1893159(self, multihost, backupsssdconf):
        """
        :title: default debug logs: Check default level 2
        :id: d44d5883-fc52-418d-b407-3ac63f7104d8
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1893159
        :setup:
          1. Remove debug_level option from sssd.conf
          2. Set domains = typo_domain (non existing) in [sssd] section
          3. Start sssd after clearing cache and logs
        :steps:
          1. Check sssd.log contains log related to 'SSSD cannot load config'
        :expectedresults:
          1. /var/log/sssd/sssd.log contains 'SSSD couldn't load configuration' log
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.sssd_conf('sssd', {'domains': 'some'}, action='update')
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/log/sssd')
        multihost.client[0].run_command('systemctl start sssd', raiseonerr=False)
        log = '/var/log/sssd/sssd.log'
        log_str = multihost.client[0].get_file_contents(log).decode('utf-8')
        pattern = re.compile(r'SSSD couldn\'t load the configuration database')
        assert pattern.search(log_str)

    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_nonexisting_ldap_server')
    @pytest.mark.tier1_4
    def test_bz1893159(self, multihost, backupsssdconf):
        """
        :title: default debug logs: default log level logs in sssd.log
        :id: 8f9c8c47-a1f6-4ec0-b979-202d8d6dc6c3
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1893159
        :setup:
          1. Remove debug_level option from sssd.conf
          2. Set ldap_uri to a non-existing ldap-server
          3. Start sssd after clearing cache and logs
        :steps:
          1. Check logs
        :expectedresults:
          1. Domain Logs should contain a log related to 'going offline'
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.sssd_conf(section, {'ldap_uri': 'ldap://typo'} , action='update')
        tools.clear_sssd_cache()
        log = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        log_str = multihost.client[0].get_file_contents(log).decode('utf-8')
        find = re.compile(r'Failed to connect, going offline')
        #check what is logged at default debug_level(2)
        assert find.search(log_str)

    @pytest.mark.converted('logging.py', 'test_logging__default_debug_level_sbus')
    @pytest.mark.tier1_4
    def test_0005_bz1915319(self, multihost, backupsssdconf):
        """
        :title: default debug logs: Check SBUS code should not trigger failure
         message during modules startup
        :id: 5c7b9eb7-ee89-4ed7-94d0-467de16a505f
        :steps:
          1. Remove debug_level from sssd.conf
          2. Start sssd after clearing cache and logs
          3. Check string "Unable to remove key" is not in the logs
        :expectedresults:
          1. sssd should use default debug level with no level defined
          2. Succeeds
          3. Succeeds
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        log_list = ['sssd', f'sssd_{ds_instance_name}',
                    'sssd_nss', 'sssd_pam']
        for log in log_list:
            log = f'/var/log/sssd/{log}.log'
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'Unable to remove key.*')
            assert not find.search(log_str)

    @staticmethod
    @pytest.mark.tier2
    def test_bz785908(multihost, backupsssdconf):
        """
        :title: ldap search base dose not fully limit the group search base bz785908
        :id: 5f736f56-a299-11ed-a880-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=785908
        :setup:
            1. Add users to Ldap server
            2. Create group with member within group search base
            2. Create group with member outside of the group search base
            4. Update sssd domain with ldap_group_object_class, ldap_search_base and
                ldap_group_object_class
        :steps:
            1. Runs command getent -s sss group to query the SSSD cache and save the results to a file.
            2. Cleans up the LDAP server by deleting the previously created user and group entries,
               and finally search for log messages containing the strings "Group111" and "Group22".
        :expectedresults:
            1. Query the SSSD cache and save the results to a file Should succeed
            2. Log messages should containing the strings
                "Group111" and "Group22" in the /tmp/grp_file
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = f'uid=tempuser2,{ds_suffix}'
        user_info = {'cn': 'Temp user2'.encode('utf-8'),
                     'loginshell': '/bin/bash'.encode('utf-8'),
                     'uidNumber': '121298'.encode('utf-8'),
                     'gidNumber': '10000'.encode('utf-8'),
                     'objectClass': ['top'.encode('utf-8'),
                                     'posixAccount'.encode('utf-8')],
                     'homeDirectory': '/home/tempuser2'.encode('utf-8'),
                     'userPassword': 'Secret123'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        user_dn = f'uid=tempuser3,{ds_suffix}'
        user_info = {'cn': 'Temp user3'.encode('utf-8'),
                     'loginshell': '/bin/bash'.encode('utf-8'),
                     'uidNumber': '121297'.encode('utf-8'),
                     'gidNumber': '10000'.encode('utf-8'),
                     'objectClass': ['top'.encode('utf-8'),
                                     'posixAccount'.encode('utf-8')],
                     'homeDirectory': '/home/tempuser3'.encode('utf-8'),
                     'userPassword': 'Secret123'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        ldap_inst.org_unit("qagroup", ds_suffix)
        group_dn = f"cn=Group11,ou=qagroup,{ds_suffix}"
        grp_info = {'cn': 'Group11'.encode('utf-8'),
                    'gidNumber': '222011'.encode('utf-8'),
                    'objectClass': ['top'.encode('utf-8'),
                                    'posixGroup'.encode('utf-8'),
                                    'groupOfNames'.encode('utf-8')],
                    'member': f'uid=tempuser3,{ds_suffix}'.encode('utf-8')}
        ldap_inst.add_entry(grp_info, group_dn)
        group_dn = f"cn=Group22,ou=Groups,{ds_suffix}"
        grp_info = {'cn': 'Group22'.encode('utf-8'),
                    'gidNumber': '222022'.encode('utf-8'),
                    'objectClass': ['top'.encode('utf-8'),
                                    'posixGroup'.encode('utf-8'),
                                    'groupOfNames'.encode('utf-8')],
                    'member': f'uid=tempuser3,{ds_suffix}'.encode('utf-8')}
        ldap_inst.add_entry(grp_info, group_dn)
        group_dn = f"cn=Group222,ou=qagroup,{ds_suffix}"
        grp_info = {'cn': 'Group222'.encode('utf-8'),
                    'gidNumber': '222000'.encode('utf-8'),
                    'objectClass': ['top'.encode('utf-8'),
                                    'posixGroup'.encode('utf-8'),
                                    'groupOfNames'.encode('utf-8')],
                    'member': [f'cn=Group11,ou=qagroup,{ds_suffix}'.encode('utf-8')]}
        ldap_inst.add_entry(grp_info, group_dn)
        group_dn = f"cn=Group111,ou=Groups,{ds_suffix}"
        grp_info = {'cn': 'Group111'.encode('utf-8'),
                    'gidNumber': '111000'.encode('utf-8'),
                    'objectClass': ['top'.encode('utf-8'),
                                    'posixGroup'.encode('utf-8'),
                                    'groupOfNames'.encode('utf-8')],
                    'member': [f'cn=Group222,ou=qagroup,{ds_suffix}'.encode('utf-8'),
                               f'cn=Group22,ou=Groups,{ds_suffix}'.encode('utf-8'),
                               f'uid=tempuser2,{ds_suffix}'.encode('utf-8')]}
        ldap_inst.add_entry(grp_info, group_dn)
        tools.sssd_conf("domain/example1",
                        {'cache_credentials': True,
                         'enumerate': True,
                         'ldap_search_base': f'ou=Groups,{ds_suffix}',
                         'ldap_schema': 'rfc2307bis',
                         'ldap_group_object_class': "groupOfNames"}, action='update')
        tools.clear_sssd_cache()
        time.sleep(20)
        cmd = client.run_command("getent -s sss group").stdout_text
        for dn_dn in [f'uid=tempuser2,{ds_suffix}',
                      f'uid=tempuser3,{ds_suffix}',
                      f'cn=Group111,ou=Groups,{ds_suffix}',
                      f'cn=Group222,ou=qagroup,{ds_suffix}',
                      f'cn=Group22,ou=Groups,{ds_suffix}',
                      f'cn=Group11,ou=qagroup,{ds_suffix}',
                      f'ou=qagroup,{ds_suffix}']:
            ldap_inst.del_dn(dn_dn)
        for group in ["Group111", "Group22"]:
            assert group in cmd

    @staticmethod
    @pytest.mark.tier1_4
    def test_bz785898(multihost, backupsssdconf):
        """
        :title: Enable midway cache refresh by default bz785898
        :id: 39695a7a-a29c-11ed-b2b1-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=785898
        :setup:
            1. Creates a user in the LDAP server for use in subsequent tests.
            3. Updates the SSSD configuration file for the specified domain with some configuration options.
            4. Updates the SSSD configuration file for the "nss" service with some configuration options.
            5. Updates the SSSD configuration file for the "sssd" service with a configuration option.
            6. Clears the SSSD cache.
            7. Creates a directory in the client machine's /tmp directory.
        :steps:
            1. Loops 30 times and performs the following actions in each iteration:
                Truncates the sssd_example1.log file.
                Calls the getent passwd command to retrieve information about the mid_cacheuser user.
                Waits for 3 seconds.
                Copies the contents of the sssd_example1.log file to a file in the /tmp/lookup directory.
            2. Search the /tmp/lookup directory for log
                entries containing the string "Got request for".
            3. Saves the output of the search to the /tmp/lookupfile file.
            4. Deletes the user created before.
            5. Removes the /tmp/lookup and /tmp/lookupfile directories.
            6. Reads the contents of the /tmp/lookupfile file and asserts that there are more than 2 lines.
        :expectedresults:
            1. All commands executed within the loop should Success
            2. "Got request for" string should present
            3. Successfully saved Output of the search to the /tmp/lookupfile file
            4. User deletion should success
            5. Removal of directories should success
            6. There should be more that 2 lines in /tmp/lookupfile
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = f'uid=mid_cacheuser,{ds_suffix}'
        user_info = {'cn': 'Midcache'.encode('utf-8'),
                     'loginshell': '/bin/bash'.encode('utf-8'),
                     'uidNumber': '121298'.encode('utf-8'),
                     'gidNumber': '10000'.encode('utf-8'),
                     'objectClass': ['top'.encode('utf-8'),
                                     'posixAccount'.encode('utf-8')],
                     'homeDirectory': '/home/mid_cacheuser'.encode('utf-8'),
                     'userPassword': 'Secret123'.encode('utf-8')}
        ldap_inst.add_entry(user_info, user_dn)
        tools.sssd_conf("domain/example1",
                        {'entry_cache_timeout': '60',
                         'cache_credentials': True,
                         'use_fully_qualified_names': False}, action='update')
        tools.sssd_conf("nss", {'filter_groups': 'root',
                                'filter_users': 'root',
                                'debug_level': '9',
                                'entry_cache_nowait_percentage': '50',
                                'memcache_timeout': '1'}, action='update')
        tools.sssd_conf("sssd", {'sbus_timeout': '30'}, action='update')
        tools.clear_sssd_cache()
        client.run_command("mkdir /tmp/lookup")
        for i in range(30):
            client.run_command("> /var/log/sssd/sssd_example1.log")
            client.run_command("getent passwd -s sss mid_cacheuser")
            time.sleep(3)
            client.run_command(f"cat /var/log/sssd/sssd_example1.log > /tmp/lookup/lookup{i}")
        client.run_command("grep -r 'Got request for' /tmp/lookup/")
        client.run_command("grep -r 'Got request for' /tmp/lookup > /tmp/lookupfile")
        time.sleep(3)
        ldap_inst.del_dn(f"uid=mid_cacheuser,{ds_suffix}")
        log_str = multihost.client[0].get_file_contents("/tmp/lookupfile").decode('utf-8')
        for logs in ['lookupfile', 'lookup']:
            client.run_command(f"rm -vfr /tmp/{logs}")
        assert len(log_str.split('\n')) > 2

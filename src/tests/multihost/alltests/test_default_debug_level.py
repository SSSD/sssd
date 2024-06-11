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
from constants import ds_instance_name, ds_suffix, ds_rootpw, ds_rootdn


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.defaultdebuglevel
class TestDefaultDebugLevel(object):
    """ Check sssd default debug level """
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

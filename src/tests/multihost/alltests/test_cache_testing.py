"""Automation for cache performance tests ported from bash

:requirement: SSSD Memory cache Performance
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
import time
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client_bool


@pytest.fixture(scope='class')
def custom_setup(session_multihost, setup_sssd, create_posix_usersgroups):
    """ Added neccessary sssd domain parameters """
    tools = sssdTools(session_multihost.client[0])
    sssd_params = {'services': "nss, pam",
                   'config_file_version': 2}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'use_fully_qualified_names': 'False',
                     'override_homedir': '/home/%u'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()


@pytest.mark.tier2
@pytest.mark.cache_performance
@pytest.mark.usefixtures('custom_setup')
class TestCacheTesting():
    """
    This is test case class for cache_performance testing suite

    Test SSSD Cache existence and presence of updated information
    on the basis of several User and Group Modifications.
    Test for correct cache presence in case of user and group lookups.
    Test for correct cache presence in case of expiration of user and group entries.
    Test for correct cache presence in case of user authentication.
    Test for correct cache presence in case of variety of SSSD Configurations.
    Test for correct cache presence in case of modification & deletion of user entries.
    """
    @staticmethod
    def test_0001_Verify_Timestamp_Cache_Exists(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify the existence Of Timestamp Cache
        :id: d58f6bc7-97bd-459c-9871-f3e0ae6c449e
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute getent to fetch user details.
          2. Check if timestamps cache file exits.
        :expectedresults:
          1. User details should be successfully fetched.
          2. Cache file should be present.
        """
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        client.get_getent_passwd('foo1')
        file = f"/var/lib/sss/db/timestamps_{ds_instance_name}.ldb"
        list_cmd = f"ls -ld {file}"
        cmd = multihost.client[0].run_command(list_cmd, raiseonerr=False)
        assert cmd.returncode == 0, f"Could not find timestamp cache file {file}"

    @staticmethod
    def test_0002_Verify_Cache_on_User_Lookup(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify ldb cache updates on user lookup
        :id: e71e1a88-7521-406c-9630-7201362b0587
        :steps:
          1. Execute the ldbsearch command to get cache db output
          2. Execute the ldbsearch command to get timestamps db output
        :expectedresults:
          1. Command executes and cache file should be present.
          2. Command executes and cache file should be present.
        """
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb'"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'

    @staticmethod
    def test_0003_Expire_User_Entries_and_Verify_Updates(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Expire user entries in cache and verify the updates
        :id: 4a2d7d2a-74cc-4d14-ae4b-d2693f3c5181
        :steps:
          1. Invalidate the existing cache
          2. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Cache sucessfully get invalidated.
          2. dataExpireTimestamp should be present in cache db output.
          3. dataExpireTimestamp should be present in timestamps db output.
        """
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        ldb_cmd1 = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb1"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd1, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb1').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd1} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd1_output, "dataExpireTimestamp not found in /tmp/file_ldb1"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd2_output, "dataExpireTimestamp not found in /tmp/file_ldb2"

    @staticmethod
    def test_0004_Refresh_User_Entries_After_Expiry(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Refresh user entries after expiry and \
            verify the cache updates
        :id: 05e1a77b-bb9d-422b-ba4e-3b34f0752f65
        :steps:
          1. Execute getent to fetch user details.
          2. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. User details should be successfully fetched.
          2. dataExpireTimestamp should be present in cache db output.
          3. dataExpireTimestamp should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        client.get_getent_passwd('foo1')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd_output, "dataExpireTimestamp not found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd2_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0005_Expire_User_Entries_ans_Run_User_Auth(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Expire entries in cache and run user auth
        :id: 70befce4-fde6-4cbd-bf7e-625e19c4dbb7
        :steps:
          1. Invalidate the existing cache
          2. Authenticate the user foo1 from the client
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          4. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Cache sucessfully get invalidated.
          2. User foo1 should be able to successfully login
          3. dataExpireTimestamp should be present in cache db output.
          4. dataExpireTimestamp should not be present in timestamps db output.
        """
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        ssh = check_login_client_bool(multihost, 'foo1', 'Secret123')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert ssh, 'foo1 user is unable to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd1_output, "dataExpireTimestamp not found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd2_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0006_Set_refresh_expired_interval_to_40(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Set refresh expired interval to 40 and \
            verify user record updates
        :id: 329e6aa3-5b97-432b-bd2e-81f6c543e3f5
        :setup:
          1. Set the refresh_expired_interval to 40 in the sssd.conf
        :steps:
          1. Execute getent to fetch user details.
          2. Invalidate the existing cache
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          4. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. User details should be successfully fetched.
          2. Cache sucessfully get invalidated.
          3. dataExpireTimestamp should be present in cache db output.
          4. dataExpireTimestamp should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'entry_cache_timeout': 160,
                         'refresh_expired_interval': 40
                         }
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        client.get_getent_passwd('foo1')

        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        time.sleep(40)
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd1_output, "dataExpireTimestamp not found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd2_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0007_Set_use_fully_qualified_names_to_true(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Set use fully qualified names to true and \
            verify cache updates
        :id: 31946f7a-2f7a-466c-ac87-0e9741bd0c80
        :setup:
          1. Set the use_fully_qualified_names to True in the sssd.conf
        :steps:
          1. Execute getent to fetch user details.
          2. Execute the ldbsearch command to get cache db output
          3. Execute the ldbsearch command to get timestamps db output
        :expectedresults:
          1. User details should be successfully fetched.
          2. Command executes and cache file should be present.
          3. Command executes and cache file should be present.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'use_fully_qualified_names': True}
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        client.get_getent_passwd('foo1@example1')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb'"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'

    @staticmethod
    def test_0008_Set_case_sensitive_to_false(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Set case sensitive to false and verify cache updates
        :id: fd1dc840-3908-4eba-81ec-ae492335b8c6
        :setup:
          1. Set the case_sensitive to False in the sssd.conf
        :steps:
          1. Execute getent to fetch user details.
          2. Execute the ldbsearch command to get cache db output
          3. Execute the ldbsearch command to get timestamps db output
        :expectedresults:
          1. User details should be successfully fetched.
          2. Command executes and cache file should be present.
          3. Command executes and cache file should be present.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'case_sensitive': False}
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        client.get_getent_passwd('FOO1@EXAMPLE1')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb'"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'

    @staticmethod
    def test_0009_Verify_ldb_cache_updates_on_group_lookup(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify ldb cache updates on group lookup
        :id: 8af50374-bc7f-44f2-b381-b8c28f7a2f52
        :steps:
          1. Execute getent to fetch group details.
          2. Execute the ldbsearch command to get cache db output
          3. Execute the ldbsearch command to get timestamps db output
        :expectedresults:
          1. Group details should be successfully fetched.
          2. Command executes and cache file should be present.
          3. Command executes and cache file should be present.
        """
        client = sssdTools(multihost.client[0])
        client.get_getent_group('ldapusers')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' | tee /tmp/output"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb'"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'

    @staticmethod
    def test_0010_Expire_group_record_in_cache(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Expire group record in cache and verify the updates
        :id: 39bc2b36-8950-4d74-84a7-8f701af09456
        :steps:
          1. Invalidate the existing cache
          2. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Cache sucessfully get invalidated.
          2. dataExpireTimestamp should be present in cache db output.
          3. dataExpireTimestamp should be present in timestamps db output.
        """
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        ldb_cmd1 = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb1"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd1, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb1').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd1} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd1_output, "dataExpireTimestamp not found in /tmp/file_ldb1"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd2_output, "dataExpireTimestamp not found in /tmp/file_ldb2"

    @staticmethod
    def test_0011_Refresh_group_record_after_expiry(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Refresh group record after expiry and \
            verify the cache updates
        :id: d1e735df-cd09-43cf-b069-48c244acaece
        :steps:
          1. Execute getent to fetch group details.
          2. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Group details should be successfully fetched.
          2. dataExpireTimestamp should be present in cache db output.
          3. dataExpireTimestamp should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        client.get_getent_group('ldapusers')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd_output, "dataExpireTimestamp not found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd2_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0012_Set_refresh_expired_interval_to_40(multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Set refresh expired interval to 40 and \
            verify Group record updates
        :id: 1905e2ae-3e1a-40e4-8aff-378de9d8f45b
        :setup:
          1. Set the refresh_expired_interval in the sssd.conf
        :steps:
          1. Execute getent to fetch group details.
          2. Invalidate the existing cache
          3. Execute the ldbsearch command and check for dataExpireTimestamp in the cache db output
          4. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Group details should be successfully fetched.
          2. Cache sucessfully get invalidated.
          3. dataExpireTimestamp should be present in cache db output.
          4. dataExpireTimestamp should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        domain_section = f'domain/{ds_instance_name}'
        domain_params = {'entry_cache_timeout': 160,
                         'refresh_expired_interval': 40
                         }
        client.sssd_conf(domain_section, domain_params)
        client.clear_sssd_cache()
        client.get_getent_group('ldapusers')

        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        time.sleep(45)
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=ldapusers@{ds_instance_name},cn=groups,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" in cmd1_output, "dataExpireTimestamp not found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd2_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0013_Modify_User_Attribute(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Modify user attribute and verify cache updates
        :id: ae02729b-8ac9-491f-8a0d-9902ee4948fa
        :steps:
          1. Execute getent to fetch group details.
          2. Invalidate the existing cache
          3. Execute the ldapmodify command to modify user's loginShell details
          4. Execute the ldbsearch command and check for loginShell in the cache db output
          5. Execute the ldbsearch command and check for dataExpireTimestamp in the timestamps db output
        :expectedresults:
          1. Group details should be successfully fetched.
          2. Cache sucessfully get invalidated.
          3. Ldapmodify command executes successfully.
          4. Updated loginShell value should be present in cache db output.
          5. dataExpireTimestamp should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        client.get_getent_passwd('foo1')

        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        user = 'uid=foo1,ou=People,dc=example,dc=test'
        content = f'''dn: {user}\nchangetype: modify\nreplace: loginShell\nloginShell: /bin/sh\n'''
        multihost.client[0].put_file_contents("/tmp/changes.ldif", content)
        ldap_cmd = f'ldapmodify -x -H ldap://{multihost.master[0].sys_hostname}' \
                   f' -D "cn=Directory Manager" -w "Secret123" -f /tmp/changes.ldif'
        cmd2 = multihost.client[0].run_command(ldap_cmd, raiseonerr=False)
        client.get_getent_passwd('foo1')

        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd3 = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd4 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd3_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd4_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldap_cmd} did not execute successfully'
        assert cmd3.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "/bin/sh" in cmd3_output, "Updated loginShell value not found in /tmp/file_ldb"
        assert cmd4.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "dataExpireTimestamp: 1\n" not in cmd4_output, "dataExpireTimestamp found in /tmp/file_ldb2"

    @staticmethod
    def test_0014_Delete_an_existing_user(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Delete an existing user and verify cache updates
        :id: 2c05ee2c-d5d6-4c98-9b1d-e349df5d7780
        :steps:
          1. Execute getent to fetch user details.
          2. Invalidate the existing cache
          3. Execute the ldapdelete command to delete user foo1.
          4. Execute the ldbsearch command and check if user foo1 is present in the cache db output
          5. Execute the ldbsearch command and check if user foo1 is present in the timestamps db output
        :expectedresults:
          1. User details should be successfully fetched.
          2. Cache sucessfully get invalidated.
          3. Ldapdelete command executes successfully.
          4. User foo1 should not be present in cache db output.
          5. User foo1 should not be present in timestamps db output.
        """
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        client.get_getent_passwd('foo1')

        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        ldap_cmd = f'ldapdelete -x -H ldap://{multihost.master[0].sys_hostname} \
                   -D "cn=Directory Manager" -w "Secret123" uid=foo1,ou=People,dc=example,dc=test'

        delete_cmd = multihost.client[0].run_command(ldap_cmd, raiseonerr=False)
        client.get_getent_passwd('foo1')
        ldb_cmd = f"ldbsearch -H /var/lib/sss/db/cache_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb"
        ldb_cmd2 = f"ldbsearch -H /var/lib/sss/db/timestamps_{ds_instance_name}.ldb \
                    -b 'name=foo1@{ds_instance_name},cn=users,cn={ds_instance_name},cn=sysdb' > /tmp/file_ldb2"
        cmd1 = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(ldb_cmd2, raiseonerr=False)
        cmd1_output = multihost.client[0].get_file_contents('/tmp/file_ldb').decode('utf-8')
        cmd2_output = multihost.client[0].get_file_contents('/tmp/file_ldb2').decode('utf-8')
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert delete_cmd.returncode == 0, f'{ldap_cmd} did not execute successfully'
        assert cmd1.returncode == 0, f'{ldb_cmd} did not execute successfully'
        assert "foo1@example1" not in cmd1_output, "User foo1 found in /tmp/file_ldb"
        assert cmd2.returncode == 0, f'{ldb_cmd2} did not execute successfully'
        assert "foo1@example1" not in cmd2_output, "User foo1 found in /tmp/file_ldb2"

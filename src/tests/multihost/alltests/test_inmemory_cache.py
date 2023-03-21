""" Automation of memory cache suite

:requirement: inmemory_cache
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved

"""
import time
import pytest
import subprocess
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str


@pytest.fixture(scope='function')
def common_sssd_setup(multihost):
    """
    This is common sssd setup used in this test suit.
    """
    tools = sssdTools(multihost.client[0])
    tools.sssd_conf("nss", {'debug_level': '9'}, action='update')
    ldap_params = {'use_fully_qualified_names': False}
    tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
    tools.clear_sssd_cache()
    client = multihost.client[0]
    client.run_command("rm -vf /tmp/straceuser*")


def clear_only_domain_log(multihost):
    "This function will clear domain logs"
    client = multihost.client[0]
    log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
    client.run_command(f'> {log_sssd}')


@pytest.mark.tier1_4
@pytest.mark.usefixtures('setup_sssd',
                         'create_posix_usersgroups')
@pytest.mark.sss_cache
class TestPasswordPolicy(object):
    """
    This is test case class for sssd memory cache suite
    """
    @staticmethod
    def test_bz789507(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: SSSD should provide fast in memory cache bz789507
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=789507
        :id: 19dfa7ae-96e9-11ed-adf3-845cf3eff344
        :steps:
            1. For new user foo1 run command getent passwd foo1,
                cache should be stored for this operation.
            2. For new group ldapusers run command getent group ldapusers,
                cache should be stored for this operation.
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        client = multihost.client[0]
        client.run_command("strace -o /tmp/straceuser1 getent passwd foo1")
        log_name = "/tmp/straceuser1"
        log_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        find_logs(multihost, log_name, "/var/lib/sss/pipes/nss")
        find_logs(multihost, log_name, "/var/lib/sss/mc/passwd")
        find_logs(multihost, log_ssd, "Got request for ")
        find_logs(multihost, log_ssd, "uid=foo1")
        clear_only_domain_log(multihost)
        client.run_command("strace -o /tmp/stracegroup1 getent group ldapusers")
        log_name = "/tmp/stracegroup1"
        find_logs(multihost, log_name, "/var/lib/sss/pipes/nss")
        find_logs(multihost, log_name, "/var/lib/sss/mc/group")
        find_logs(multihost, log_ssd, "Got request for ")
        find_logs(multihost, log_ssd, "cn=ldapusers")

    @staticmethod
    def test_maxage(multihost, common_sssd_setup):
        """
        :title: Data is directly pulled from inmemory cache
            without opening the pipe to the NSS responder
        :id: 31217168-96e9-11ed-b69f-845cf3eff344
        :steps:
            1. Clear sssd domain logs
            2. Make sure /var/lib/sss/pipes/nss was not called while cache is there
            3. sssd should not send request to master server while cache is there,
                by checking that new request was not sent to master server.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        client = multihost.client[0]
        file_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        client.run_command("strace -o /tmp/straceuser1 getent passwd foo1")
        client.run_command("strace -o /tmp/stracegroup1 getent group ldapusers")
        clear_only_domain_log(multihost)
        client.run_command("strace -o /tmp/straceuser2 getent passwd foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/straceuser2", "/var/lib/sss/pipes/nss")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd, "Got request for ")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd, "uid=foo1")
        find_logs(multihost, "/tmp/straceuser2", "/var/lib/sss/mc/passwd")
        clear_only_domain_log(multihost)
        client.run_command("strace -o /tmp/stracegroup2 getent group ldapusers")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/stracegroup2", "/var/lib/sss/pipes/nss")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd, "Got request for ")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd, "cn=ldapusers")
        find_logs(multihost, "/tmp/stracegroup2", "/var/lib/sss/mc/group")

    @staticmethod
    def test_invalidate_inmemory_cache(multihost, common_sssd_setup):
        """
        :title: sss cache invalidates the InMemory cache
        :id: 92ee87f8-96eb-11ed-a172-845cf3eff344
        :steps:
            1. Make sure sss cache invalidates the InMemory cache.
                Force invalidation of cached data.
        :expectedresults:
            1. Forcing up-to-date data into SSSD cache.
        """
        clear_only_domain_log(multihost)
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        client = multihost.client[0]
        client.run_command(f"sss_cache -U --domain={ds_instance_name}")
        client.run_command("strace -o /tmp/straceuser3 getent passwd foo1")
        find_logs(multihost, "/tmp/straceuser3", "/var/lib/sss/pipes/nss")
        find_logs(multihost, "/tmp/straceuser3", "/var/lib/sss/mc/passwd")
        find_logs(multihost, log_sssd, "Got request for ")
        find_logs(multihost, log_sssd, "uid=foo1")
        clear_only_domain_log(multihost)
        client.run_command(f"sss_cache -G --domain={ds_instance_name}")
        client.run_command("strace -o /tmp/stracegroup3 getent group ldapusers")
        find_logs(multihost, "/tmp/stracegroup3", "/var/lib/sss/pipes/nss")
        find_logs(multihost, "/tmp/stracegroup3", "/var/lib/sss/mc/group")
        find_logs(multihost, log_sssd, "Got request for ")
        find_logs(multihost, log_sssd, "cn=ldapusers")

    @staticmethod
    def test_bz867933(multihost, common_sssd_setup):
        """
        :title: sss cache invalidates the InMemory cache when sssd is stopped bz867933
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=867933
        :id: 0db6d2e0-96ee-11ed-bbb9-845cf3eff344
        :steps:
            1. Make the API to invalidate the cache public
            2. In the sss_cache tool, carefully detect if the sss_nss process is running
            3. if the sss_nss process is running, proceed with sending the signal
            4. if the sss_nss process is not running, invalidate the memcache.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        """
        client = multihost.client[0]
        log_sssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        client.run_command("service sssd stop")
        client.run_command(f"sss_cache -U --domain={ds_instance_name}")
        client.run_command(f"sss_cache -G --domain={ds_instance_name}")
        client.run_command("service sssd start")
        clear_only_domain_log(multihost)
        client.run_command("getent passwd foo1")
        client.run_command("getent group ldapusers")
        find_logs(multihost, log_sssd, "Got request for ")
        find_logs(multihost, log_sssd, "uid=foo1")
        find_logs(multihost, log_sssd, "cn=ldapusers")

    @staticmethod
    def test_memcache_timeout(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Set value of option memcache timeout to 0 and expire InMemory cache immediately
        :id: 19dfa7ae-96e9-11ed-adf3-845cf3eff344
        :steps:
            1. Set value of option memcache timeout to 0 and expire InMemory cache immediately
            2. Validate the user using sss cache
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'memcache_timeout': '0'}, action='update')
        tools.clear_sssd_cache()
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(2)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(5)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(5)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")

    @staticmethod
    def test_bz1484376(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Add a configuration option to SSSD to disable the memory cache bz1484376
                Set value of option Memcache timeout to 35
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1484376
        :id: b64237b4-96ef-11ed-adb1-845cf3eff344
        :steps:
            1. Add a configuration option to SSSD to disable the memory cache
            2. Set memcache_timeout=0
            3. Set value of option Memcache timeout to 35
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'memcache_timeout': '0'}, action='update')
        tools.clear_sssd_cache()
        client.run_command("rm -rvf /var/lib/sss/mc/*")
        client.run_command("systemctl restart sssd")
        # MC directory is empty, result as expected.
        assert client.run_command("ls -A /var/lib/sss/mc/").stdout_text == ''
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'memcache_timeout': '35'}, action='update')
        tools.clear_sssd_cache()
        clear_only_domain_log(multihost)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        date_start = int(client.run_command('date "+%s"').stdout_text.split()[0])
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(10)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(10)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(10)
        elapsed_second = int(client.run_command('date "+%s"').stdout_text.split()[0]) - date_start
        if elapsed_second < 35:
            client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
            with pytest.raises(AssertionError):
                find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(6)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")

    @staticmethod
    def test_time_out_300(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Set default value of option Memcache timeout to 300
        :id: a0b9ee92-96fd-11ed-bc4e-845cf3eff344
        :steps:
            1. Set default value of option Memcache timeout to 300
            2. Validate the user using sss cache
        :expectedresults:
            1. Should succeed
            2. Should succeed
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'memcache_timeout': ''}, action='delete')
        tools.clear_sssd_cache()
        clear_only_domain_log(multihost)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(100)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(100)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")
        time.sleep(101)
        client.run_command("strace -o /tmp/stracefoo1 getent passwd foo1")
        find_logs(multihost, "/tmp/stracefoo1", "/var/lib/sss/pipes/nss")

    @staticmethod
    def test_default_behaviour(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Verify default behaviour of Cache Initgroups feature
        :id: 975d9060-96fd-11ed-b9f7-845cf3eff344
        :steps:
            1. Set Memcache timeout default
            2. Set Memcache timeout 0 and expire cache immediately
            3. Invalidate the user using sss cache
            4. Invalidate the group using sss cache
            5. Stop sssd service and verify the cache
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
            5. Should succeed
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf("nss", {'memcache_timeout': ''}, action='delete')
        tools.clear_sssd_cache()
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/mc/initgroups")
        time.sleep(10)
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        # Set Memcache timeout 0 and expire cache immediately
        tools.sssd_conf("nss", {'memcache_timeout': '0'}, action='update')
        tools.clear_sssd_cache()
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        time.sleep(3)
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        tools.clear_sssd_cache()
        # Invalidate the user using sss cache
        client.run_command("id foo1")
        client.run_command("sss_cache -u foo1")
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/mc/initgroups")
        # Invalidate the group using sss cache
        tools.clear_sssd_cache()
        client.run_command("id foo1")
        client.run_command(f"sss_cache -G --domain={ds_instance_name}")
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/mc/initgroups")
        # Stop sssd service and verify the cache
        tools.sssd_conf("nss", {'memcache_timeout': ''}, action='delete')
        tools.clear_sssd_cache()
        client.run_command("id foo1")
        client.run_command("service sssd stop")
        client.run_command("strace -o /tmp/tracefile id --groups foo1")
        with pytest.raises(AssertionError):
            find_logs(multihost, "/tmp/tracefile", "/var/lib/sss/pipes/nss")
        client.run_command("sss_cache -u foo1")
        with pytest.raises(subprocess.CalledProcessError):
            client.run_command("id foo1")
        client.run_command("service sssd start")

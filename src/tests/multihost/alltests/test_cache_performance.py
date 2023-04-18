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
from ldif import LDIFWriter
from sssd.testlib.common.utils import sssdTools
from pexpect import pxssh


def generate_users(multihost, count, UID):
    """
    This function is used to create large ldif file for user/group creation in SERVER.
    Function parameters are:
        - COUNT of users to be created
        - Starting UID number of user
    Lets say the count is 100 then the generated script will create an ldif
    file for 100 users & groups with each group having 100 users as members.
    """
    fh = open("/tmp/group.ldif", 'a')
    ldif_writer = LDIFWriter(fh)
    for i in range(1, count):
        user_info = {'cn': [bytes(f'test{count}_foo{i}', encoding='utf-8')],
                     'uid': [bytes(f'test{count}_foo{i}', encoding='utf-8')],
                     'uidNumber': [bytes(f'{UID+i}', encoding='utf-8')],
                     'gidNumber': [bytes(f'{UID+i}', encoding='utf-8')],
                     'objectClass': [b'top', b'posixAccount', b'inetuser'],
                     'homeDirectory': [bytes(f'/home/test{count}_foo{i}', encoding='utf-8')],
                     'userPassword': [b'Secret123'],
                     'loginShell': [b'/bin/bash']}

        dn = f'uid=test{count}_foo{i},ou=People,dc=example,dc=test'
        ldif_writer.unparse(dn, user_info)

    for i in range(1, count):
        memberdn = bytes(f'uid=test{count}_foo1,ou=People,dc=example,dc=test', encoding='utf-8')
        group_info = {'cn': [bytes(f'test{count}_ldapusers{i}', encoding='utf-8')],
                      'gidNumber': [bytes(f'{UID+i}', encoding='utf-8')],
                      'objectClass': [b'top', b'posixGroup', b'groupOfNames'],
                      'member': [memberdn]}

        group_dn = f'cn=test{count}_ldapusers{i},ou=Groups,dc=example,dc=test'
        if i <= 3:
            for j in range(2, count):
                user_dn = bytes(f'uid=test{count}_foo{j},ou=People,dc=example,dc=test', encoding='utf-8')
                group_info['member'].append(user_dn)
        else:
            for j in range(2, 3):
                user_dn = bytes(f'uid=test{count}_foo{j},ou=People,dc=example,dc=test', encoding='utf-8')
                group_info['member'].append(user_dn)

        ldif_writer.unparse(group_dn, group_info)

    multihost.master[0].transport.put_file("/tmp/group.ldif", "/tmp/group.ldif")
    ldap_cmd = f"ldapadd -x -H ldap://{multihost.master[0].sys_hostname} -D 'cn=Directory Manager' -w 'Secret123' \
                -f /tmp/group.ldif"
    cmd1 = multihost.master[0].run_command(ldap_cmd, raiseonerr=False)
    time.sleep(5)
    trun_cmd = "truncate -s 0 /tmp/group.ldif"
    cmd2 = multihost.master[0].run_command(trun_cmd, raiseonerr=False)
    fh.truncate(0)
    fh.close()
    assert cmd1.returncode == 0, f'{ldap_cmd} did not execute successfully'
    assert cmd2.returncode == 0, f'{trun_cmd} did not execute successfully'


def disable_dslimit(multihost):
    """It Disables limits in Directory Server to fetch user / group records."""

    content = 'dn: cn=config\nchangetype: modify\nadd: nsslapd-sizelimit\nnsslapd-sizelimit: -1\n\
\ndn: cn=config,cn=ldbm database,cn=plugins,cn=config\nchangetype: modify\nreplace: nsslapd-lookthroughlimit\n\
nsslapd-lookthroughlimit: -1\n\
\ndn: cn=config,cn=ldbm database,cn=plugins,cn=config\nchangetype: modify\nreplace: nsslapd-idlistscanlimit\n\
nsslapd-idlistscanlimit: -1'
    multihost.client[0].put_file_contents("/root/ds_disable_limit.ldif", content)
    ldap_cmd = f'ldapmodify -x -H ldap://{multihost.master[0].sys_hostname} \
                   -D "cn=Directory Manager" -w "Secret123" -f /root/ds_disable_limit.ldif'
    cmd1 = multihost.client[0].run_command(ldap_cmd, raiseonerr=False)
    dirsrv_cmd = "dsctl example1 restart"
    cmd2 = multihost.master[0].run_command(dirsrv_cmd, raiseonerr=False)
    assert cmd1.returncode == 0, f'{ldap_cmd} did not execute successfully'
    assert cmd2.returncode == 0, f'{dirsrv_cmd} did not execute successfully'


def user_auth(multihost, user):
    ssh = pxssh.pxssh(options={"StrictHostKeyChecking": "no",
                               "UserKnownHostsFile": "/dev/null"})
    ssh.force_password = True
    try:
        ssh.login(multihost.client[0].sys_hostname, user, 'Secret123', sync_multiplier=5,
                  auto_prompt_reset=False, login_timeout=20)
        ssh.sendline('ls -l')
        ssh.prompt(timeout=10)
        ssh.logout()
    except pxssh.ExceptionPxssh:
        pytest.fail(f"Authentication Failed as user {user}")


def cont_user_login(multihost, count, start_uid, end_uid):
    for i in range(start_uid, end_uid):
        user = f'test{count}_foo{i}'
        user_auth(multihost, user)


@pytest.fixture(scope='class')
def custom_setup(session_multihost, setup_sssd):
    """ Added neccessary sssd domain parameters """
    tools = sssdTools(session_multihost.client[0])
    sssd_params = {'services': "nss, pam",
                   'config_file_version': 2}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'use_fully_qualified_names': False,
                     'override_homedir': '/home/%u',
                     'cache_credentials': True,
                     'timeout': 60
                     }
    tools.sssd_conf(domain_section, domain_params)
    tools.sssd_conf("pam", {'timeout': 60})
    tools.sssd_conf("nss", {'timeout': 60})
    tools.clear_sssd_cache()
    disable_dslimit(session_multihost)


@pytest.mark.tier2
@pytest.mark.cache_performance
@pytest.mark.usefixtures('custom_setup')
class TestCachePerformance():
    """
    This is test case class for cache_performance performance suite

    Test for collecting and reporting time statistics of infromation retrieval from SSSD cache.
    Collect time stats in case of User login time for member of 200, 500, 1000, 1500, 2000, 3000 groups.
    Collect time stats in case of ID command time for member of 200, 500, 1000, 1500, 2000, 3000 groups.
    Collect time stats in case of Group lookup time for 200, 500, 1000, 1500, 2000, 3000 users.
    Collect time stats in case of listing files time for 200, 500, 1000, 1500, 2000, 3000 users.
    Collect time stats in case of simultaneous login by 200, 500, 1000, 1500, 2000, 3000 users
    """
    @staticmethod
    def test_0001_User_login_member_of_200_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 200 groups
        :id: 7f8c7de5-e69a-458b-ab68-cc8b91f9e467
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test200_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test200_foo1 from the client
        :expectedresults:
          1. User test200_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test200_foo1 should be able to successfully login
        """
        count = 200
        generate_users(multihost, count, 4000)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0002_User_login_member_of_500_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 500 groups
        :id: ccad38d7-a282-4c49-812d-44065140b6f8
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test500_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test500_foo1 from the client
        :expectedresults:
          1. User test500_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test500_foo1 should be able to successfully login
        """
        count = 500
        generate_users(multihost, count, 5000)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0003_User_login_member_of_1000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 1000 groups
        :id: 81abe4a9-cea5-4d9b-a73a-70ad0a8502f5
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test1000_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test1000_foo1 from the client
        :expectedresults:
          1. User test1000_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test1000_foo1 should be able to successfully login
        """
        count = 1000
        generate_users(multihost, count, 6000)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0004_User_login_member_of_1500_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 1500 groups
        :id: a6192fd9-bf62-411f-9e51-df2c31e198e4
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test1500_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test1500_foo1 from the client
        :expectedresults:
          1. User test1500_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test1500_foo1 should be able to successfully login
        """
        count = 1500
        generate_users(multihost, count, 7400)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0005_User_login_member_of_2000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 2000 groups
        :id: e109b974-9cd3-4003-9fd9-bce0759de52e
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test2000_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test2000_foo1 from the client
        :expectedresults:
          1. User test2000_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test2000_foo1 should be able to successfully login
        """
        count = 2000
        generate_users(multihost, count, 9000)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0006_User_login_member_of_3000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: User login time statistics for member of 3000 groups
        :id: 7fda38be-20cd-4f33-8043-bf5fd6c477ae
        :setup:
          1. Generate the test users with unique UID range
          2. Clear the sssd cache and restart sssd.
        :steps:
          1. Authenticate the user test3000_foo1 from the client
          2. Invalidate the existing cache
          3. Authenticate the user test3000_foo1 from the client
        :expectedresults:
          1. User test3000_foo1 should be able to successfully login
          2. Cache sucessfully get invalidated.
          3. User test3000_foo1 should be able to successfully login
        """
        count = 3000
        generate_users(multihost, count, 12000)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        invalidate_cache = "sss_cache -E"
        cmd = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        ssh2 = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert ssh == 3, 'foo1 not able to login'
        assert cmd.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh2 == 3, 'foo1 not able to login'

    @staticmethod
    def test_0007_ID_cmd_member_of_200_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 200 groups
        :id: 4ba29318-ea4b-4245-9285-58f0cf4f1d9d
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test200_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test200_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 200
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0008_ID_cmd_member_of_500_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 500 groups
        :id: c5335af7-49f7-497b-8203-4488f453d274
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test500_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test500_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0009_ID_cmd_member_of_1000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 1000 groups
        :id: e381006f-5680-47b3-af73-a24007620398
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test1000_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test1000_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 1000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0010_ID_cmd_member_of_1500_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 1500 groups
        :id: d73d695c-89b4-4f63-a535-b10137536168
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test1500_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test1500_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 1500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0011_ID_cmd_member_of_2000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 2000 groups
        :id: 8ee44092-95ee-44f1-a371-8e64badf8255
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test2000_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test2000_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 2000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0012_ID_cmd_member_of_3000_groups(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: ID cmd time statistics for member of 3000 groups
        :id: 59ea0290-fb93-4ceb-95b7-59124a74117c
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the ID command to get details of user test3000_foo2
          2. Invalidate the existing cache
          3. Execute the ID command to get details of user test3000_foo2
        :expectedresults:
          1. ID command should execute successfully
          2. Cache sucessfully get invalidated.
          3. ID command should execute successfully
        """
        count = 3000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = f'id test{count}_foo2'
        cmd1 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        time.sleep(5)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{id_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{id_cmd} did not execute successfully'

    @staticmethod
    def test_0013_Group_lookup_stats_with_200_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 200 users in a group
        :id: 776578ba-1347-43ce-b3e6-23e2d8130e2f
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test200_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test200_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 200
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0014_Group_lookup_stats_with_500_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 500 users in a group
        :id: 06e99415-d7f2-4763-a0f6-dd1383f35c00
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test500_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test500_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0015_Group_lookup_stats_with_1000_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 1000 users in a group
        :id: 6e6575d6-ad90-4fee-a633-79d518c83275
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test1000_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test1000_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 1000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0016_Group_lookup_stats_with_1500_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 1500 users in a group
        :id: 5897d5f2-a762-4742-8679-62748e52af3a
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test1500_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test1500_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 1500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0017_Group_lookup_stats_with_2000_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 2000 users in a group
        :id: f0e3d580-cce6-4668-9400-7cafb1fa130d
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test2000_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test2000_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 2000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0018_Group_lookup_stats_with_3000_users_in_a_group(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Group lookup stats with 3000 users in a group
        :id: 50b817ba-c44d-404d-9baf-aae8ca83074a
        :setup:
          1. Clear the sssd cache and restart sssd.
        :steps:
          1. Execute the getent command to fetch test3000_ldapusers1 group details.
          2. Invalidate the existing cache
          3. Execute the getent command to fetch test3000_ldapusers1 group details.
        :expectedresults:
          1. getent command should execute successfully
          2. Cache sucessfully get invalidated.
          3. getent command should execute successfully
        """
        count = 3000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        grp_lookup__cmd = f'getent group test{count}_ldapusers1'
        cmd1 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)
        START = time.time()
        cmd3 = multihost.client[0].run_command(grp_lookup__cmd, raiseonerr=False)
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{grp_lookup__cmd} did not execute successfully'

    @staticmethod
    def test_0019_Time_Stats_for_list_files_owned_by_200_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 200 users
        :id: 734604bf-ef04-44ef-a982-422296eb4012
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 200 users from the client
        :steps:
          1. Authenticate user test200_foo100 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test200_foo100 to list all files in home directory.
        :expectedresults:
          1. User test200_foo100 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test200_foo100 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 200
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0020_Time_Stats_for_list_files_owned_by_500_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 500 users
        :id: 486c4f6b-7a7a-47d1-b7dc-5cce663f46e2
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 500 users from the client
        :steps:
          1. Authenticate user test500_foo250 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test500_foo250 to list all files in home directory.
        :expectedresults:
          1. User test500_foo250 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test500_foo250 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0021_Time_Stats_for_list_files_owned_by_1000_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 1000 users
        :id: 91a0e19f-351b-41e3-bc4d-9d7e2771a8b1
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 1000 users from the client
        :steps:
          1. Authenticate user test1000_foo500 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test1000_foo500 to list all files in home directory.
        :expectedresults:
          1. User test1000_foo500 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test1000_foo500 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 1000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0022_Time_Stats_for_list_files_owned_by_1500_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 1500 users
        :id: c6d96615-7585-4f56-a680-bb61aa5ebbd0
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 1500 users from the client
        :steps:
          1. Authenticate user test1500_foo750 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test1500_foo750 to list all files in home directory.
        :expectedresults:
          1. User test1500_foo750 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test1500_foo750 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 1500
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0023_Time_Stats_for_list_files_owned_by_2000_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 2000 users
        :id: c4c49abd-9b7c-4f41-b703-360d191270c7
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 2000 users from the client
        :steps:
          1. Authenticate user test2000_foo1000 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test2000_foo1000 to list all files in home directory.
        :expectedresults:
          1. User test2000_foo1000 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test2000_foo1000 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 2000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0024_Time_Stats_for_list_files_owned_by_3000_users(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Time statistics for listing files owned by 3000 users
        :id: c924eb70-accc-4a4d-b7f1-0a973412ead1
        :setup:
          1. Clear the sssd cache and restart sssd.
          2. Authenticate all 3000 users from the client
        :steps:
          1. Authenticate user test3000_foo1500 to list all files in home directory.
          2. Invalidate the existing cache
          3. Authenticate user test3000_foo1500 to list all files in home directory.
        :expectedresults:
          1. User test3000_foo1500 should be able to successfully login & list files.
          2. Cache sucessfully get invalidated.
          3. User test3000_foo1500 should be able to successfully login & list files.
        :teardown:
          1. Remove all user directories from home directory
        """
        count = 3000
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        chmod_cmd = 'chmod -R 777 /home'
        cmd1 = multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        user = f'test{count}_foo{count//2}'
        user_auth(multihost, user)

        invalidate_cache = "sss_cache -E"
        cmd2 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        user_auth(multihost, user)
        END = time.time()

        rm_cmd = 'rm -rf /home/test*'
        cmd3 = multihost.client[0].run_command(rm_cmd, raiseonerr=False)

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{chmod_cmd} did not execute successfully'
        assert cmd2.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert cmd3.returncode == 0, f'{rm_cmd} did not execute successfully'

    @staticmethod
    def test_0025_Verify_user_login_when_100_users_attempt_simultaneous_login(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify user login time when 100 \
            users attempt simultaneous login
        :id: f1a9eda3-0969-401e-a120-82e5fceee9ac
        :setup:
          1. Authenticate all 100 users from the client
        :steps:
          1. Authenticate users among different range to simulate simultaneous login
          2. Invalidate the existing cache
          3. Authenticate user test200_foo1 from the client.
        :expectedresults:
          1. Users should be able to successfully login.
          2. Cache sucessfully get invalidated.
          3. User test200_foo1 should be able to successfully login.
        """
        count = 200
        client = sssdTools(multihost.client[0])
        for i in range(1, 100):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        cont_user_login(multihost, count, 20, 60)
        time.sleep(10)

        cont_user_login(multihost, count, 2, 30)
        time.sleep(10)

        cont_user_login(multihost, count, 50, 80)
        time.sleep(10)

        cont_user_login(multihost, count, 70, 100)
        time.sleep(10)

        invalidate_cache = "sss_cache -E"
        cmd1 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh == 3, f'test{count}_foo1 not able to login'

    @staticmethod
    def test_0026_Verify_user_login_when_200_users_attempt_simultaneous_login(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify user login time when 200 \
            users attempt simultaneous login
        :id: 73b30ff5-5009-4a2f-9215-1afc60bc1690
        :setup:
          1. Authenticate all 200 users from the client
        :steps:
          1. Authenticate users among different range to simulate simultaneous login
          2. Invalidate the existing cache
          3. Authenticate user test200_foo1 from the client.
        :expectedresults:
          1. Users should be able to successfully login.
          2. Cache sucessfully get invalidated.
          3. User test200_foo1 should be able to successfully login.
        """
        count = 200
        client = sssdTools(multihost.client[0])
        for i in range(101, 200):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        cont_user_login(multihost, count, 120, 170)
        time.sleep(10)

        cont_user_login(multihost, count, 2, 60)
        time.sleep(10)

        cont_user_login(multihost, count, 50, 100)
        time.sleep(10)

        cont_user_login(multihost, count, 150, 200)
        time.sleep(10)

        cont_user_login(multihost, count, 90, 140)
        time.sleep(10)

        invalidate_cache = "sss_cache -E"
        cmd1 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh == 3, f'test{count}_foo1 not able to login'

    @staticmethod
    def test_0027_Verify_user_login_when_500_users_attempt_simultaneous_login(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify user login time when 500 \
            users attempt simultaneous login
        :id: b07f6e85-e5ce-4106-bec6-379dae8eb41c
        :setup:
          1. Authenticate all 500 users from the client
        :steps:
          1. Authenticate users among different range to simulate simultaneous login
          2. Invalidate the existing cache
          3. Authenticate user test500_foo1 from the client.
        :expectedresults:
          1. Users should be able to successfully login.
          2. Cache sucessfully get invalidated.
          3. User test500_foo1 should be able to successfully login.
        """
        count = 500
        client = sssdTools(multihost.client[0])
        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        cont_user_login(multihost, count, 2, 120)
        time.sleep(10)

        cont_user_login(multihost, count, 100, 225)
        time.sleep(10)

        cont_user_login(multihost, count, 180, 300)
        time.sleep(10)

        cont_user_login(multihost, count, 275, 410)
        time.sleep(10)

        cont_user_login(multihost, count, 375, 500)
        time.sleep(10)

        invalidate_cache = "sss_cache -E"
        cmd1 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time_ns()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time_ns()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh == 3, f'test{count}_foo1 not able to login'

    @staticmethod
    def test_0028_Verify_user_login_when_1000_users_attempt_simultaneous_login(multihost):
        """
        :title: IDM-SSSD-TC: ldap_provider: cache_performance: Verify user login time when 1000 \
            users attempt simultaneous login
        :id: 4d8fd316-f9be-4e84-bbf9-9927f8f41600
        :setup:
          1. Authenticate all 1000 users from the client
        :steps:
          1. Authenticate users among different range to simulate simultaneous login
          2. Invalidate the existing cache
          3. Authenticate user test1000_foo1 from the client.
        :expectedresults:
          1. Users should be able to successfully login.
          2. Cache sucessfully get invalidated.
          3. User test1000_foo1 should be able to successfully login.
        """
        count = 1000
        client = sssdTools(multihost.client[0])
        for i in range(1, count):
            user = f'test{count}_foo{i}'
            user_auth(multihost, user)

        cont_user_login(multihost, count, 2, 220)
        time.sleep(10)

        cont_user_login(multihost, count, 200, 375)
        time.sleep(10)

        cont_user_login(multihost, count, 325, 550)
        time.sleep(10)

        cont_user_login(multihost, count, 500, 750)
        time.sleep(10)

        cont_user_login(multihost, count, 725, 900)
        time.sleep(10)

        cont_user_login(multihost, count, 800, 1000)
        time.sleep(10)

        invalidate_cache = "sss_cache -E"
        cmd1 = multihost.client[0].run_command(invalidate_cache, raiseonerr=False)

        START = time.time_ns()
        ssh = client.auth_from_client(f'test{count}_foo1', 'Secret123')
        END = time.time_ns()

        DATA = END - START
        DATA_MIN = DATA / 60
        DATA_SEC = DATA - (60 * DATA_MIN)
        print(DATA_MIN, ":", DATA_SEC)
        assert cmd1.returncode == 0, f'{invalidate_cache} did not execute successfully'
        assert ssh == 3, f'test{count}_foo1 not able to login'

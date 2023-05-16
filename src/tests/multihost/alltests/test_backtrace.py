"""Automation poor man's backtrace

:requirement: Poor Man's Backtrace
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
:bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1949149
"""

from __future__ import print_function
import re
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from constants import ds_instance_name


def bad_url(multihost):
    tools = sssdTools(multihost.client[0])
    hostname = multihost.master[0].sys_hostname
    section = f"domain/{ds_instance_name}"
    bad_ldap_uri = f"ldaps://typo.{hostname}"
    domain_params = {'ldap_uri': bad_ldap_uri}
    tools.sssd_conf(section, domain_params)


def no_fallback_dir(multihost):
    tools = sssdTools(multihost.client[0])
    section = f"domain/{ds_instance_name}"
    domain_params = {'fallback_homedir': ''}
    tools.sssd_conf(section, domain_params, action='delete')
    tools.clear_sssd_cache()
    user = f'foo1@{ds_instance_name}'
    # Authenticate user
    client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                         'Secret123', debug=False)
    client.login(login_timeout=30, sync_multiplier=5,
                 auto_prompt_reset=False)


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.backtrace
@pytest.mark.tier1_2
class TestPoorManBacktrace(object):
    """ Check sssd backtrace feature """
    def test_0001_bz2021196(self, multihost, backupsssdconf):
        """
        :title: avoid duplicate backtraces
        :id: d4d8a0a0-ab90-4c8f-8087-95dc7ad3f3ae
        :customerscenario: true
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=2021196
          https://bugzilla.redhat.com/show_bug.cgi?id=2021499
        :steps:
          1. Modify sssd.conf with a typo in the ldap_uri
          2. Remove debug_level from domain section
          3. Start sssd
          4. Truncate domain logs
          5. Lookup any user
          6. Check logs generate a backtrace
          7. Lookup same user again
          8. Check logs dont have repeated backtrace
        :expectedresults:
          1. Bad url successfully added in sssd.conf
          2. debug_level not set in sssd.conf
          3. Should succeed
          4. Should succeed
          5. Should fail as expected
          6. Should succeed
          7. Should fail as expected
          8. Should have string 'skipping repetitive backtrace'
        """
        bad_url(multihost)
        tools = sssdTools(multihost.client[0])
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        logfile = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        log_str = multihost.client[0].get_file_contents(logfile). \
            decode('utf-8')
        print(f'\n{logfile}\n+===++++++===+\n{log_str}\n')
        time.sleep(2)
        # Truncate logs to generate fresh backtrace on user lookup and compare
        # with the logs generated with the second lookup for same error
        multihost.client[0].run_command('sssctl logs-remove')
        cmd = f'getent passwd fakeuser@{ds_instance_name}'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        time.sleep(2)
        msg = 'BACKTRACE DUMP ENDS HERE'
        msg2 = '... skipping repetitive backtrace ...'
        pattern = re.compile(fr'{msg}')
        pattern2 = re.compile(fr'{msg2}')
        log_str1 = multihost.client[0].get_file_contents(logfile). \
            decode('utf-8')
        print(f'\n{logfile}\n+===++++++===+\n{log_str1}\n')
        multihost.client[0].run_command('sssctl logs-remove')
        multihost.client[0].run_command(cmd, raiseonerr=False)
        time.sleep(2)
        log_str2 = multihost.client[0].get_file_contents(logfile). \
            decode('utf-8')
        print(f'\n{logfile}\n+===++++++===+\n{log_str2}\n')
        # Check the backtrace is dumped first time and no backtrace is skipped
        assert len(pattern.findall(log_str1)) == len(pattern2.findall(log_str1)) == 1
        # Check there is no new backtrace with the same issue and repeative
        # backtrace is skipped
        assert pattern2.search(log_str2) and not pattern.search(log_str2)

    def test_0002_bz1949149(self, multihost, backupsssdconf):
        """
        :title: backtrace is disabled if debug level >= 9
        :id: 50f2d501-3296-4229-86a0-b81844381637
        :steps:
          1. Set debug_level to 9 in all sections of sssd.conf
          2. Dont set fallback_homedir
          3. Start sssd
          4. Login as user
          5. Set bad url for ldap_uri
          6. Restart sssd
          7. Check logs
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Login succeeds
          5. Should succeed
          6. Should succeed
          7. Logs should not have string 'BACKTRACE'
        """
        section = f"domain/{ds_instance_name}"
        param = {'debug_level': '9'}
        serv_list = ['sssd', section, 'nss', 'pam']
        tools = sssdTools(multihost.client[0])
        for serv in serv_list:
            tools.sssd_conf(serv, param)
        no_fallback_dir(multihost)
        bad_url(multihost)
        tools.service_ctrl('restart', 'sssd')
        cmd = f'getent passwd fakeuser@{ds_instance_name}'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        log_list = ['sssd', f'sssd_{ds_instance_name}',
                    'sssd_nss', 'sssd_pam']
        for logfilename in log_list:
            log = f'/var/log/sssd/{logfilename}.log'
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'BACKTRACE DUMP ENDS HERE')
            assert not find.search(log_str)

    def test_0003_bz1949149(self, multihost, backupsssdconf):
        """
        :title: set debug_backtrace_enabled false
        :id: b8084e03-5e21-45ee-a463-65ab537fa110
        :steps:
          1. Set debug_backtrace_enabled to false in sssd.conf
          2. Start sssd
          3. Login as user
          4. Set bad url for ldap_uri
          5. Restart sssd
          6. Lookup any user
          7. Check logs
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Login succeeds
          4. Should succeed
          5. Should succeed
          6. Should fail as expected
          7. Logs dont have backtrace
        """
        section = f"domain/{ds_instance_name}"
        param = {'debug_backtrace_enabled': 'false'}
        serv_list = ['sssd', section, 'nss', 'pam']
        tools = sssdTools(multihost.client[0])
        for serv in serv_list:
            tools.sssd_conf(serv, param)
        no_fallback_dir(multihost)
        bad_url(multihost)
        tools.service_ctrl('restart', 'sssd')
        cmd = f'getent passwd fakeuser@{ds_instance_name}'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        log_list = ['sssd', 'sssd_example1', 'sssd_nss', 'sssd_pam']
        for logfilename in log_list:
            log = f'/var/log/sssd/{logfilename}.log'
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'BACKTRACE DUMP ENDS HERE')
            assert not find.search(log_str)

    def test_0004_bz1949149(self, multihost, backupsssdconf):
        """
        :title: backtrace level is 0 with debug level set to 0
        :id: 4376d596-a613-447c-8f85-e3f3fbc05728
        :steps:
          1. Set debug_level to 0
          2. Remove fallback dir from sssd.conf
          3. Login as a user
          4. Add bad url to ldap_uri in sssd.conf
          5. Restart sssd
          6. Lookup any user
          7. Check logs has backtraces for step 3 and 6
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Backtrace generated only for level 0 logs
        """
        section = f"domain/{ds_instance_name}"
        param = {'debug_level': '0'}
        serv_list = ['sssd', section, 'nss', 'pam']
        tools = sssdTools(multihost.client[0])
        for serv in serv_list:
            tools.sssd_conf(serv, param)
        no_fallback_dir(multihost)
        bad_url(multihost)
        tools.service_ctrl('restart', 'sssd')
        log_list = ['sssd', f'sssd_{ds_instance_name}', 'sssd_nss', 'sssd_pam']
        find1 = re.compile(r'BACKTRACE DUMP ENDS HERE')
        find2 = re.compile(r'.0x0010.')
        for logfilename in log_list:
            log = f'/var/log/sssd/{logfilename}.log'
            log_str = multihost.client[0].get_file_contents(log). \
                decode('utf-8')
            log_lines = log_str.splitlines()
            # Check only error of level 0x0010 generates backtrace
            for index, line in enumerate(log_lines):
                if find1.search(line):
                    log_level = log_lines[index - 1]
                    assert find2.search(log_level)

    def test_0005_bz1949149(self, multihost, backupsssdconf):
        """
        :title: backtrace level is 1 with debug level set to 1
        :id: 8a8adcdd-63bc-4a64-83cd-5c7b76fe745a
        :steps:
          1. Set debug_level to 1
          2. Remove fallback dir from sssd.conf
          3. Login as a user
          4. Add bad url to ldap_uri in sssd.conf
          5. Restart sssd
          6. Lookup any user
          7. Check logs has backtraces for step 3 and 6
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Backtrace is generated only for level 0 and level 1 logs
        """
        section = "domain/{ds_instance_name}"
        param = {'debug_level': '1'}
        serv_list = ['sssd', section, 'nss', 'pam']
        tools = sssdTools(multihost.client[0])
        for serv in serv_list:
            tools.sssd_conf(serv, param)
        no_fallback_dir(multihost)
        bad_url(multihost)
        tools.service_ctrl('restart', 'sssd')
        log_list = ['sssd', f'sssd_{ds_instance_name}', 'sssd_nss', 'sssd_pam']
        find1 = re.compile(r'BACKTRACE DUMP ENDS HERE')
        find2 = re.compile(r'.0x0010.')
        find3 = re.compile(r'.0x0020.')
        for logfilename in log_list:
            log = f'/var/log/sssd/{logfilename}.log'
            log_str = multihost.client[0].get_file_contents(log). \
                decode('utf-8')
            log_lines = log_str.splitlines()
            # Check only error of level 0x0010 and 0x0020 generates backtrace
            for index, line in enumerate(log_lines):
                if find1.search(line):
                    log_level = log_lines[index - 1]
                    assert find2.search(log_level) or find3.search(log_level)

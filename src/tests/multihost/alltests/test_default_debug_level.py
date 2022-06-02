"""Automation for default debug level

:requirement: SSSD - Default debug level
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

from __future__ import print_function
import re
import time
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.defaultdebuglevel
@pytest.mark.tier1_2
class TestDefaultDebugLevel(object):
    """ Check sssd default debug level """
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
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5,
                     auto_prompt_reset=False)
        alog_size = multihost.client[0].run_command(check_log_size,
                                                    raiseonerr=False)
        print("after auth:", alog_size.stdout_text)
        assert alog_size.stdout_text == blog_size.stdout_text

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

    def test_0004_bz1893159(self, multihost, backupsssdconf):
        """
        :title: default debug logs: Check default level 2
        :id: d44d5883-fc52-418d-b407-3ac63f7104d8
        :steps:
          1. Remove debug_level from sssd.conf
          2. Start sssd after clearing cache and logs
          3. Kill pid of sssd with signal SIGUSR2
          4. Check logs
        :expectedresults:
          1. sssd should use default debug level with no level defined
          2. Succeeds
          3. sssd process is killed
          4. logs of level of 0x0040 are in the log file
        """
        section = f"domain/{ds_instance_name}"
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        cmd_kill = 'kill -SIGUSR2 $(pidof sssd)'
        multihost.client[0].run_command(cmd_kill, raiseonerr=False)
        logfilename = 'sssd'
        log = f'/var/log/sssd/{logfilename}.log'
        log_str = multihost.client[0].get_file_contents(log).decode('utf-8')
        find = re.compile(r'.0x0040.')
        assert find.search(log_str)

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

from __future__ import print_function
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.defaultdebuglevel
class TestDefaultDebugLevel(object):
    """ Check sssd default debug level """
    @pytest.mark.tier1_2
    def test_0001_check_default_debug_level(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check default debug level when sssd start
        successfully
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        # stop sssd, delete sssd logs and cache, start sssd
        tools.clear_sssd_cache()
        log_list = ['sssd', 'sssd_example1', 'sssd_nss',
                    'sssd_pam', 'sssd_implicit_files']
        for log_filename in log_list:
            log = '/var/log/sssd/%s.log' % log_filename
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            log_split = log_str.split("\n")
            for index in range(len(log_split)-1):
                log_single_line = log_split[index]
                pattern = re.compile(r'\] \(0x\d*\): ')
                debug_str = pattern.search(log_single_line).group()
                # get debug_level in hex from log
                value = debug_str[3:-3]
                int_debug_level = int(value, 16)
                # int('0x0040', 16) is 64
                if int_debug_level > 64:
                    assert False

    @pytest.mark.tier1_2
    def test_0002_check_default_level_with_auth(self, multihost,
                                                backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check default debug level by checking sssd
        log size before and after authetication of user is same
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        # stop sssd, delete logs and cache, start sssd
        tools.clear_sssd_cache()
        check_log_size = 'ls -ash /var/log/sssd/'
        blog_size = multihost.client[0].run_command(check_log_size,
                                                    raiseonerr=False)
        split_string = blog_size.stdout_text.split("\n", 1)
        before_auth = int(re.search(r'\d+', split_string[0]).group())
        user = 'foo1@%s' % ds_instance_name
        # Authenticate user
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5,
                     auto_prompt_reset=False)
        alog_size = multihost.client[0].run_command(check_log_size,
                                                    raiseonerr=False)
        split_string = alog_size.stdout_text.split("\n", 1)
        after_auth = int(re.search(r'\d+', split_string[0]).group())
        if before_auth == after_auth:
            assert True

    @pytest.mark.tier1_2
    def test_0003_bz1893159(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check default level as 0 and 1
        """
        section = "domain/%s" % ds_instance_name
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
        if not find1.search(log_str) and find2.search(log_str):
            assert False

    @pytest.mark.tier1_2
    def test_0004_bz1893159(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check default level 2
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        cmd_kill = 'kill -SIGUSR2 $(pidof sssd)'
        multihost.client[0].run_command(cmd_kill, raiseonerr=False)
        log_list = ['sssd', 'sssd_example1', 'sssd_nss', 'sssd_pam',
                    'sssd_implicit_files']
        for logfilename in log_list:
            log = '/var/log/sssd/%s.log' % logfilename
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'.0x0040.')
            if not find.search(log_str):
                assert False

    @pytest.mark.tier1_2
    def test_0005_bz1915319(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check SBUS code should not trigger failure
        message during modules startup
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        log_list = ['sssd', 'sssd_example1', 'sssd_nss', 'sssd_pam',
                    'sssd_implicit_files']
        for log in log_list:
            log = '/var/log/sssd/%s.log' % log
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'Unable to remove key.*')
            if not find.search(log_str):
                assert True

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
    @pytest.mark.tier1
    def test_0001_check_default_debug_level(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check default debug level by authenticating the
        user
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        user = 'foo1@%s' % ds_instance_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5,
                     auto_prompt_reset=False)
        log_list = ['sssd.log', 'sssd_example1.log', 'sssd_nss.log',
                    'sssd_pam.log', 'sssd_implicit_files.log']
        for log in log_list:
            log = '/var/log/sssd/%s' % log
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find1 = re.compile(r'0x0020')
            find2 = re.compile(r'0x0010')
            find3 = re.compile(r'0x0040')
            find4 = re.compile(r'Starting with debug level = 0x0070')
            if not (find1.search(log_str) or find2.search(log_str) or
                    find3.search(log_str)) and find4.search(log_str):
                status = 'FAIL'
            else:
                status = 'PASS'
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0002_bz1893159(self, multihost, backupsssdconf):
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
        if cmd.returncode == 1:
            status = 'PASS'
        tools.remove_sss_cache('/var/log/sssd')
        multihost.client[0].run_command('systemctl start sssd',
                                        raiseonerr=False)
        slog = '/var/log/sssd/sssd.log'
        log_str = multihost.client[0].get_file_contents(slog).decode('utf-8')
        find1 = re.compile(r'0x0020')
        find2 = re.compile(r'0x0010')
        if not find1.search(log_str) and find2.search(log_str):
            status = 'FAIL'
        else:
            status = 'PASS'
        restore_sssd = 'chmod 600 /etc/sssd/sssd.conf'
        multihost.client[0].run_command(restore_sssd, raiseonerr=False)
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0003_bz1893159(self, multihost, backupsssdconf):
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
        log_list = ['sssd.log', 'sssd_example1.log', 'sssd_nss.log',
                    'sssd_pam.log', 'sssd_implicit_files.log']
        for log in log_list:
            log = '/var/log/sssd/%s' % log
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'.0x0040.')
            if not find.search(log_str):
                status = 'FAIL'
            else:
                status = 'PASS'
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_0004_bz1915319(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Check SBUS code triggers failure message during
        modules startup
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'debug_level': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        tools.clear_sssd_cache()
        log_list = ['sssd.log', 'sssd_example1.log', 'sssd_nss.log',
                    'sssd_pam.log', 'sssd_implicit_files.log']
        for log in log_list:
            log = '/var/log/sssd/%s' % log
            log_str = multihost.client[0].get_file_contents(log).decode(
                'utf-8')
            find = re.compile(r'Unable to remove key.*')
            if not find.search(log_str):
                status = 'PASS'
            else:
                status = 'FAIL'
        assert status == 'PASS'

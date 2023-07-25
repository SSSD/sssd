"""Automation tests for sudo

:requirement: sudo
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import re
import pytest
from sssd.testlib.common.ssh2_python import SSHClient
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name, ds_suffix


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_sss_sudo_nsswitch')
@pytest.mark.sudo
class TestSudo(object):
    """ Sudo test suite """

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__local_users_negative_cache')
    @pytest.mark.usefixtures('backupsssdconf')
    @pytest.mark.tier1_2
    def test_bz1294670(multihost, localusers):
        """
        :title: sudo: Local users with local sudo rules causes LDAP queries
        :id: e8c5c396-e5e5-4eff-84f8-feff01defda1
        """
        # enable sudo with authselect
        authselect_cmd = 'authselect select sssd with-sudo'
        multihost.client[0].run_command(authselect_cmd)

        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db/')
        ldap_uri = 'ldap://%s' % multihost.master[0].sys_hostname
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf('sssd', sssd_params)
        ldap_params = {'ldap_uri': ldap_uri}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        multihost.client[0].service_sssd('restart')
        sudo_pcapfile = '/tmp/bz1294670.pcap'
        ldap_host = multihost.master[0].sys_hostname
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ldap_host, sudo_pcapfile)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        for user in localusers.keys():
            add_rule1 = "echo '%s  ALL=(ALL) NOPASSWD:ALL,!/bin/sh'"\
                        " >> /etc/sudoers.d/%s" % (user, user)
            multihost.client[0].run_command(add_rule1)
            add_rule2 = "echo 'Defaults:%s !requiretty'"\
                        " >> /etc/sudoers.d/%s" % (user, user)
            multihost.client[0].run_command(add_rule2)
            ssh = SSHClient(multihost.client[0].sys_hostname, user, 'Secret123')
            try:
                ssh.connect()
                for _ in range(1, 10):
                    ssh.execute_command('sudo fdisk -l')
                    ssh.execute_command('sudo ls -l /usr/sbin/')
                ssh.close()
            except Exception:
                pytest.fail(f"Authentication Failed as user {user}")
        pkill = 'pkill tcpdump'
        multihost.client[0].run_command(pkill)
        for user in localusers.keys():
            rm_sudo_rule = "rm -f /etc/sudoers.d/%s" % (user)
            multihost.client[0].run_command(rm_sudo_rule)
        tshark_cmd = 'tshark -r %s -R ldap.filter -V -2' % sudo_pcapfile
        cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
        print("output = ", cmd.stderr_text)
        assert cmd.returncode == 0
        rm_pcap_file = 'rm -f %s' % sudo_pcapfile
        multihost.client[0].run_command(rm_pcap_file)

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__sudonotbefore_shorttime')
    @pytest.mark.usefixtures('backupsssdconf')
    @pytest.mark.tier2
    def test_timed_sudoers_entry(multihost, timed_sudoers):
        """
        :title: sudo: sssd accepts timed entries without minutes and or
         seconds to attribute
        :id: 5103a796-6c7f-4af0-b7b8-64c7338f0934
        """
        # pylint: disable=unused-argument
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db/')
        sudo_base = 'ou=sudoers,dc=example,dc=test'
        sudo_uri = "ldap://%s" % multihost.master[0].sys_hostname
        params = {'ldap_sudo_search_base': sudo_base,
                  'ldap_uri': sudo_uri, 'sudo_provider': "ldap"}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, params, action='update')
        section = "sssd"
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf(section, sssd_params, action='update')
        multihost.client[0].service_sssd('start')
        ssh = SSHClient(multihost.client[0].sys_hostname, 'foo1@example.test', 'Secret123')
        try:
            ssh.connect()
            id_out = ssh.execute_command('id')
            sudo_out = ssh.execute_command('sudo -l')
            ssh.close()
        except Exception:
            pytest.fail("Failed to login via ssh.")
        assert 'foo1' in id_out, "id command did not work."
        assert 'NOTBEFORE=' in sudo_out or 'NOTAFTER=' in sudo_out,\
            "Expected sudo rule not found!"
        # Make sure that the rule validity time works without minutes
        # and seconds 0000Z is at the end of the NOTAFTER part of rule
        rule_time = re.search(
            r"(NOTBEFORE|NOTAFTER)=[0-9]{10}0000Z NOPASSWD: /usr/bin/head",
            sudo_out)
        if not rule_time:
            journalctl_cmd = 'journalctl -x -n 100 --no-pager'
            multihost.master[0].run_command(journalctl_cmd)
            pytest.fail("sudo -l cmd failed for user foo1")

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__refresh_random_offset')
    @pytest.mark.usefixtures('backupsssdconf', 'sudo_rule')
    @pytest.mark.tier2
    def test_randomize_sudo_timeout(multihost):
        """
        :title: sudo: randomize sudo refresh timeouts
        :id: 57720975-29ba-4ed7-868a-f9b784bbfed2
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1925514
        :customerscenario: True
        :steps:
          1. Edit sssdconfig and specify sssd smart, full timeout option
          2. Restart sssd with cleared logs and cache
          3. Wait for 120 seconds
          4. Parse logs and confirm sudo refresh timeouts are random
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        sudo_base = 'ou=sudoers,%s' % (ds_suffix)
        sudo_uri = "ldap://%s" % multihost.master[0].sys_hostname
        params = {'ldap_sudo_search_base': sudo_base,
                  'ldap_uri': sudo_uri,
                  'sudo_provider': "ldap",
                  'ldap_sudo_full_refresh_interval': '25',
                  'ldap_sudo_smart_refresh_interval': '15',
                  'ldap_sudo_random_offset': '5'}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, params, action='update')
        section = "sssd"
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf(section, sssd_params, action='update')
        multihost.client[0].service_sssd('start')
        time.sleep(120)
        logfile = '/var/log/sssd/sssd_%s.log' % ds_instance_name
        tmout_ptrn = r"(SUDO.*\:\sscheduling task \d+ seconds)"
        regex_tmout = re.compile("%s" % tmout_ptrn)
        smart_tmout = []
        full_tmout = []
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        for line in log.split('\n'):
            if line:
                if regex_tmout.findall(line):
                    rfrsh_type = regex_tmout.findall(line)[0].split()[1]
                    timeout = regex_tmout.findall(line)[0].split()[5]
                    if rfrsh_type == 'Smart':
                        smart_tmout.append(timeout)
                    elif rfrsh_type == 'Full':
                        full_tmout.append(timeout)
        rand_intvl, same_intvl = 0, 0
        for timeout in smart_tmout, full_tmout:
            index = 1
            rand_intvl, same_intvl = 0, 0
            while index < len(timeout):
                if timeout[index] != timeout[index - 1]:
                    rand_intvl += 1
                else:
                    same_intvl += 1
                index += 1
            assert rand_intvl > same_intvl

    @staticmethod
    @pytest.mark.converted('test_sudo.py', 'test_sudo__prefer_full_refresh_over_smart_refresh')
    @pytest.mark.usefixtures('backupsssdconf', 'sudo_rule', 'sssd_sudo_conf')
    @pytest.mark.tier2
    def test_improve_refresh_timers_sudo_timeout(multihost):
        """
        :title: sudo: improve sudo full and smart refresh timeouts
        :id: 3860d1b9-28fc-4d44-9537-caf28ab033c8
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1925505
        :customerscenario: True
        :steps:
          1. Edit sssdconfig and specify sssd smart, full timeout option
          2. Restart sssd with cleared logs and cache
          3. Wait for 40 seconds
          4. Parse logs and confirm sudo full refresh and smart refresh
             timeout are not running at same time
          5. If sudo full refresh and smart refresh timer are scheduled at
             same time then smart refresh is rescheduled to the next cycle
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        params = {'ldap_sudo_full_refresh_interval': '10',
                  'ldap_sudo_random_offset': '0',
                  'ldap_sudo_smart_refresh_interval': '5'}
        domain_section = f'domain/{ds_instance_name}'
        tools.sssd_conf(domain_section, params, action='update')
        multihost.client[0].service_sssd('start')
        time.sleep(40)
        logfile = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        tmout_ptrn = '(SUDO.*Refresh.*executing)'
        rschdl_ptrn = '(SUDO.*Refresh.*rescheduling)'
        regex_tmout = re.compile(f'{tmout_ptrn}')
        rgx_rs_tstmp = re.compile(f'{rschdl_ptrn}')
        full_rfsh_tstmp = []
        smrt_rfsh_tstmp = []
        rschdl_tstmp = []
        log = multihost.client[0].get_file_contents(logfile).decode('utf-8')
        for line in log.split('\n'):
            if regex_tmout.findall(line):
                dt_time = line.split('):')[0]
                tstmp = dt_time.split()[1]
                ref_type = line.split()[7]
                if ref_type == 'Smart':
                    smrt_rfsh_tstmp.append(tstmp)
                elif ref_type == 'Full':
                    full_rfsh_tstmp.append(tstmp)
            if rgx_rs_tstmp.findall(line):
                dt_time = line.split('):')[0]
                tstmp = dt_time.split()[1]
                rschdl_tstmp.append(tstmp)
        for tm_stamp in full_rfsh_tstmp:
            if tm_stamp in smrt_rfsh_tstmp:
                assert tm_stamp in rschdl_tstmp
            else:
                assert tm_stamp not in smrt_rfsh_tstmp

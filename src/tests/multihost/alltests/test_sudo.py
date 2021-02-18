"""Automation tests for sudo

:requirement: sudo
:casecomponent: sssd
:subsystemteam: sst_identity_management
:upstream: yes
"""
import time
import re
import pytest
import paramiko
from sssd.testlib.common.utils import SSHClient
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_sss_sudo_nsswitch')
@pytest.mark.sudo
class TestSudo(object):
    """ Sudo test suite """

    @pytest.mark.tier1_2
    def test_bz1294670(self, multihost, backupsssdconf, localusers):
        """
        :title: sudo: Local users with local sudo rules causes LDAP queries
        :id: e8c5c396-e5e5-4eff-84f8-feff01defda1
        """
        # enable sudo with authselect
        authselect_cmd = 'authselect select sssd with-sudo'

        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        tools = sssdTools(multihost.client[0])
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
            try:
                ssh = SSHClient(multihost.client[0].sys_hostname,
                                username=user, password='Secret123')
            except paramiko.ssh_exception.AuthenticationException:
                pytest.fail("Authentication Failed as user %s" % (localuser))
            else:
                for count in range(1, 10):
                    sudo_cmd = 'sudo fdisk -l'
                    (_, _, _) = ssh.execute_cmd(args=sudo_cmd)
                    sudo_cmd = 'sudo ls -l /usr/sbin/'
                    (_, _, _) = ssh.execute_cmd(args=sudo_cmd)
            ssh.close()
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

    @pytest.mark.tier2
    def test_timed_sudoers_entry(self,
                                 multihost, backupsssdconf, timed_sudoers):
        """
        :title: sudo: sssd accepts timed entries without minutes and or
         seconds to attribute
        :id: 5103a796-6c7f-4af0-b7b8-64c7338f0934
        """
        # pylint: disable=unused-argument
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        sudo_base = 'ou=sudoers,dc=example,dc=test'
        sudo_uri = "ldap://%s" % multihost.master[0].sys_hostname
        params = {'ldap_sudo_search_base': sudo_base,
                  'ldap_uri': sudo_uri, 'sudo_provider': "ldap"}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, params, action='update')
        section = "sssd"
        sssd_params = {'services': 'nss, pam, sudo'}
        tools.sssd_conf(section, sssd_params, action='update')
        start = multihost.client[0].service_sssd('start')
        try:
            ssh = SSHClient(multihost.client[0].sys_hostname,
                            username='foo1@example.test', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("%s failed to login" % 'foo1')
        else:
            print("Executing %s command as %s user"
                  % ('sudo -l', 'foo1@example.test'))
            (std_out, _, exit_status) = ssh.execute_cmd('id')
            for line in std_out.readlines():
                print(line)
            (std_out, _, exit_status) = ssh.execute_cmd('sudo -l')
            for line in std_out.readlines():
                if 'NOPASSWD' in line:
                    evar = list(line.strip().split()[1].split('=')[1])[10:14]
                    assert evar == list('0000')
            if exit_status != 0:
                journalctl_cmd = 'journalctl -x -n 100 --no-pager'
                multihost.master[0].run_command(journalctl_cmd)
                pytest.fail("%s cmd failed for user %s" % ('sudo -l', 'foo1'))
            ssh.close()

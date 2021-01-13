""" Automation of sssctl suite with ldap and krb5 provider"""

from __future__ import print_function
import re
import pytest
import time
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'sssdproxyldap')
@pytest.mark.sssctl
class Testsssctl(object):
    """ This is test case class for sssctl suite """
    @pytest.mark.tier1_2
    def test_0001_bz1638295(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to root and ldap user
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': 'root, foo1@%s' % ds_instance_name,
                         'user_attributes': '+mail, -gecos'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'gecos: not set',
                  'mail: foo1@example.test']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0002_bz1638295(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to 0 and ldap user's uid
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': '0, 14583101',
                         'user_attributes': '+mail, -gecos'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'gecos: not set',
                  'mail: foo1@example.test']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0003_bz1638295(self, multihost, localusers, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to root and localuser
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': 'root, user5000',
                         'user_attributes': '-name, -uidNumber'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks user5000'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'name: not set',
                  'uidNumber: not set']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0004_bz1638295(self, multihost, localusers, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to root's and
        localuser's uid
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': '0, 5000',
                         'user_attributes': '-name, -uidNumber'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks user5000'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'name: not set',
                  'uidNumber: not set']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0005_bz1638295(self, multihost, localusers, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to localuser's uids
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': '5000',
                         'user_attributes': '-name, -uidNumber'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks user5000'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        find = re.compile(r'InfoPipe\sUser\slookup\swith\s.user5000.\sfailed')
        result = find.search(cmd.stderr_text)
        assert result is not None

    @pytest.mark.tier1_2
    def test_0006_bz1638295(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to 0 and ldap user
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': '0, foo1@%s' % ds_instance_name,
                         'user_attributes': '+mail, -gecos'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks foo1@%s' % ds_instance_name
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'gecos: not set',
                  'mail: foo1@example.test']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0007_bz1638295(self, multihost, localusers, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl user-checks does not show custom
        IFP user_attributes with allowed_uids equal to root and localuser's uid
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        domain_params = {'allowed_uids': 'root, 5000',
                         'user_attributes': '-name, -uidNumber'}
        tools.sssd_conf("ifp", domain_params)
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl user-checks user5000'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0
        checks = ['SSSD InfoPipe user lookup', 'name: not set',
                  'uidNumber: not set']
        for _ in checks:
            find = re.compile(r'%s' % _)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1_2
    def test_0008_bz1761047(self, multihost):
        """
        @Title: sssctl: Null dereference in
        sssctl/sssctl_domains.c:sssctl_domain_status_active_server()
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        sssd_params = {'domains': '%s, %s' % (domain_name, 'proxy')}
        tools.sssd_conf("sssd", sssd_params, action='update')
        proxy_params = {'auth_provider': 'proxy',
                        'id_provider': 'proxy',
                        'debug_level': '0xFFF0',
                        'proxy_lib_name': 'ldap',
                        'proxy_pam_target': 'sssdproxyldap'}
        tools.sssd_conf("domain/proxy", proxy_params, action='add')
        multihost.client[0].service_sssd('start')
        cat = 'cat /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cat, raiseonerr=False)
        sssctl_cmd = 'sssctl domain-status proxy'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        # when sssd crashes it returns with exit code of 139
        assert cmd.returncode == 0
        # remove the proxy section
        tools.sssd_conf("domain/proxy", proxy_params, 'delete')
        multihost.client[0].run_command(cat, raiseonerr=False)

    @pytest.mark.tier1_2
    def test_0009_bz1751691(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: sssctl: sssctl domain-list command displays
        results intermittently
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.sssd_conf("sssd", {'services': 'nss, pam, ifp'}, action='update')
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl domain-list'
        checks = ['example1', 'implicit_files']
        for _ in range(10):
            time.sleep(5)
            cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
            assert cmd.returncode == 0
            for _ in checks:
                find = re.compile(r'%s' % _)
                result = find.search(cmd.stdout_text)
                assert result is not None

    @pytest.mark.tier1_2
    def test_0010_bz1628122(self, multihost):
        """
        @Title: sssctl: Printing incorrect information
        about domain with sssctl utility
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl domain-status %s -o' % ds_instance_name
        sssctl_cmd = multihost.client[0].run_command(sssctl_cmd,
                                                     raiseonerr=False)
        cmd = sssctl_cmd.stdout_text.split()[-1]
        log = 'cat /var/log/sssd/sssd_%s.log' % ds_instance_name
        log = multihost.client[0].run_command(log, raiseonerr=False)
        assert log.returncode == 0
        if 'Back end is online' or \
                'Backend is already online' in log.stdout_text:
            status = 'Online'
        else:
            status = 'Offline'
        if cmd == status:
            assert True
        else:
            if sssctl_cmd.returncode == 1:
                assert False, 'Invalid domain name'
            else:
                assert False, 'domain status conflict'

    @pytest.mark.tier1_2
    def test_0011_bz1406678(self, multihost):
        """
        @Title: sssctl: sssd started before network
        sssd to go online once network service starts after it
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        start = multihost.client[0].service_sssd('start')
        stop_ds = 'systemctl stop dirsrv@%s' % ds_instance_name
        cmd = multihost.master[0].run_command(stop_ds, raiseonerr=False)
        status_ds = 'systemctl status dirsrv@%s' % ds_instance_name
        cmd = multihost.master[0].run_command(status_ds, raiseonerr=False)
        find = re.compile(r'slapd stopped')
        result = find.search(cmd.stdout_text)
        sss_kill = 'kill -10 `pidof sssd`'
        cmd = multihost.client[0].run_command(sss_kill, raiseonerr=False)
        domain_status = 'sssctl domain-status %s' % ds_instance_name
        cmd = multihost.client[0].run_command(domain_status, raiseonerr=False)
        find = re.compile(r'Online status: Offline')
        result = find.search(cmd.stdout_text)
        assert result is not None
        time.sleep(1)
        touch = 'touch /etc/resolv.conf'
        touch_cmd = multihost.client[0].run_command(touch, raiseonerr=False)
        time.sleep(3)
        start_ds = 'systemctl start dirsrv@%s' % ds_instance_name
        cmd = multihost.master[0].run_command(start_ds, raiseonerr=False)
        cmd = multihost.master[0].run_command(status_ds, raiseonerr=False)
        find = re.compile(r'slapd started')
        result = find.search(cmd.stdout_text)
        time.sleep(6)
        domain_status = 'sssctl domain-status %s' % ds_instance_name
        cmd = multihost.client[0].run_command(domain_status, raiseonerr=False)
        find = re.compile(r'Online status: Online')
        result = find.search(cmd.stdout_text)
        assert result is not None

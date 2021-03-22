""" SSSD Sanity Test Cases

:requirement: IDM-SSSD-REQ : KRB5 Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import time
from sssd.testlib.common.utils import SSHClient
import configparser as ConfigParser
import paramiko
import pytest


class TestSanitySSSD(object):
    """ Basic Sanity Test cases """
    def test_ssh_user_login(self, multihost):
        """
        :title: Login: Check ssh login as LDAP user with Kerberos credentials
        :id: b7600a46-1827-486a-ae2e-cbedad6ddf41
        """
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo1', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo1'))
        else:
            assert True
            ssh.close()

    def test_kinit(self, multihost):
        """
        :title: Login: Verify kinit is successfull after user login
        :id: 5e15e9e9-c559-49b8-a164-abe13d82d0fd
        """
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo2', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo2'))
        else:
            (_, _, exit_status) = ssh.execute_cmd(args='kinit',
                                                  stdin='Secret123')
            assert exit_status == 0
            (stdout, _, _) = ssh.execute_cmd('klist')
            for line in stdout.readlines():
                print(line)
                assert exit_status == 0
                ssh.close()

    def test_offline_ssh_login(self, multihost):
        """
        :title: Login: Verify offline ssh login
        :id: 90e9a834-a1f9-4bef-bdae-57a7b411cce4
        """
        multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                               '/tmp/sssd.conf')
        sssdconfig = ConfigParser.RawConfigParser()
        sssdconfig.read('/tmp/sssd.conf')
        domain_section = "%s/%s" % ('domain', 'EXAMPLE.TEST')
        if domain_section in sssdconfig.sections():
            sssdconfig.set(domain_section, 'cache_credentials', 'True')
            sssdconfig.set(domain_section, 'krb5_store_password_if_offline',
                           'True')
            sssdconfig.set('pam', 'offline_credentials_expiration', '0')
            with open('/tmp/sssd.conf', "w") as fd:
                sssdconfig.write(fd)
        else:
            print("Could not fetch sssd.conf")
            assert False
        multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                               '/etc/sssd/sssd.conf')
        multihost.master[0].service_sssd('restart')
        time.sleep(5)
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo4', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Unable to authenticate as %s" % ('foo4'))
        else:
            ssh.close()
            stop_dirsrv = 'systemctl stop dirsrv@example1'
            stop_krb5kdc = 'systemctl stop krb5kdc'
            multihost.master[0].run_command(stop_dirsrv)
            multihost.master[0].run_command(stop_krb5kdc)
            try:
                ssh = SSHClient(multihost.master[0].sys_hostname,
                                username='foo4', password='Secret123')
            except paramiko.ssh_exception.AuthenticationException:
                pytest.fail("Unable to authenticate as %s" % ('foo4'))
            else:
                ssh.close()
                start_dirsrv = 'systemctl start dirsrv@example1'
                start_krb5kdc = 'systemctl start krb5kdc'
                multihost.master[0].run_command(start_dirsrv)
                multihost.master[0].run_command(start_krb5kdc)

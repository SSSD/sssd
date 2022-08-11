""" SSSD Sanity Test Cases

:requirement: IDM-SSSD-REQ : KRB5 Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import configparser as ConfigParser
from sssd.testlib.common.utils import sssdTools


class TestSanitySSSD(object):
    """ Basic Sanity Test cases """
    @staticmethod
    def test_ssh_user_login(multihost):
        """
        :title: Login: Check ssh login as LDAP user with Kerberos credentials
        :id: b7600a46-1827-486a-ae2e-cbedad6ddf41
        """
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client("foo1", 'Secret123') == 3
        assert ssh0, "Authentication Failed as user foo1"

    @staticmethod
    def test_kinit(multihost):
        """
        :title: Login: Verify kinit is successfull after user login
        :id: 5e15e9e9-c559-49b8-a164-abe13d82d0fd
        """
        user = 'foo2'
        cmd = multihost.master[0].run_command(
            f'su - {user} -c "kinit"', stdin_text='Secret123',
            raiseonerr=False)
        assert cmd.returncode == 0, "kinit failed!"

        cmd2 = multihost.master[0].run_command(
            f'su - {user} -c "klist"', raiseonerr=False)
        assert cmd2.returncode == 0, "klist failed!"

    @staticmethod
    def test_offline_ssh_login(multihost):
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
            with open('/tmp/sssd.conf', "w") as file_d:
                sssdconfig.write(file_d)
        else:
            print("Could not fetch sssd.conf")
            assert False
        multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                               '/etc/sssd/sssd.conf')
        multihost.master[0].service_sssd('restart')
        time.sleep(5)
        client = sssdTools(multihost.master[0])
        user = 'foo4'
        ssh0 = client.auth_from_client(user, password='Secret123') == 3
        assert ssh0, f"Initial ssh login as {user} failed."

        stop_dirsrv = 'systemctl stop dirsrv@example1'
        stop_krb5kdc = 'systemctl stop krb5kdc'
        multihost.master[0].run_command(stop_dirsrv)
        multihost.master[0].run_command(stop_krb5kdc)

        ssh1 = client.auth_from_client(user, password='Secret123') == 3

        start_dirsrv = 'systemctl start dirsrv@example1'
        start_krb5kdc = 'systemctl start krb5kdc'
        multihost.master[0].run_command(start_dirsrv)
        multihost.master[0].run_command(start_krb5kdc)

        assert ssh1, f"Offline ssh login as {user} failed."

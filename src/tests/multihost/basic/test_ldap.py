""" SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import re
import time
from sssd.testlib.common.utils import SSHClient
import pytest
import textwrap
import paramiko
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

UNINDENT_RE = re.compile("^ +", re.MULTILINE)


def expect_chpass_script(current_pass, new_pass):
    return textwrap.dedent("""\
    set timeout 15
    spawn passwd
    expect "Changing password for user puser."
    expect "Current Password:"
    send "{current_pass}\r"
    expect "New password:"
    send "{new_pass}\r"
    expect "Retype new password:"
    send "{new_pass}\r"
    expect "passwd: all authentication tokens updated successfully"
    expect EOF
    """).format(**locals())


def run_expect_script(multihost, ssh_conn, expect_string):
    expect_file = '/tmp/expect_multihost'
    try:
        multihost.master[0].run_command('rm -f ' + expect_file)
        multihost.master[0].put_file_contents(expect_file, expect_string)
        ssh_conn.execute_cmd('expect -f ' + expect_file)
    except Exception as err:
        raise err
    finally:
        multihost.master[0].run_command('rm -f ' + expect_file)


def chpass(multihost, ssh_conn, current_pass, new_pass):
    script = expect_chpass_script(current_pass, new_pass)
    run_expect_script(multihost, ssh_conn, script)


@pytest.fixture
def set_ldap_auth_provider(session_multihost, request):
    """ Set entry cache sudo timeout in sssd.conf """
    bkup_sssd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
    session_multihost.master[0].run_command(bkup_sssd)
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    domain_section = "%s/%s" % ('domain', 'EXAMPLE.TEST')
    if domain_section in sssdconfig.sections():
        sssdconfig.set(domain_section, 'auth_provider', 'ldap')
        sssdconfig.set(domain_section,
                       'ldap_auth_disable_tls_never_use_in_production',
                       'true')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')

    def restore_sssd():
        """ Restore sssd.conf """
        restore_sssd = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        session_multihost.master[0].run_command(restore_sssd)
        session_multihost.master[0].service_sssd('restart')
    request.addfinalizer(restore_sssd)


@pytest.fixture
def set_ldap_pwmodify_mode_ldap_modify(session_multihost, request):
    """ Set entry cache sudo timeout in sssd.conf """
    bkup_sssd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
    session_multihost.master[0].run_command(bkup_sssd)
    session_multihost.master[0].transport.get_file('/etc/sssd/sssd.conf',
                                                   '/tmp/sssd.conf')
    sssdconfig = ConfigParser.ConfigParser()
    sssdconfig.read('/tmp/sssd.conf')
    domain_section = "%s/%s" % ('domain', 'EXAMPLE.TEST')
    if domain_section in sssdconfig.sections():
        sssdconfig.set(domain_section, 'ldap_pwmodify_mode', 'ldap_modify')
        with open('/tmp/sssd.conf', "w") as sssconf:
            sssdconfig.write(sssconf)
    session_multihost.master[0].transport.put_file('/tmp/sssd.conf',
                                                   '/etc/sssd/sssd.conf')
    session_multihost.master[0].service_sssd('restart')

    def restore_sssd():
        """ Restore sssd.conf """
        restore_sssd = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        session_multihost.master[0].run_command(restore_sssd)
        session_multihost.master[0].service_sssd('restart')
    request.addfinalizer(restore_sssd)


class TestLDAPChpass(object):
    """ Test changing LDAP password """

    def _change_test_reset_password(self, multihost):
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo1', password='Secret123')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo1'))

        expect_script = chpass(multihost, ssh, 'Secret123', 'Secret1234')
        ssh.close()

        # Try logging in with the new password
        try:
            ssh = SSHClient(multihost.master[0].sys_hostname,
                            username='foo1', password='Secret1234')
        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail("Authentication Failed as user %s" % ('foo1'))

        # Clean up and change the password back
        expect_script = chpass(multihost, ssh, 'Secret1234', 'Secret123')
        ssh.close()

    def test_ldap_chpass_extop(self, multihost):
        """
        :title: chpass: Test password change using the default extended
         operation
        :id: 4b3ab9a6-d26f-484d-994f-8bc74c31b9dd
        """
        self._change_test_reset_password(multihost)

    def test_ldap_chpass_modify(self,
                                multihost,
                                set_ldap_auth_provider,
                                set_ldap_pwmodify_mode_ldap_modify):
        """
        :title: chpass: Test password change using LDAP modify
        :id: 554c989d-f99b-4722-925b-5be54a33af89
        """
        self._change_test_reset_password(multihost)

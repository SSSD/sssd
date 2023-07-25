""" SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
from sssd.testlib.common.utils import sssdTools
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser


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

    @staticmethod
    def _change_test_reset_password(multihost):
        user = 'foo1'
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client(user, 'Secret123') == 3
        assert ssh0, f"Authentication Failed as user {user}"
        client.change_user_password(
            user, 'Secret123', 'Secret123', 'Secret1234', 'Secret1234')

        # Try logging in with the new password
        ssh1 = client.auth_from_client(user, 'Secret1234') == 3
        assert ssh1, f"Authentication Failed as {user} with the new password."

        # Clean up and change the password back
        client.change_user_password(
            user, 'Secret1234', 'Secret1234', 'Secret123', 'Secret123')

    @staticmethod
    def test_ldap_chpass_extop(multihost):
        """
        :title: chpass: Test password change using the default extended
         operation
        :id: 4b3ab9a6-d26f-484d-994f-8bc74c31b9dd
        """
        TestLDAPChpass._change_test_reset_password(multihost)

    @staticmethod
    @pytest.mark.usefixtures("set_ldap_auth_provider",
                             "set_ldap_pwmodify_mode_ldap_modify")
    def test_ldap_chpass_modify(multihost):
        """
        :title: chpass: Test password change using LDAP modify
        :id: 554c989d-f99b-4722-925b-5be54a33af89
        """
        TestLDAPChpass._change_test_reset_password(multihost)

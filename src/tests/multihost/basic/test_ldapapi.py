""" SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.fixture
def set_ldap_uri(multihost):
    ldap_uri = 'ldapi://%2Frun%2Fslapd-example1.socket'
    tools = sssdTools(multihost.master[0])
    domain_name = tools.get_domain_section_name()
    master = sssdTools(multihost.master[0])
    domain_params = {'ldap_uri': ldap_uri,
                     'ldap_id_use_start_tls': 'false'}
    master.sssd_conf(f'domain/{domain_name}', domain_params)
    multihost.master[0].service_sssd('restart')


@pytest.mark.usefixtures("set_ldap_uri")
class TestLdapApi(object):
    """ Basic Ldap Uri Test cases """
    @staticmethod
    def test_ssh_user_login(multihost):
        """
        :title: Add support for ldapi:// URLs
        :bugzilla:https://bugzilla.redhat.com/show_bug.cgi?id=2152177
        :id: 4f4a01a6-da6d-11ed-9c8d-845cf3eff344
        :steps:
          1. Check user can be fetched from master server
          2. Check sssctl command works
          3. Check getent command works
          4. Check user can login to localhost
        :expectedresults:
          1. User id should be fetched
          2. Should succeed
          3. Should succeed
          4. User should able to login to localhost
        """
        std_out = multihost.master[0].run_command("id foo1").stdout_text
        for data in ['foo1', 'ldapusers']:
            assert data in std_out
        std_out = multihost.master[0].run_command("sssctl user-checks foo1").stdout_text
        for data in ["uidNumber", 'foo1', '/bin/bash']:
            assert data in std_out
        std_out = multihost.master[0].run_command("getent passwd foo1").stdout_text
        for data in ['foo1', '/bin/bash']:
            assert data in std_out
        client = sssdTools(multihost.master[0])
        ssh0 = client.auth_from_client("foo1", 'Secret123') == 3
        assert ssh0, "Authentication Failed as user foo1"

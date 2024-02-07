""" AD idmap tests from bash
:requirement: IDM-SSSD-REQ: idmap
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('joinad', 'create_idmap_users_groups')
@pytest.mark.tier2
@pytest.mark.idmap
class Testidmap(object):
    """ Test cases for idmap
    :setup:
        1. Join to AD using realm command.
        2. Create a non-POSIX user and a non-POSIX group
        3. Create a user and a group with posix attributes
    """
    @pytest.mark.converted('test_identity.py', 'test_identity__lookup_idmapping_of_posix_and_non_posix_user_and_group')
    @staticmethod
    def test_001_idmap_disable(multihost):
        """
        :title: with ldap provider idmapping is disabled
        :description: Disable idmapping for ldap provider and confirm the
         only the users, and group, with posix attributes defined in AD-server
         are returned
        :id: 989ec7eb-451c-49c4-9b09-e3ac005721d7
        :setup:
            1. Configure ldap_provider with idmapping disabled
        :steps:
            1. Fetch non-posix users and groups information
            2. Fetch posix users and groups information
            3. Log in as a posix-user
        :expectedresults:
            1. Non-posix user and group should not be returned
            2. POSIX user and group information should be returned
            3. POSIX user should be able to log in
        """
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        domain_name = client.get_domain_section_name()
        dom_section = f'domain/{domain_name}'
        params = {'id_provider': 'ldap',
                  'ldap_uri': f'ldap://{multihost.ad[0].hostname}',
                  'ldap_schema': 'ad',
                  'ldap_id_mapping': 'false',
                  'ldap_default_bind_dn': f'CN=administrator,CN=Users,{multihost.ad[0].domain_basedn_entry}',
                  'ldap_default_authtok': f'{multihost.ad[0].ssh_password}',
                  'ldap_default_authtok_type': 'password',
                  'debug_level': '0xFFF0',
                  'use_fully_qualified_names': 'false',
                  'ldap_tls_cacert': '/etc/openldap/certs/ad_cert.pem',
                  'ldap_tls_reqcert': 'demand',
                  'ldap_referrals': 'false'}
        client.sssd_conf(dom_section, params)
        client.clear_sssd_cache()
        cmd1 = multihost.client[0].run_command('getent passwd noposix_usr', raiseonerr=False)
        cmd2 = multihost.client[0].run_command('getent group noposix_grp', raiseonerr=False)
        cmd3 = multihost.client[0].run_command('getent passwd posix_usr', raiseonerr=False)
        cmd4 = multihost.client[0].run_command('getent group posix_grp', raiseonerr=False)
        client.restore_sssd_conf()
        assert client.auth_from_client('posix_usr', 'Secret123') == 3, 'ssh login failed for posix-user'
        assert cmd1.returncode == 2, 'non-posix user is returned by sssd, it should not be'
        assert cmd2.returncode == 2, 'non-posix group is returned by sssd, it should not be'
        assert cmd3.returncode == 0, 'posix-user is not returned by sssd'
        assert cmd4.returncode == 0, 'posix-group is not returned by sssd'

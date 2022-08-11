"""Tests related to host map and network map

:requirement: SSSD NSS should support host map
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
from sssd.testlib.common.utils import sssdTools, LdapOperations
import pytest


@pytest.mark.usefixtures('setup_sssd', 'enable_sssd_hostmap', 'add_host_entry')
@pytest.mark.hostmap
class TestHostMaps(object):
    """
    SSSD NSS should support host map
    :bugzilla:
     https://bugzilla.redhat.com/show_bug.cgi?id=1340908
    """
    @pytest.mark.tier1
    def test_001_ldap_iphost_search_base(self, multihost):
        """
        :title: hosts: Test ldap_iphost_search_base field
        :id: a5b82f87-e4f2-49ce-bfc2-e23f5020219d
        :customerscenario: True
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_iphost_search_base':
                         'ou=People,dc=example,dc=test'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent = "getent hosts node1"
        cmd = multihost.client[0].run_command(getent)
        if '192.168.1.1' in cmd.stdout_text and \
                '192.168.1.2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        assert status == 'PASS'
        getent = "getent hosts 192.168.1.1"
        cmd = multihost.client[0].run_command(getent)
        if 'node1' in cmd.stdout_text and 'node2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_002_ldap_iphost_object_class(self, multihost):
        """
        :title: hosts: Test ldap_iphost_object_class field
        :id: eed161fa-1310-43b7-90e6-dd99846d9cbe
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_iphost_object_class': 'ipHost'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent = "getent hosts node1"
        cmd = multihost.client[0].run_command(getent)
        if '192.168.1.1' in cmd.stdout_text and \
                '192.168.1.2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        assert status == 'PASS'
        getent = "getent hosts 192.168.1.1"
        cmd = multihost.client[0].run_command(getent)
        if 'node1' in cmd.stdout_text and 'node2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_003_ldap_iphost_name(self, multihost):
        """
        :title: hosts: Test ldap_iphost_name field
        :id: 00ae3874-f3ef-4121-bb89-1fce554ddbef
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_iphost_name': 'cn'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent = "getent hosts node1"
        cmd = multihost.client[0].run_command(getent)
        if '192.168.1.1' in cmd.stdout_text and \
                '192.168.1.2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        assert status == 'PASS'
        getent = "getent hosts 192.168.1.1"
        cmd = multihost.client[0].run_command(getent)
        if 'node1' in cmd.stdout_text and 'node2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_004_ldap_iphost_number(self, multihost):
        """
        :title: hosts: Test ldap_iphost_number field
        :id: f78b0874-411c-45f4-8497-e1544d01fdbc
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_iphost_number': 'ipHostNumber'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent = "getent hosts node1"
        cmd = multihost.client[0].run_command(getent)
        if '192.168.1.1' in cmd.stdout_text and \
                '192.168.1.2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        assert status == 'PASS'
        getent = "getent hosts 192.168.1.1"
        cmd = multihost.client[0].run_command(getent)
        if 'node1' in cmd.stdout_text and 'node2' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_005_ldap_ipnetwork_search_base(self, multihost):
        """
        :title: hosts: Test ldap_ipnetwork_search_base field
        :id: 075bd1e0-8db2-4cc4-bfdf-99fbbe8df62d
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_ipnetwork_search_base':
                         'ou=People,dc=example,dc=test'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent_networks = "getent networks node2"
        cmd = multihost.client[0].run_command(getent_networks)
        if '192.168.1.2' in cmd.stdout_text and \
                '192.168.1.1' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_006_ldap_ipnetwork_object_class(self, multihost):
        """
        :title: hosts: Test ldap_ipnetwork_object_class field
        :id: fcf249c4-4501-4ff3-a916-5ab13cccc349
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_ipnetwork_object_class': 'ipNetwork'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent_networks = "getent networks node2"
        cmd = multihost.client[0].run_command(getent_networks)
        if '192.168.1.2' in cmd.stdout_text and \
                '192.168.1.1' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_007_ldap_ipnetwork_name(self, multihost):
        """
        :title: hosts: Test ldap_ipnetwork_name field
        :id: 8d90a533-7d42-4dd4-aab1-c8c3e25cb60a
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_ipnetwork_name': 'cn'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent_networks = "getent networks node2"
        cmd = multihost.client[0].run_command(getent_networks)
        if '192.168.1.2' in cmd.stdout_text and \
                '192.168.1.1' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_008_ldap_ipnetwork_number(self, multihost):
        """
        :title: hosts: Test ldap_ipnetwork_number field
        :id: ae1df923-5115-4f58-8650-d4a187cf8f7e
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_ipnetwork_number': 'ipNetworkNumber'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent_networks = "getent networks node2"
        cmd = multihost.client[0].run_command(getent_networks)
        if '192.168.1.2' in cmd.stdout_text and \
                '192.168.1.1' not in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1
    def test_009_ipnetwork_iphost(self, multihost):
        """
        :title: hosts: Test ldap_ipnetwork_search_base
         and ldap_iphost_search_base fields
        :id: 6394baf6-d285-40ef-8182-262ef29d4e33
        """
        client = sssdTools(multihost.client[0])
        domain_params = {
            'ldap_ipnetwork_search_base': 'ou=People,dc=example,dc=test',
            'ldap_iphost_search_base': 'ou=People,dc=example,dc=test'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        getent_networks = "getent networks node3"
        cmd = multihost.client[0].run_command(getent_networks)
        if '192.168.1.3' in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        assert status == 'PASS'
        getent_networks = "getent hosts 192.168.1.3"
        cmd = multihost.client[0].run_command(getent_networks)
        if 'node3' in cmd.stdout_text:
            status = 'PASS'
        else:
            status = 'FAIL'
        client.sssd_conf('domain/example1', domain_params, action='delete')
        assert status == 'PASS'

    @pytest.mark.tier1_3
    def test_more_than_one_cn(self, multihost):
        """
        :title: hosts: 'getent hosts' not return hosts
         if they have more than one CN in LDAP
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2056035
        :id: f2bacc70-ccff-11ec-9b25-845cf3eff344
        :customerscenario: true
        :steps:
          1. Create hostname having multiple 'cn'
          2. Entry having multiple 'cn' handled correctly by SSSD
        :expectedresults:
          1. Should succeed
          2. Should succeed
        """
        ldap_uri = 'ldap://%s' % (multihost.master[0].sys_hostname)
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_info = {'cn': ['node4'.encode('utf-8'),
                            'node4.example.test'.encode('utf-8')],
                     'objectClass': [b'top', b'ipHost', b'device'],
                     'ipHostNumber': '192.168.1.4'.encode('utf-8')}
        user_dn = 'cn=node4+ipHostNumber=192.168.1.4,ou=People,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        client = sssdTools(multihost.client[0])
        domain_params = {'ldap_iphost_search_base': 'ou=People,dc=example,dc=test'}
        client.sssd_conf('domain/example1', domain_params)
        client.clear_sssd_cache()
        output = multihost.client[0].run_command("getent hosts node4").stdout_text
        for i in ['node4.example.test', '192.168.1.4']:
            assert i in output
        output = multihost.client[0].run_command("getent "
                                                 "hosts "
                                                 "node4.example.test").stdout_text
        for i in ['node4.example.test', '192.168.1.4']:
            assert i in output
        cmd = multihost.client[0].run_command("getent "
                                              "hosts "
                                              "node1 "
                                              "node3 "
                                              "node4").stdout_text
        for i in ['192.168.1.1', '192.168.1.3', '192.168.1.4',
                  'node1', 'node3', 'node4.example.test']:
            assert i in cmd
        ldap_inst.del_dn('cn=node4+ipHostNumber=192.168.1.4,ou=People,dc=example,dc=test')

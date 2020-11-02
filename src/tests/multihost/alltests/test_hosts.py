"""Tests related to host map and network map"""
from __future__ import print_function
from sssd.testlib.common.utils import sssdTools
import pytest


@pytest.mark.usefixtures('setup_sssd', 'enable_sssd_hostmap', 'add_host_entry')
@pytest.mark.hostmap
class TestHostMaps(object):
    """
    SSSD NSS should support host map
    @bugzilla:
    https://bugzilla.redhat.com/show_bug.cgi?id=1340908
    """
    @pytest.mark.tier1
    def test_001_ldap_iphost_search_base(self, multihost):
        """
        :Title:hosts: Test ldap_iphost_search_base field
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
        :Title:hosts: Test ldap_iphost_object_class field
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
        :Title:hosts: Test ldap_iphost_name field
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
        :Title:hosts: Test ldap_iphost_number field
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
        :Title:hosts: Test ldap_ipnetwork_search_base field
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
        :Title:hosts: Test ldap_ipnetwork_object_class field
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
        :Title:hosts: Test ldap_ipnetwork_name field
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
        :Title:hosts: Test ldap_ipnetwork_number field
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
        :Title:hosts: Test ldap_ipnetwork_search_base
        and ldap_iphost_search_base fields
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

"""Automation tests for dynamic DNS

:requirement: dyndns
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: no
"""

import pytest
import time
import random
from sssd.testlib.common.utils import sssdTools


@pytest.fixture(scope="class")
def change_client_hostname(session_multihost, request):
    """ Change client hostname to a truncated version in the AD domain"""
    cmd = session_multihost.client[0].run_command('hostname', raiseonerr=False)
    old_hostname = cmd.stdout_text.rstrip()
    ad_domain = session_multihost.ad[0].domainname
    new_hostname = "client" + str(random.randrange(99))
    new_hostname = new_hostname + "." + ad_domain
    session_multihost.client[0].run_command(f'hostname {new_hostname}', raiseonerr=False)

    def restore_hostname():
        """ Restore hostname """
        session_multihost.client[0].run_command(f'hostname {old_hostname}', raiseonerr=False)
    request.addfinalizer(restore_hostname)


@pytest.fixture(scope="function")
def extra_network(session_multihost, request):
    """ Create reverse zone """
    network = "192.168.1.1"
    network_list = network.split(".")
    network_zone = str(network_list[2] + '.' + network_list[1] + '.' + network_list[0])
    cmd_zoneadd = f"dnscmd.exe /zoneadd {network_zone}.in-addr.arpa /primary"
    cmd_zoneconfig = f"dnscmd.exe /config {network_zone}.in-addr.arpa /allowupdate 1"
    session_multihost.ad[0].run_command(cmd_zoneadd)
    session_multihost.ad[0].run_command(cmd_zoneconfig)

    def remove_extra_network():
        """ Delete reverse zone"""
        session_multihost.ad[0].run_command(f"dnscmd.exe /zonedelete {network_zone}.in-addr.arpa /f")

    request.addfinalizer(remove_extra_network)


@pytest.fixture(scope="function")
def extra_interface(session_multihost, request):
    """ Create extra interface """
    dummy_interface = 'ibm' + str(random.randrange(99))
    dummy_ip = '192.168.1.' + str(random.randrange(2, 255))
    session_multihost.client[0].run_command('ip link add ' + dummy_interface + ' type dummy', raiseonerr=False)
    session_multihost.client[0].run_command('ip addr add ' + dummy_ip + ' dev ' + dummy_interface, raiseonerr=False)

    def remove_interface():
        """ Delete interface """
        session_multihost.client[0].run_commnd('ip addr flush dev ' + dummy_interface, raiseonerr=False)
        session_multihost.client[0].run_command('ip link del ' + dummy_interface, raiseonerr=False)

    request.addfinalizer(remove_interface)
    return dummy_interface, dummy_ip


@pytest.fixture(scope="function")
def getptr(session_multihost, request):
    """ Get network and ptr record """
    ip = str(session_multihost.client[0].ip)
    net_list = ip.split(".")
    network = str(net_list[2] + '.' + net_list[1] + '.' + net_list[0])
    ptr = str(net_list[3])

    def removeptr():
        """ Delete PTR record from DNS """
        cmd_delete_ptr = f"dnscmd.exe /recorddelete {network}.in-addr.arpa {ptr}. PTR /f"
        session_multihost.ad[0].run_command(cmd_delete_ptr, raiseonerr=False)
    request.addfinalizer(removeptr)

    return ip, network, ptr


@pytest.mark.usefixtures("change_client_hostname")
@pytest.mark.dyndns
@pytest.mark.tier1_3
class TestDynDns(object):

    def test_0001_verify_with_default_setting(self, multihost, adjoin, getptr):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: default settings
        :id: 183cc040-0b8c-47af-8b19-8bcb72c3f001
        :steps:
          1. Join client to AD domain
          2. Perform DNS lookup for hostname
          3. Perform DNS lookup for IP
        :expectedresults:
          1. Client joins domain
          2. Hostname resolves correctly
          3. IP resolves correctly
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        (ip, network, ptr) = getptr
        client.clear_sssd_cache()
        cmd_lookup = multihost.client[0].run_command(f"nslookup {hostname}", raiseonerr=False)
        assert cmd_lookup.returncode == 0
        cmd_lookup_ptr = multihost.client[0].run_command(f"nslookup {ip}", raiseonerr=False)
        assert cmd_lookup_ptr.returncode == 0

    def test_0002_verify_when_dyndns_update_set_to_false(self, multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: verify when dyndns update set to false
        :id: 0cdbd0fe-4c67-4192-b44b-04e4227b5858
        :steps:
          1. Join client to AD domain
          2. Perform DNS lookup for hostname
          3. Perform DNS lookup for IP
        :expectedresults:
          1. Client joins domain
          2. Hostname resolves incorrectly
          3. IP resolves incorrectly
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        ip = str(multihost.client[0].ip)

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_update': 'false'}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        cmd_forward_lookup = multihost.client[0].run_command([f"nslookup {hostname}"], raiseonerr=False)
        assert cmd_forward_lookup.returncode != 0
        cmd_ptr_lookup = multihost.client[0].run_command([f"nslookup {ip}"], raiseonerr=False)
        assert cmd_ptr_lookup.returncode != 0

    def test_0003_verify_with_dyndns_ttl_functionality(self, multihost, adjoin, getptr):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: Verify with dyndns ttl functionality
        :id: ffb8ee9b-2a82-4917-82b0-d87fd066a24c
        :steps:
          1. Join client to AD domain
          2. Configure sssd.conf with dyndns_ttl = 9200
          3. Perform DNS lookup for hostname
          4. Perform DNS lookup for IP
        :expectedresults:
          1. Client joins domain
          2. Should succeed
          3. Hostname resolves with 9200 ttl
          4. IP resolves with 9200 ttl
        """
        adjoin(membersw='adcli')
        ttl = '9200'
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        (ip, network, ptr) = getptr
        cmd_change_hostname = 'hostname ' + hostname
        multihost.client[0].run_command(cmd_change_hostname)
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_ttl': ttl}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        time.sleep(30)
        cmd_ptr_lookup = multihost.client[0].run_command(f'nslookup -debug {ip} | grep ttl | cut -f2 -d"=" | sed "s/ //"')
        assert cmd_ptr_lookup.returncode == 0
        assert 9200 >= int(cmd_ptr_lookup.stdout_text)
        assert 9000 <= int(cmd_ptr_lookup.stdout_text)

    def test_0004_check_dyndns_iface_with_existing_interfaces(
            self, multihost, adjoin, extra_network, extra_interface, getptr):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check dyndns iface with existing interface
        :id: 166ee0a0-6f19-4be0-b5db-7373dde82862
        :steps:
          1. Join client to AD domain
          2. Create dummy interface
          3. Perform DNS lookup for hostname on dummy interface
          4. Perform DNS lookup for IP on dummy interface
        :expectedresults:
          1. Client joins domain
          2. Should succeed
          3. Hostname resolves correctly on dummy interface
          4. IP resolves correctly on dummy interface
        """
        (dummy_interface, dummy_ip) = extra_interface
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        (ip, network, ptr) = getptr

        adjoin(membersw='adcli')
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_iface': dummy_interface}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        multihost.client[0].run_command(f"nslookup {hostname}")
        multihost.client[0].run_command(f"nslookup {dummy_ip}", raiseonerr=False)
        cmd_lkup = multihost.client[0].run_command(f"nslookup {ip}", raiseonerr=False)
        assert cmd_lkup.returncode != 0

    def test_0005_check_dyndns_iface_with_non_existing_interfaces(self, multihost, adjoin, getptr):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check dyndns iface with non-existing interface
        :id: 412f684a-5a68-472d-86b1-93019bb53e6f
        :steps:
          1. Join client to AD domain
          2. Perform DNS lookup for hostname on bogus interface
          3. Perform DNS lookup for IP on bogus interface
        :expectedresults:
          1. Client joins domain
          2. Hostname does not resolve correctly on bogus interface
          3. IP does not resolve correctly on bogus interface
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        host = hostname.split(".")[0]
        domain = multihost.ad[0].domainname
        (ip, network, ptr) = getptr

        cmd_delete_a = f"dnscmd.exe /recorddelete {domain} {host} A /f"
        cmd_delete_ptr = f"dnscmd.exe /recorddelete {network}.in-addr.arpa {ptr}. PTR /f"
        multihost.ad[0].run_command(cmd_delete_a, raiseonerr=False)
        multihost.ad[0].run_command(cmd_delete_ptr, raiseonerr=False)

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_iface': 'non_existent'}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        cmd_forward_lookup = multihost.client[0].run_command(f"nslookup {hostname}", raiseonerr=False)
        assert multihost.client[0].hostname != hostname
        assert domain not in cmd_forward_lookup.stdout_text

    def test_0006_check_with_dyndns_refresh_interval(self, multihost, adjoin, extra_network, extra_interface):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check with dyndns refresh interval
        :id: 54765188-b21f-4ba1-890b-953eec9b696d
        :steps:
          1. Join client to AD domain
          2. Create dummy interface and assign IP
          3. Set refresh interval and dyndns iface in sssd.conf
          4. Perform DNS lookup for hostname on dummy interface
          5. Perform DNS lookup for IP on dummy interface
          6. Change IP on dummy interface
          7. Wait for SSSD to update the IP, refresh interval + update timeout
          8. Perform DNS lookup for hostname on dummy interface
          9. Perform DNS lookup for IP on dummy interface
        :expectedresults:
          1. Client joins domain
          2. Should succeed
          3. Should succeed
          4. Hostname resolves correctly on dummy interface
          5. IP resolves correctly on dummy interface
          6. New IP address is assigned for dummy interface
          7. Wait for some time
          8. Hostname resolves correctly on dummy interface with new IP
          9. IP resolves correctly on dummy interface with new hostname
        """
        (dummy_interface, dummy_ip) = extra_interface
        dummy_ip_after_refresh = '192.168.1.' + str(random.randrange(2, 255))
        while dummy_ip == dummy_ip_after_refresh:
            dummy_ip_after_refresh = '192.168.1.' + str(random.randrange(2, 255))
        update_timeout = 20
        refresh_interval = 61
        client = sssdTools(multihost.client[0], multihost.ad[0])
        hostname_cmd = multihost.client[0].run_command('hostname', raiseonerr=False)
        hostname = hostname_cmd.stdout_text.rstrip()
        domain = multihost.ad[0].domainname

        adjoin(membersw='adcli')
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {
            'dyndns_iface': dummy_interface,
            'dyndns_refresh_interval': refresh_interval}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        time.sleep(update_timeout)
        cmd_lkup = multihost.client[0].run_command(f"nslookup {hostname}", raiseonerr=False)
        cmd_ptr_lkup = multihost.client[0].run_command(f"nslookup {dummy_ip}", raiseonerr=False)
        assert cmd_lkup.returncode == 0
        assert cmd_ptr_lkup.returncode == 0
        multihost.client[0].run_command('ip addr flush dev ' + dummy_interface)
        multihost.client[0].run_command('ip addr add ' + dummy_ip_after_refresh + ' dev ' + dummy_interface)

        time.sleep(update_timeout)
        cmd_forward_lookup = multihost.client[0].run_command(f"nslookup {hostname}")
        cmd_ptr_lookup = multihost.client[0].run_command(f"nslookup {dummy_ip}")
        assert cmd_forward_lookup.returncode == 0
        assert cmd_ptr_lookup.returncode == 0
        multihost.client[0].run_command('ip addr flush dev ' + dummy_interface)
        multihost.client[0].run_command('ip addr add ' + dummy_ip_after_refresh + ' dev ' + dummy_interface)

        time.sleep(refresh_interval)
        cmd_forward_lookup = multihost.client[0].run_command(f"nslookup {hostname}")
        cmd_ptr_lookup = multihost.client[0].run_command(f"nslookup {dummy_ip_after_refresh}")
        assert cmd_forward_lookup.returncode == 0
        assert cmd_ptr_lookup.returncode == 0


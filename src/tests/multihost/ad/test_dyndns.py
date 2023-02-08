"""Automation tests for dynamic DNS

:requirement: dyndns
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
+:status: approved
"""
# flake8: noqa: W605

import pytest
import time
import random
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import ADDNS


@pytest.fixture(scope="class")
def change_client_hostname(session_multihost, request):
    """ Change client hostname to client[XX].domain.com """
    cmd = session_multihost.client[0].run_command('hostname', raiseonerr=False)
    old_hostname = cmd.stdout_text.rstrip()
    ad_domain = session_multihost.ad[0].domainname
    new_hostname = "client" + str(random.randrange(99)) + "." + ad_domain
    session_multihost.client[0].run_command(f'hostnamectl set-hostname \"{new_hostname}\"')

    def restore_hostname():
        """ Restore hostname """
        session_multihost.client[0].run_command(f'hostnamectl set-hostname {old_hostname}')

    request.addfinalizer(restore_hostname)


@pytest.fixture(scope="class")
def disable_dns_forwarders(session_multihost, request):
    """ Disables recursive lookups on DNS server """
    session_multihost.ad[0].run_command('dnscmd.exe /config /norecursion 1', raiseonerr=False)

    def enable_dns_forwarders():
        """ Enables recursion lookups on DNS servers """
        session_multihost.ad[0].run_command('dnscmd.exe /config /norecursion 0', raiseonerr=False)

    request.addfinalizer(enable_dns_forwarders)


@pytest.fixture(scope="class")
def reverse_zone(session_multihost, request):
    """ Creates reverse zones """
    dns = ADDNS(session_multihost.ad[0])
    ip = session_multihost.ad[0].ip.split(".")
    ip1 = session_multihost.client[0].ip.split(".")
    network = str(f'{ip[2]}.{ip[1]}.{ip[0]}.in-addr.arpa')
    dns.add_zone(network)
    if ip[2] != ip1[2]:
        network1 = str(f'{ip1[2]}.{ip1[1]}.{ip1[0]}.in-addr.arpa')
        assert dns.add_zone(network1)

    def remove_reverse_zone():
        """ Delete reverse zones """
        dns.del_zone(network)
        if ip[2] != ip1[2]:
            dns.del_zone(network1)

    request.addfinalizer(remove_reverse_zone)


@pytest.fixture(scope="function")
def extra_network(session_multihost, request):
    """ Create reverse zone """
    dns = ADDNS(session_multihost.ad[0])
    network = "1.168.192.in-addr.arpa"
    assert dns.add_zone(network)

    def remove_extra_network():
        """ Delete reverse zone"""
        dns.del_zone(network)

    request.addfinalizer(remove_extra_network)


@pytest.fixture(scope="function")
def extra_interface(session_multihost, request):
    """ Create extra interface """
    extra_interface = 'ibm' + str(random.randrange(99))
    extra_ip = '192.168.1.' + str(random.randrange(2, 255))
    session_multihost.client[0].run_command('ip link add ' + extra_interface + ' type dummy')
    session_multihost.client[0].run_command('ip addr add ' + extra_ip + ' dev ' + extra_interface)

    def remove_interface():
        """ Delete interface """
        session_multihost.client[0].run_command('ip addr flush dev ' + extra_interface)
        session_multihost.client[0].run_command('ip link del ' + extra_interface)

    request.addfinalizer(remove_interface)
    return extra_interface, extra_ip


@pytest.mark.usefixtures("reverse_zone", "disable_dns_forwarders", "change_client_hostname")
@pytest.mark.dyndns
@pytest.mark.tier2
class TestDynDns(object):

    @staticmethod
    def test_0001_verify_with_default_setting(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: verify with default settings
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
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        ip = multihost.client[0].ip

        client.clear_sssd_cache()
        # Update function with IPV6 support is added to output what failed
        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip)

    @staticmethod
    def test_0002_verify_when_dyndns_update_set_to_false(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: verify when dyndns update set to false
        :id: 0cdbd0fe-4c67-4192-b44b-04e4227b5858
        :steps:
          1. Join client to AD domain and delete all client DNS records
          2. Perform DNS lookup for hostname
          3. Perform DNS lookup for IP
        :expectedresults:
          1. Client joins domain
          2. Hostname resolves incorrectly
          3. IP resolves incorrectly
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        ip = str(multihost.client[0].ip)

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_update': 'false'}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        client.clear_sssd_cache()
        assert dns.find_a(hostname, ip) is not True
        assert dns.find_ptr(hostname, ip) is not True

    @staticmethod
    def test_0003_verify_with_dyndns_ttl_functionality(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: verify with dyndns ttl functionality
        :id: ffb8ee9b-2a82-4917-82b0-d87fd066a24c
        :steps:
          1. Join client to AD domain and delete all client DNS records
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
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        ip = multihost.client[0].ip

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_update': 'true', 'dyndns_ttl': '9200'}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip)
        assert '9200' in dns.print_zone(domain)

    @staticmethod
    def test_0004_check_dyndns_iface_with_existing_interfaces(
            multihost, adjoin, extra_network, extra_interface):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check dyndns iface with existing interface
        :id: 166ee0a0-6f19-4be0-b5db-7373dde82862
        :steps:
          1. Join client to AD domain and delete all client DNS records
          2. Create extra interface
          3. Perform DNS lookup for hostname on extra interface
          4. Perform DNS lookup for IP on extra interface
        :expectedresults:
          1. Client joins domain
          2. Should succeed
          3. Hostname resolves correctly on extra interface
          4. IP resolves correctly on extra interface
        """
        adjoin(membersw='adcli')
        (extra_interface, extra_ip) = extra_interface
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        domain = multihost.ad[0].domainname
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        ip = multihost.client[0].ip

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_iface': extra_interface}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        dns.del_record(extra_ip)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, extra_ip)
        assert dns.find_ptr(hostname, extra_ip)
        assert ip not in dns.print_zone(domain)

    @staticmethod
    def test_0005_check_dyndns_iface_with_non_existing_interfaces(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check dyndns iface with non-existing interfaces
        :id: 412f684a-5a68-472d-86b1-93019bb53e6f
        :steps:
          1. Join client to AD domain and delete all client DNS records
          2. Perform DNS lookup for hostname on bogus interface
          3. Perform DNS lookup for IP on bogus interface
        :expectedresults:
          1. Client joins domain
          2. Hostname does not resolve correctly on bogus interface
          3. IP does not resolve correctly on bogus interface
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        ip = multihost.client[0].ip
        dns.del_record(hostname)
        dns.del_record(ip)

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_iface': 'non_existent'}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, ip) is not True
        assert dns.find_ptr(hostname, ip) is not True

    @staticmethod
    def test_0006_check_with_dyndns_refresh_interval(multihost, adjoin, extra_network, extra_interface):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check with dyndns refresh interval
        :id: 54765188-b21f-4ba1-890b-953eec9b696d
        :steps:
          1. Join client to AD domain and delete all client DNS records
          2. Create extra interface and assign IP
          3. Set refresh interval and dyndns iface in sssd.conf
          4. Perform DNS lookup for hostname on extra interface
          5. Perform DNS lookup for IP on extra interface
          6. Change IP on extra interface
          7. Let SSSD update DNS
          8. Perform DNS lookup for hostname on extra interface
          9. Perform DNS lookup for IP on extra interface
        :expectedresults:
          1. Client joins domain
          2. Should succeed
          3. Should succeed
          4. Hostname resolves correctly on extra interface
          5. IP resolves correctly on extra interface
          6. New IP address is assigned for extra interface
          7. SSSD updates DNS
          8. Hostname resolves correctly on extra interface with new IP
          9. IP resolves correctly on extra interface with new hostname
        """
        (extra_interface, extra_ip) = extra_interface
        extra_ip_after_refresh = '192.168.1.' + str(random.randrange(2, 255))
        while extra_ip == extra_ip_after_refresh:
            extra_ip_after_refresh = '192.168.1.' + str(random.randrange(2, 255))
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        ip = multihost.client[0].ip
        dns.del_record(hostname)
        dns.del_record(ip)

        adjoin(membersw='adcli')
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_refresh_interval': '81', 'dyndns_iface': extra_interface}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        assert dns.find_a(hostname, extra_ip)
        assert dns.find_ptr(hostname, extra_ip)

        multihost.client[0].run_command('ip addr flush dev ' + extra_interface)
        multihost.client[0].run_command('ip addr change ' + extra_ip_after_refresh + ' dev ' + extra_interface)
        time.sleep(83)

        assert dns.find_a(hostname, extra_ip_after_refresh)
        assert dns.find_ptr(hostname, extra_ip_after_refresh)

    @staticmethod
    def test_0007_set_dyndns_update_ptr_false_ptr_records_are_absent(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: set dyndns update ptr false ptr records are absent
        Will test parameter dyndns_update_ptr = false when no records exists
        NOTE: dyndns_refresh_interval lowest value is 60 seconds, with a 21 second timeout so the value is 81
        :id: e7bac85a-0504-4487-b26e-129a99121810
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Delete both A and PTR records
        3. Set dyndns_update_ptr = false in sssd.conf
        4. Start SSSD
        5. Use DNS to check the host and IP
        :expectedresults:
        1. Client joins domain
        2. Host records are removed from the DNS server
        3. SSSD is configured
        4. SSSD is started
        5. Host record can be resolved and the PTR record cannot
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname_cmd = multihost.client[0].run_command('hostname')
        hostname = hostname_cmd.stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        ip = multihost.client[0].ip

        dns.del_record(hostname)
        dns.del_record(ip)
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_refresh_interval': '81', 'dyndns_update_ptr': 'false'}
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip) is not True

    @staticmethod
    def test_0008_set_dyndns_update_ptr_to_false_ptr_records_are_present(
            multihost, adjoin, extra_interface, extra_network):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: set dyndns update ptr to false ptr records are present
        Will test parameter dyndns_update_ptr = false when records exits
        NOTE: dyndns_refresh_interval lowest value is 60 seconds, with a 21 second timeout so the value is 81
        :id: 7c96e4d2-b1da-4391-9a7c-ff632667b1bc
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Delete both A and PTR records
        3. Start SSSD
        4. Use DNS to check the host and IP
        5. Set dyndns_update_ptr = false and dyndns_refresh_interval = 81 in sssd.conf
        6. Update IP on extra interface and start SSSD
        7. Use DNS to check the host and IP
        :expectedresults:
        1. Client joins domain
        2. Host records are removed from the DNS server
        3. SSSD is started
        4. Host and IP is resolvable
        5. SSSD is stopped and sssd.conf has been updated
        6. IP on dummy has been changed
        7. Host and IP is resolvable but the PTR record is the old IP
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        (extra_int, ip) = extra_interface
        ptr = str(random.randrange(2, 255))
        while ptr == str(ip.split(".")[3]):
            ptr = str(random.randrange(2, 255))
        new_ip = str(ip.split(".")[0]) + "." + str(ip.split(".")[1]) + "." + str(ip.split(".")[2]) + "." + ptr

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_refresh_interval': '81', 'dyndns_update': 'true', 'dyndns_iface': extra_int}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        client.clear_sssd_cache()
        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip)

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_update_ptr': 'false'}
        client.sssd_conf(domain_section, sssd_params)
        multihost.client[0].run_command('ip addr flush dev ' + extra_int)
        multihost.client[0].run_command('ip link del ' + extra_int)
        multihost.client[0].run_command('ip link add ' + extra_int + ' type dummy')
        multihost.client[0].run_command('ip addr add ' + new_ip + ' dev ' + extra_int)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, new_ip)
        assert dns.find_ptr(hostname, ip)
        assert dns.find_ptr(hostname, new_ip) is not True

    @staticmethod
    def test_0009_check_with_dyndns_force_tcp(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check with dyndns force tcp
        Test SSSD to use TCP for dynamic DNS. Blocking all TCP traffic will test that no other protocols will
        be used to update DNS
        :id: 0de1b45c-cecb-451f-b625-823761f255b2
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Set ldap_purge_cache_timeout = 0, krb5_auth_timeout = 12, dyndns_force_tcp = true
        3. Update firewall to block TCP traffic on port 53
        4. Start SSSD
        5. Check DNS records
        6. Unblock traffic
        7. Check DNS records again
        :expectedresults:
        1. Client joins domain
        2. Configure SSSD
        3. Traffic is being blocked and dyndns is only using tcp
        4. SSSD starts
        5.  No A or PTR records exists
        6. Traffic is flowing
        7. DNS records are now updating properly
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname_cmd = multihost.client[0].run_command('hostname')
        hostname = hostname_cmd.stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        ip = multihost.client[0].ip

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'ldap_purge_cache_timeout': '0', 'krb5_auth_timeout': '12', 'dyndns_force_tcp': 'true'}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        multihost.client[0].run_command('which iptables || yum install -y iptables', raiseonerr=False)
        multihost.client[0].run_command(f'iptables -A INPUT -p tcp --dport 53 -s {multihost.ad[0].ip} -j DROP; '
                                        f'iptables -A OUTPUT -p tcp --dport 53 -d {multihost.ad[0].ip} -j DROP')
        client.clear_sssd_cache()
        assert dns.find_a(hostname, ip) is not True
        assert dns.find_ptr(hostname, ip) is not True

        multihost.client[0].run_command('iptables -F', raiseonerr=False)
        client.clear_sssd_cache()
        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip)

    @staticmethod
    def test_0010_check_with_combination_of_addresses(
            multihost, adjoin, extra_interface, extra_network):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: check with combination of addresses
        Check DynDNS when the client has several interfaces, testing that the right interface updates DNS.
        NOTE: The original test includes IPV6, however CI does not support IPV6, so this is done with just IPV4
        :id: fc7e3b4d-5cd3-4206-b16d-d90c96acca14
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Add extra interface and network
        3. Configure SSSD with dyndns_iface = extra_interface
        4. Start SSSD
        5. Check DNS records
        :expectedresults:
        1. Client joins domain
        2. Extra interface exists on client machine
        3. SSSD is configured
        4. SSSD starts
        5. DNS server will update with only the A and PTR records from the extra interface
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        (extra_int, extra_ip) = extra_interface
        ip = multihost.client[0].ip

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_iface': f'{extra_int}'}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        client.clear_sssd_cache()

        assert dns.find_a(hostname, extra_ip)
        assert dns.find_ptr(hostname, extra_ip)
        assert dns.find_ptr(hostname, ip) is not True

    @staticmethod
    def test_0011_verify_use_after_free_in_dyndns_code_bz1132361(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: verify use after free in dyndns code bz1132361
        bz1132361 is an OOM error that is recreated by
        setting TALLOC_FREE_FILL
        :id: 72d5e4ad-fdb9-4278-860f-57ff563a20d7
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Add extra interface
        3. Set TALLOC_FREE_FILL=253 in /etc/sysconfig/sssd
        4. Start SSSD
        :expectedresults:
        1. Client joins domain
        2. Extra interface is created
        3. Configuration files updated
        4. SSSD starts and does not segfault
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        multihost.client[0].run_command('echo "TALLOC_FREE_FILL=253" >> /etc/sysconfig/sssd')
        client.clear_sssd_cache()

        ps_cmd = multihost.client[0].run_command('ps aux | grep sssd')
        assert 'sssd_be' in ps_cmd.stdout_text
        assert 'sssd_nss' in ps_cmd.stdout_text
        assert 'sssd_pam' in ps_cmd.stdout_text
        assert 'sssd_pac' in ps_cmd.stdout_text
        multihost.client[0].run_command('sed -i "/TALLOC_FREE_FILL/d" /etc/sysconfig/sssd')

    @staticmethod
    def test_0012_set_dyndns_update_ptr_when_dyndns_server_equals_ad_server(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: dyndns: set dyndns update ptr when dyndns server equals ad server
        Testing parameter ad_server = $AD_SERVER
        :id: afa91b9b-4943-423a-a2e2-54f6c6204107
        :steps:
        1. Join client to AD domain and delete all client DNS records
        2. Configure SSSD to contain dyndns_server = AD_SERVER
        3. Start SSSD
        4. Check DNS records
        :expectedresults:
        1. Client joins domain
        2. SSSD is configured
        3. SSSD is started
        4. Both A and PTR records are found
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        dns = ADDNS(multihost.ad[0])
        hostname = multihost.client[0].run_command('hostname').stdout_text.rstrip()
        domain = multihost.ad[0].domainname
        adserver = multihost.ad[0].hostname
        ip = multihost.client[0].ip

        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'dyndns_server': f'{adserver}'}
        client.sssd_conf(domain_section, sssd_params)
        dns.del_record(hostname)
        dns.del_record(ip)
        client.clear_sssd_cache()
        assert dns.find_a(hostname, ip)
        assert dns.find_ptr(hostname, ip)

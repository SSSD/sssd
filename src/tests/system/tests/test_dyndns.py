"""
SSSD Dynamic DNS Test Cases

SSSD by default will update DNS records allowing the client to be resolvable by name. Updating PTR record by default
are enabled on AD and Samba but disabled by on IPA. These tests may omit IPA on these occasions.

For these tests to run, we have the following conditional forwarders configured in the dns container.
  - 10.255.250.0/24 for AD
  - 10.255.251.0/24 for IPA
  - 10.255.252.0/24 for Samba

The default interface 'eth0' is not used for testing. Instead, 'dummy0' interface is created on the client with
an IP in the correct subnet for the provider, Last octet 40 is used for the client, *.*.*.40. This allows us to test
dynamic DNS updates without affecting the default network configuration of the client and each provider can be
authoritative for their network.

Note the assertions, dig results can return multiple records, so we check that the expected record is in the results.

:requirement: dyndns
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.misc import ip_to_ptr
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


def create_ptr_zones(client: Client, provider: GenericProvider, device: str = "dummy0") -> None:
    """
    Create PTR zones.
    :param client: Client object.
    :type client: Client.
    :param provider: Provider object.
    :type provider: GenericProvider
    :param device: Network device name.
    :type device: str
    """
    provider.dns().clear_forwarders()
    ip_address = client.net.ip(device).address
    if ip_to_ptr(ip_address) not in provider.dns().list_zones():
        provider.dns().zone(ip_to_ptr(ip_address)).create()


def create_dummy_interface(
    client: Client, provider: GenericProvider, device: str | None = "dummy0"
) -> tuple[str, str | None]:
    """
    Create a dummy network interface on the client.
    :param client: Client object.
    :type client: Client.
    :param provider: GenericProvider object.
    :type provider: GenericProvider
    :param device: Name of the dummy network interface.
    :type device: str | None
    :return: IP and device name.
    :rtype: tuple[str, str | None]
    """
    if provider.server == "dc.ad.test":
        ip = "10.255.250.40"
        client.net.ip(device).add_device("10.255.250.40", "255.255.255.0")
    elif provider.server == "master.ipa.test":
        ip = "10.255.251.40"
        client.net.ip("dummy0").add_device("10.255.251.40", "255.255.255.0")
    elif provider.server == "dc.samba.test":
        ip = "10.255.252.40"
        client.net.ip("dummy0").add_device("10.255.252.40", "255.255.255.0")
    else:
        raise ValueError("Invalid provider server!")

    return ip, device


def check_records(client: Client, provider: GenericProvider, hostname: str) -> None:
    """
    Clean hostname records.
    :param client: Client object.
    :type client: Client.
    :param provider: GenericProvider object.
    :type provider: GenericProvider
    :param hostname: Hostname to clean A records for.
    :type hostname: str
    """
    records = client.net.dig(hostname, provider.server)
    if records is not None:
        for record in records:
            provider.dns().zone(provider.domain).delete_record(hostname.split(".")[0], record["data"])


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
def test_dyndns__enabled(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates all records
    :setup:
        1. Create dummy interface
        2. Create reverse zones
        3. Check for existing records
        4. Configure and start SSSD
    :steps:
        1. Lookup hostname
        2. Lookup ipv4 address
    :expectedresults:
        1. Hostname is found
        2. IP address is found
    customerscenario: True
    """
    short_hostname = client.net.hostname(short=True)
    hostname = f"{short_hostname}.{provider.domain}"
    ip, device = create_dummy_interface(client, provider)
    create_ptr_zones(client, provider)
    check_records(client, provider, hostname)
    client.sssd.common.dyndns()
    client.sssd.start()

    time.sleep(15)

    assert client.net.dig(hostname, provider.server), f"Host {hostname} was not found!"
    assert any(
        r["data"] == ip for r in client.net.dig(hostname, provider.server)
    ), f"Host {hostname} found with invalid ip!"

    assert client.net.dig(ip, provider.server), f"PTR record for {ip} was not found!"
    assert any(
        r["data"] == hostname for r in client.net.dig(ip, provider.server)
    ), f"Host {hostname} found with invalid ip!"



def test_dyndns__update_creates_forward_ipv4_records(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates IPV4 address only
    :description: SSSD should create records for network addresses that are on the client
    :setup:
       1. Remove IPV6 address from ethernet interface
       2. Create PTR zone for default network
       3. Start SSSD
    :steps:
       1. Check forward zone for client's A record
    :expectedresults:
       1. Client A record exists and is the only client record in the zone file
    :customerscenario: True
    """


def test_dyndns__updates_all_forward_records(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates AAAA records on all interfaces
    :description: SSSD should update all records if the IP changes
    :setup:
       1. Create PTR zone
       2.  A/AAAA/PTR records that DO NOT match the client's IP Address
       3. Start SSSD
    :steps:
       1. Check forward zone for client's A record
       2. Check forward zone for client's AAAA record
       3. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client A record exists in the zone file
       2. Client AAAA record exists in the zone file
       3. Client PTR record exists and points to the latest IP
    :customerscenario: True
    """


def test_dyndns__updates_all_forward_records(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates AAAA records on all interfaces
    :description: SSSD should update all records if the IP changes
    :setup:
       1. Create PTR zone
       2.  A/AAAA/PTR records that DO NOT match the client's IP Address
       3. Start SSSD
    :steps:
       1. Check forward zone for client's A record
       2. Check forward zone for client's AAAA record
       3. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client A record exists in the zone file
       2. Client AAAA record exists in the zone file
       3. Client PTR record exists and points to the latest IP
    :customerscenario: True
    """


def test_dyndns__update_is_disabled(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS is disabled
    :description: SSSD will not create any records on the DNS server
    :setup:
       1. Create PTR zone
       2. Set dyndns_update_ptr = false and dyndns_update = false in sssd.conf
       3. Start SSSD
    :steps:
       1. Check forward zone for client's A record
       2. Check reverse zone for client's PTR record
    :expectedresults:
       1. Client A record does not exist
       2. Client PTR record does not exist
    :customerscenario: True
    """


def test_dyndns__update_updates_ttl_settings_when_configured(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS will set the configured TTL value with the forward records
    :description: SSSD can update the DNS records with a custom Time-To-Live value
    :setup:
       1. Create PTR zone
       2. Set dyndns_ttl = 9200
       3. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
    :expectedresults:
       1. Client forward exists with the TTL set to 9200
    :customerscenario: true
    """


def test_dyndns__updates_multiple_interfaces(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS supports multiple interfaces
    :description: SSSD will update all available interfaces
    :setup:
       1. Create PTR zone
       2. Create bogus network interface on client
       3. Create PTR zone for bogus network matching bogus client interface
       4. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
       3. Check reverse zone for client's bogus interface pointer record
    :expectedresults:
       1. Client forward exists
       2. Client pointer record exist in zone file
       3. Client bogus pointer record exists in bogus network zone file
    :customerscenario: true
    """


def test_dyndns__updates_specific_interface(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS update specific interface
    :description: SSSD will update the DNS with the configured interface
    :setup:
       1. Create PTR zone
       2. Create bogus network interface on client
       3. Create PTR zone for bogus network matching bogus client interface
       4. Configure sssd with 'dyndns_iface = bogus interface'
       5. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
       3. Check reverse zone for client's bogus interface pointer record
    :expectedresults:
       1. Client forward exists
       2. Client pointer record does not exist in primary network zone file
       3. Client bogus pointer record exists in bogus network zone file
    :customerscenario: true
    """


def test_dyndns__updates_at_configured_interval(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates at configured interval
    :description: SSSD will update the DNS server at the configured timed interval
    :setup:
       1. Create PTR zone
       2. Configure sssd with 'dyndns_refresh_interval = X'
       3. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Delete A record
       3. Check forward zone for client's A record
       4. Wait X seconds and check for client's A record
    :expectedresults:
       1. Client A record exists
       2. A record is deleted
       3. Client A record does not exist
       4. Client's A record exists
    :customerscenario: true
    """


def test_dyndns__updates_works_over_tcp_only(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates works with TCP only
    :description: SSSD will update the DNS server using TCP only, instead requiring UDP as well
    :setup:
       1. Create PTR zone
       2. Configure SSSD with ldap_purge_cache_timeout = 0, krb5_auth_timeout = 12, dyndns_force_tcp = true
       3. Block all UDP traffic from client
       4. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client A record exists
       2. Client PTR record exists
    :customerscenario: true
    """


def test_dyndns__updates_works_using_insecure_nsupdate(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates using nsupdate instead of gss-tsig
    :description: SSSD can update DNS using insecure nsupdate
    :stup:
       1. Create PTR zone
       2. Disable secure updates for forward and reverse zones
       3. Configure sssd with dyndns_auth = None
       4. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client A record exists
       2. Client PTR record exists
    :customerscenario: true
    """


def test_dyndns__secure_updates_works_using_tsig(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS updates using gss-tsig only
    :description: SSSD can update DNS using tsig
    :setup:
       1. Create PTR zone
       2. Disable secure updates for forward and reverse zones
       3. Configure sssd zone allowing tsig updates only
       4. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client A record exists
       2. Client PTR record exists
    :customerscenario: true
    """


def test_dyndns__insecure_updates_do_not_work_using_tsig(client: Client, provider: GenericProvider):
    """
    :title: Insecure dynamic DNS updates do not work using gss-tsig
    :description: SSSD cannot update DNS using nsupdate when the server only expects tsig
    :setup:
       1. Create PTR zone
       2. Disable secure updates for forward and reverse zones
       3. Configure sssd zone allowing tsig updates only
       4. Start SSSD
    :steps:
       1. Check forward zone for client's forward record
       2. Check reverse zone for client's pointer record
    :expectedresults:
       1. Client records do not exist
       2. Client records do not exist
    :customerscenario: true
    """


def test_dyndns__updates_an_external_dns_server_with_a_non_integrated_zone_file(
    client: Client, provider: GenericProvider
):
    """
    :TODO: Not supported ATM
    :title: Dynamic DNS updates an external DNS server
    :description: SSSD updates a third-party DNS server with a non-integrated zone file

    A lot of customers use a third-party DNS like infoblox. I'm not that familiar with the product to determine, if we setup a test to update bind/dnsmasq or even IPA, just not the realm DNS server

    :setup:
    :steps:
    :expectedresults:
    :customerscenario: true
    """

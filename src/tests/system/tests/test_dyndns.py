"""
SSSD Dynamic DNS Test Cases

SSSD supports dynamic DNS updates, allowing the client to automatically register itself so it can be
resolved by name. This feature is enabled by default with the 'ad_provider', which creates the DNS record
when SSSD starts. In contrast, the 'ipa_provider' has dynamic DNS updates disabled, since the record is
already created during the initial 'ipa-client-install'.

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
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
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
    address = client.net.ip(device).addresses
    for i in address:
        if i is not None and ip_to_ptr(i) not in provider.dns().list_zones():
            provider.dns().zone(ip_to_ptr(i)).create()


def create_dummy_interface(
    client: Client, provider: GenericProvider, device: str | None = "dummy0", ipv6: str = "2001:db8::1"
) -> tuple[str, str | None, str | None]:
    """
    Create a dummy network interface on the client.
    :param client: Client object.
    :type client: Client.
    :param provider: GenericProvider object.
    :type provider: GenericProvider
    :param device: Name of the dummy network interface.
    :type device: str | None
    :param ipv6: IPv6 address, optional
    :type ipv6: str, default 2001:db8::1
    :return: IP, IP6, and device name.
    :rtype: tuple[str, str | None, str | None]
    """
    if isinstance(provider, AD):
        ip = "10.255.250.40"
    elif isinstance(provider, IPA):
        ip = "10.255.251.40"
    elif isinstance(provider, Samba):
        ip = "10.255.252.40"
    else:
        raise ValueError("Invalid provider!")

    client.net.ip(device).add_device(ip)

    return ip, None, device


def check_records(client: Client, provider: GenericProvider, hostname: str, device: str = "dummy0") -> None:
    """
    Clean host dns records and restart services.

    :description: This helper method is mostly for IPA since there guaranteed to have a forward record.
    :param client: Client object.
    :type client: Client.
    :param provider: GenericProvider object.
    :type provider: GenericProvider
    :param hostname: Hostname to clean A and PTR records for.
    :type hostname: str
    :param device: Name of the dummy network interface.
    :type device: str, default "dummy0"
    """
    dns_zone = provider.dns().zone(provider.domain)
    a_records = client.net.dig(hostname, provider.server, attempts=2, delay=2)
    ptr_records = []

    for i in client.net.ip(device).addresses:
        if i is not None:
            records = client.net.dig(i, provider.server, attempts=2, delay=2)
            if records is not None:
                ptr_records.extend(records)

    if a_records is not None or ptr_records:
        if a_records is not None:
            for record in a_records:
                dns_zone.delete_record(record["name"])

        if ptr_records:
            for record in ptr_records:
                dns_zone.delete_record(record["data"])

        if isinstance(provider, IPA):
            provider.host.conn.run("ipactl restart")
        elif isinstance(provider, AD):
            provider.host.conn.run("Restart-Service -Name NTDS -Force")
        elif isinstance(provider, Samba):
            provider.host.conn.run("systemctl restart samba")
        else:
            raise ValueError("Invalid provider!")


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
def test_dyndns__update_is_set_to_true(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS update is set to true
    :setup:
        1. Create a dummy interface
        2. Create reverse zones
        3. Check for existing records, clean if found
        4. Configure and start SSSD
    :steps:
        1. Lookup hostname
        2. Lookup ipv4 address
    :expectedresults:
        1. Hostname is found
        2. IP address is found
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    create_ptr_zones(client, provider)
    check_records(client, provider, hostname)
    client.sssd.common.dyndns()
    client.sssd.start()

    a_records = client.net.dig(hostname, provider.server)
    assert a_records, f"Host {hostname} was not found!"
    assert any(r["data"] == ip for r in a_records), f"Host {hostname} found with invalid ip!"

    ptr_records = client.net.dig(ip, provider.server)
    assert ptr_records, f"PTR record for {ip} was not found!"
    assert any(r["data"] == hostname for r in ptr_records), f"IP {ip} found pointing to the wrong hostname!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
def test_dyndns__update_is_set_to_false(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS is disabled
    :setup:
        1. Create a dummy interface
        2. Create reverse zones
        3. Check for existing records
        4. Configure and start SSSD with dyndns_update = False and dyndns_update_ptr = False
    :steps:
        1. Lookup hostname
        2. Lookup ipv4 address
    :expectedresults:
        1. Hostname is not found
        2. IP address is not found
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    create_ptr_zones(client, provider)
    check_records(client, provider, hostname)
    client.sssd.common.dyndns()

    client.sssd.domain["dyndns_update"] = "False"
    client.sssd.domain["dyndns_update_ptr"] = "False"
    client.sssd.start()

    assert client.net.dig(hostname, provider.server, attempts=2, delay=2) is None, f"Host {hostname} was found!"
    assert client.net.dig(ip, provider.server, attempts=2, delay=2) is None, f"PTR record for {ip} was found!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
@pytest.mark.parametrize(
    "interfaces",
    [("eth0", False), ("eth0, dummy0", True)],
    ids=["dyndns_iface = eth0", "dyndns_iface = eth0, dummy0"],
)
def test_dyndns__update_with_address_filtering(
    client: Client, provider: GenericProvider, interfaces: tuple[str, bool]
):
    """
    :title: Dynamic DNS updates filtered address

    If dyndns_iface is not set, it defaults to the interface that SSSD uses to communicate with the provider,
    in this case 'eth0'. Only when the filtered IP, when the device is specified 'dummy0', dns will update.

    :setup:
        1. Create dummy interfaces
        2. Check for existing records
        3. Configure SSSD and specify one ip to filter and start
    :steps:
        1. Look up record
    :expectedresults:
        1. Hostname is found only when 'dummy0' is configured
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    check_records(client, provider, hostname)

    client.sssd.domain["dyndns_update"] = "True"
    client.sssd.domain["dyndns_update_ptr"] = "True"
    client.sssd.domain["dyndns_refresh_interval"] = "1"
    client.sssd.domain["dyndns_refresh_interval_offset"] = "5"
    client.sssd.domain["dyndns_address"] = f"{'.'.join(ip.split('.')[:-1] + ['0'])}/24"
    client.sssd.domain["dyndns_iface"] = interfaces[0]
    client.sssd.start()

    if interfaces[-1]:
        a_records = client.net.dig(hostname, provider.server)
        assert a_records, f"Host {hostname} was not found!"
        assert any(r["data"] == ip for r in a_records), f"Host {hostname} found with invalid ip!"
    else:
        assert client.net.dig(hostname, provider.server, attempts=2, delay=2) is None, f"Host {hostname} was found!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
def test_dyndns__update_configured_ttl_value(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS update creates record with configured TTL value
    :setup:
        1. Create a dummy interface
        2. Create reverse zones
        3. Check for existing records, clean if found
        4. Configure 'dyndns_ttl' and start SSSD
    :steps:
        1. Lookup hostname
    :expectedresults:
        1. Hostname is found with specified TTL value
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    check_records(client, provider, hostname)
    client.sssd.common.dyndns()
    client.sssd.domain["dyndns_ttl"] = "9999"
    client.sssd.start()

    a_records = client.net.dig(hostname, provider.server)
    assert a_records, f"Host {hostname} was not found!"
    assert any(r["data"] == ip for r in a_records), f"Host {hostname} found with invalid ip!"
    assert "9999" == str(a_records[0]["ttl"]), "TTL was not set to 9999!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
def test_dyndns__update_over_tcp_only(client: Client, provider: GenericProvider):
    """
    :title: Dynamic DNS update is configured to use TCP only
    :setup:
        1. Create a dummy interface
        2. Check for existing records, clean if found
        3. Configure 'dyndns_force_tcp = True' and start SSSD
    :steps:
        1. Wait 15 seconds and check the logs
    :expectedresults:
        1. Logs contain message indicating that TCP is set to on
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    check_records(client, provider, hostname)

    client.sssd.common.dyndns()
    client.sssd.domain["dyndns_force_tcp"] = "True"
    client.sssd.start()

    # This was changed from a functional system test to a sanity test that asserts the logs.
    # NSUpdate failed connect in CI over the TCP but does work locally. The sleep is required
    # allow nsupdate to run.

    time.sleep(15)
    logs = client.fs.read(client.sssd.logs.domain())
    assert "TCP is set to on" in logs, "No message indicating that tcp nsupdate is on!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
@pytest.mark.parametrize(
    "auth_mech",
    [("None", 1), ("GSS-TSIG", 0)],
    ids=["dyndns_auth = None", "dyndns_auth = GSS-TSIG"],
)
def test_dyndns__update_authentication_mechanism(
    client: Client, provider: GenericProvider, auth_mech: tuple[str, int]
):
    """
    :title: Dynamic DNS updates authentication mechanism
    :setup:
        1. Create dummy interfaces
        2. Check for existing records
        3. Configure and start SSSD
    :steps:
        1. Look up record
    :expectedresults:
        1. Hostname is found only when GSS-TSIG is configured
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    check_records(client, provider, hostname)

    client.sssd.common.dyndns()
    client.sssd.domain["dyndns_auth"] = auth_mech[0]
    client.sssd.start()

    if auth_mech[-1] == 0:
        a_records = client.net.dig(hostname, provider.server)
        assert a_records, f"Host {hostname} was not found!"
        assert any(r["data"] == ip for r in a_records), f"Host {hostname} found with invalid ip!"
    elif auth_mech[-1] == 1:
        assert client.net.dig(hostname, provider.server) is None, f"Host {hostname} was found!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.importance("critical")
@pytest.mark.ticket(bz=1132361)
def test_dyndns__update_does_not_contain_use_after_free_bugs(client: Client, provider: GenericProvider):
    """
    :title: Prevent use-after-free during DNS updates
    :description:
        Ensures the dyndns update code does not contain use-after-free bugs that manifest
        under low memory conditions (TALLOC_FREE_FILL).
    :setup:
        1. Create a dummy interface
        2. Create reverse zones
        3. Check for existing records, clean if found
        4. Configure 'talloc_free_fill=253' to force error
        5. Configure and start SSSD
    :steps:
        1. Lookup hostname
        2. Lookup ipv4 address
    :expectedresults:
        1. Hostname is found
        2. IP address is found
    :customerscenario: True
    """
    hostname = client.hostnameutils.fqdn
    ip, _, _ = create_dummy_interface(client, provider)

    create_ptr_zones(client, provider)
    check_records(client, provider, hostname)

    client.fs.backup("/etc/sysconfig/sssd")
    client.fs.append("/etc/sysconfig/sssd", "TALLOC_FREE_FILL=253")

    client.sssd.common.dyndns()
    client.sssd.start()

    a_records = client.net.dig(hostname, provider.server)
    assert a_records, f"Host {hostname} was not found!"
    assert any(r["data"] == ip for r in a_records), f"Host {hostname} found with invalid ip!"

    ptr_records = client.net.dig(ip, provider.server)
    assert ptr_records, f"PTR record for {ip} was not found!"
    assert any(r["data"] == hostname for r in ptr_records), f"IP {ip} found pointing to the wrong hostname!"

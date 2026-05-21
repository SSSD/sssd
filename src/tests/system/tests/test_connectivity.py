"""
SSSD Connectivity tests.

:requirement: Failover
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.parametrize("value, expected", [(None, 31), (15, 31), (60, 60)])
@pytest.mark.importance("low")
@pytest.mark.ticket(gh=7375, jira="RHEL-17659")
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_connectivity__failover_reactivation_timeout_is_honored(
    client: Client, provider: GenericProvider, value: int | None, expected: int
):
    """
    :title: Primary server reactivation timeout is honored
    :setup:
        1. Create user "user-1"
        2. Set failover_primary_timeout to @value
        3. Set server/URI to an invalid server
        4. Set backup server/URI to the server
        5. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to the backup server
        3. Find "Primary server reactivation timeout set to @expected seconds" in domain logs
    :expectedresults:
        1. User is found
        2. SSSD is connected to the backup server
        3. String is found
    :customerscenario: True
    """
    provider.user("user-1").add()

    if value is not None:
        client.sssd.domain["failover_primary_timeout"] = str(value)
    client.sssd.set_invalid_primary_server(provider)
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    # Lookup user to make sure SSSD did correctly failover to the backup server
    result = client.tools.id("user-1")
    assert result is not None, "User is not found!"

    # Check that SSSD is indeed connected to the backup server
    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert provider.host.hostname in status.stdout, f"{provider.host.hostname} is not found in domain status!"

    # Check that primary server reactivation timeout was correctly created
    log = client.fs.read(client.sssd.logs.domain())
    assert (
        f"Primary server reactivation timeout set to {expected} seconds" in log
    ), f"'Primary server reactivation timeout set to {expected} seconds' not found in logs!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_connectivity__failover_to_ipv4_when_ipv6_unavailable(client: Client, provider: GenericProvider):
    """
    :title: Make sure that we can connect using secondary protocol
    :setup:
        1. Create user
        2. Set family_order to "ipv6_first"
        3. Set IPv6 address in /etc/hosts so it resolves but it
           points to non-exesting machine
        4. Start SSSD
    :steps:
        1. Resolve user
    :expectedresults:
        1. SSSD goes online and the user is resolved
    :customerscenario: False
    """
    user = provider.user("testuser").add()
    client.sssd.domain["lookup_family_order"] = "ipv6_first"
    client.fs.append("/etc/hosts", "cafe:cafe::3 %s" % provider.host.hostname)
    client.sssd.start()

    result = client.tools.id(user.name)
    assert result is not None, f"{user.name} was not found, SSSD did not switch to IPv4 family!"


# We do not authenticate the host on LDAP provider
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2466974)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.IPA)
def test_connectivity__sssd_goes_offline_when_kerberos_is_unreachable(client: Client, provider: GenericProvider):
    """
    :title: SSSD goes offline when Kerberos authentication fails
    :setup:
        1. Create user
        2. Block outbound port 88 (Kerberos)
        3. Start SSSD
    :steps:
        1. Try to resolve user
        2. Check domain status
    :expectedresults:
        1. User is not found
        2. SSSD is offline
    :customerscenario: False
    """
    user = provider.user("testuser").add()
    client.firewall.outbound.drop_port((88, "tcp"))
    client.firewall.outbound.drop_port((88, "udp"))
    client.sssd.start()

    # Make sure SSSD tries to connect
    result = client.tools.id(user.name)
    assert result is None, f"{user.name} was found, SSSD is not offline!"

    # SSSD was not able to connect. But check that it was actually set to offline internal state.
    assert client.sssd.default_domain is not None, "No default domain?"
    status = client.sssctl.domain_status(client.sssd.default_domain, online=True)
    assert "Offline" in status.stdout, "SSSD is not offline!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_connectivity__sssd_goes_offline_when_ldap_is_unreachable(client: Client, provider: GenericProvider):
    """
    :title: SSSD goes offline when LDAP connection fails
    :setup:
        1. Create user
        2. Block outbound port 389 (LDAP)
        3. Start SSSD
    :steps:
        1. Try to resolve user
        2. Check domain status
    :expectedresults:
        1. User is not found
        2. SSSD is offline
    :customerscenario: False
    """
    user = provider.user("testuser").add()
    client.firewall.outbound.drop_port((389, "tcp"))
    client.sssd.start()

    # Make sure SSSD tries to connect
    result = client.tools.id(user.name)
    assert result is None, f"{user.name} was found, SSSD is not offline!"

    # SSSD was not able to connect. But check that it was actually set to offline internal state.
    assert client.sssd.default_domain is not None, "No default domain?"
    status = client.sssctl.domain_status(client.sssd.default_domain, online=True)
    assert "Offline" in status.stdout, "SSSD is not offline!"

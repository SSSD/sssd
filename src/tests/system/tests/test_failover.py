"""
SSSD Failover tests.

:requirement: Failover
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.parametrize("value, expected", [(None, 31), (15, 31), (60, 60)])
@pytest.mark.importance("low")
@pytest.mark.ticket(gh=7375, jira="RHEL-17659")
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_failover__reactivation_timeout_is_honored(
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

    client.sssd.enable_responder("ifp")

    if isinstance(provider, LDAP):
        client.sssd.domain["ldap_uri"] = "ldap://ldap.invalid"
        client.sssd.domain["ldap_backup_uri"] = f"ldap://{provider.host.hostname}"

    if isinstance(provider, AD):
        client.sssd.domain["ad_server"] = "invalid.ad.test"
        client.sssd.domain["ad_backup_server"] = f"{provider.host.hostname}"

    if isinstance(provider, Samba):
        client.sssd.domain["ad_server"] = "invalid.samba.test"
        client.sssd.domain["ad_backup_server"] = f"{provider.host.hostname}"

    if isinstance(provider, IPA):
        client.sssd.domain["ipa_server"] = "invalid.ipa.test"
        client.sssd.domain["ipa_backup_server"] = f"{provider.host.hostname}"

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
def test_failover__connect_using_ipv4_second_family(client: Client, provider: GenericProvider):
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

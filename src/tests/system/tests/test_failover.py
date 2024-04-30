"""
SSSD Failover tests.

:requirement: Failover
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.parametrize("value, expected", [(None, 31), (15, 31), (60, 60)])
@pytest.mark.importance("low")
@pytest.mark.ticket(gh=7375, jira="RHEL-17659")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__retry_primary(client: Client, ldap: LDAP, value: int | None, expected: int):
    """
    :title: Primary server reactivation timeout is respected
    :setup:
        1. Create LDAP user "user-1"
        2. Set failover_primary_timeout to @value
        3. Set ldap_uri to invalid, not working server
        4. Set ldap_backup_uri to working server
        5. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to backup server
        3. Find "Primary server reactivation timeout set to @expected seconds" in domain logs
    :expectedresults:
        1. SSSD failover to backup server
        2. SSSD is indeed connected to the backup server
        3. String is found
    :customerscenario: True
    """
    ldap.user("user-1").add()

    if value is not None:
        client.sssd.domain["failover_primary_timeout"] = str(value)

    client.sssd.enable_responder("ifp")
    client.sssd.domain["ldap_uri"] = "ldap://ldap.invalid"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://{ldap.host.hostname}"
    client.sssd.start()

    # Lookup user to make sure SSSD did correctly failover to backup server
    result = client.tools.id("user-1")
    assert result is not None

    # Check that SSSD is indeed connected to backup server
    assert client.sssd.default_domain is not None
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ldap.host.hostname in status.stdout

    # Check that primary server reactivation timeout was correctly created
    log = client.fs.read(client.sssd.logs.domain())
    assert f"Primary server reactivation timeout set to {expected} seconds" in log

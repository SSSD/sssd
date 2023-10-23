"""
Automation of offline tests

:requirement: offline
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.ticket(bz=1416150)
@pytest.mark.topology(KnownTopology.LDAP)
def test_offline__ldap_log_to_syslog(client: Client):
    """
    :title: Log to syslog when sssd cannot contact servers goes offline
    :setup:
        1. Set an invalid hostname uri and disable the offset to refresh sudo rules
        2. Start SSSD
    :steps:
        1. Check domain status for default domain
        2. Clear journal and restart SSSD
        3. Check journalctl
    :expectedresults:
        1. Domain is offline
        2. Succeed
        3. "Backend is offline" found
    :customerscenario: True
    """
    client.sssd.domain["ldap_uri"] = "ldaps://typo.invalid"
    client.sssd.domain["ldap_sudo_random_offset"] = "0"
    client.sssd.start()
    assert client.sssd.default_domain is not None, "Failed to load default domain"
    status = client.sssctl.domain_status(client.sssd.default_domain)
    assert "Offline" in status.stdout or "Unable to get online status" in status.stderr, "Domain is not offline"

    client.journald.clear()
    client.sssd.restart()
    time.sleep(1)

    log = client.journald.journalctl(grep="Backend is offline", unit="sssd")
    assert log.rc == 0, "'Backend is offline' is not logged"


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1928648)
@pytest.mark.topology(KnownTopology.LDAP)
def test_offline__ldap_network_timeout_parameters_shown_in_logs(client: Client, ldap: LDAP):
    """
    :title: Each timeout setting is properly logged in logs
    :setup:
        1. Add user
        2. Start SSSD
    :steps:
        1. Check that "Setting 6 seconds timeout [ldap_network_timeout] for connecting" is in logs
        2. Fetch information about user
        3. Block LDAP traffic
        4. Connect user over SSH
        5. Logs should contain following timeout parameters
             - ldap_opt_timeout
             - ldap_search_timeout
             - ldap_network_timeout
             - dns_resolver_timeout
    :expectedresults:
        1. Timeout setting is stored in logs
        2. User is found
        3. LDAP traffic is blocked
        4. User is unable to connect
        5. The timeout parameters are in the logs
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    client.sssd.start()

    log = client.fs.read(f"/var/log/sssd/sssd_{client.sssd.default_domain}.log")
    assert "Setting 6 seconds timeout [ldap_network_timeout] for connecting" in log

    assert client.tools.id("user1") is not None

    client.firewall.outbound.drop_host(ldap)

    with pytest.raises(Exception):
        client.ssh("user1", "Secret123").connect()

    log = client.fs.read(f"/var/log/sssd/sssd_{client.sssd.default_domain}.log")
    for timeout in ["ldap_opt_timeout", "ldap_search_timeout", "ldap_network_timeout", "dns_resolver_timeout"]:
        assert timeout in log, f"Value '{timeout}' not found in logs"

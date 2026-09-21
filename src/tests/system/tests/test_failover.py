"""
SSSD Failover tests.

:requirement: Failover
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
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


# We do not authenticate the host on LDAP provider
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2466974)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.IPA)
def test_failover__go_offline_if_kinit_fails(client: Client, provider: GenericProvider):
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
def test_failover__go_offline_if_ldap_fails(client: Client, provider: GenericProvider):
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


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1283798)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_failover__login_via_backup_when_primary_is_unavailable(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: User login succeeds via backup server when primary is unavailable
    :setup:
        1. Create user "user-1"
        2. Set primary server to an invalid (unreachable) server
        3. Set backup server to the real provider
        4. Start SSSD
    :steps:
        1. Login as user-1
        2. Check that SSSD is connected to the backup server
    :expectedresults:
        1. User can login via the backup server
        2. SSSD is connected to the backup server
    :customerscenario: True
    """
    provider.user("user-1").add(password="Secret123")
    client.sssd.set_invalid_primary_server(provider)
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user-1", "Secret123"
    ), "User login failed, failover to backup server did not work!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert provider.host.hostname in status.stdout, f"SSSD is not connected to backup server {provider.host.hostname}!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__primary_uri_list_falls_back_to_next_uri(client: Client, ldap: LDAP):
    """
    :title: Failover moves to the next URI in the primary list when the first one refuses the connection
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to a reachable host that does not run LDAP, followed by the LDAP server
        3. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to the LDAP server
        3. Expire the cache and lookup user-1 again
    :expectedresults:
        1. User is found
        2. SSSD is connected to the LDAP server
        3. User is found, the lookup is served over the surviving connection
    :customerscenario: False
    """
    ldap.user("user-1").add()
    # The client host resolves but has no LDAP server listening, so the connection is refused.
    client.sssd.domain["ldap_uri"] = f"ldap://{client.host.hostname},ldap://{ldap.host.hostname}"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ldap.host.hostname in status.stdout, f"SSSD is not connected to {ldap.host.hostname}!"

    client.sssctl.cache_expire(everything=True)
    assert client.tools.id("user-1") is not None, "User is not found after the cache was expired!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__backup_uri_list_falls_back_to_next_uri(client: Client, ldap: LDAP):
    """
    :title: Failover moves to the next URI in the backup list when the first backup URI is unusable
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to an invalid server
        3. Set ldap_backup_uri to a reachable host that does not run LDAP, followed by the LDAP server
        4. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to the LDAP server
        3. Expire the cache and lookup user-1 again
    :expectedresults:
        1. User is found
        2. SSSD is connected to the LDAP server
        3. User is found, the lookup is served over the surviving connection
    :customerscenario: False
    """
    ldap.user("user-1").add()
    client.sssd.domain["ldap_uri"] = f"ldap://invalid.{ldap.domain}"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://{client.host.hostname},ldap://{ldap.host.hostname}"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ldap.host.hostname in status.stdout, f"SSSD is not connected to {ldap.host.hostname}!"

    client.sssctl.cache_expire(everything=True)
    assert client.tools.id("user-1") is not None, "User is not found after the cache was expired!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__empty_primary_uri_falls_back_to_service_discovery(client: Client, ldap: LDAP):
    """
    :title: Empty primary URI list defaults to service discovery
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to an empty value
        3. Start SSSD
    :steps:
        1. Find "No primary servers defined, using service discovery" in domain logs
        2. Lookup user-1
    :expectedresults:
        1. String is found
        2. User is found via the server located by service discovery
    :customerscenario: False
    """
    ldap.user("user-1").add()
    client.sssd.domain["ldap_uri"] = ""
    client.sssd.start(check_config=False)

    log = client.fs.read(client.sssd.logs.domain())
    assert (
        "No primary servers defined, using service discovery" in log
    ), "Empty primary URI list did not fall back to service discovery!"

    assert client.tools.id("user-1") is not None, "User is not found!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__srv_in_backup_uri_is_rejected(client: Client, ldap: LDAP):
    """
    :title: Service discovery is not allowed in the backup URI list
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to the LDAP server
        3. Set ldap_backup_uri to "_srv_"
        4. Start SSSD
    :steps:
        1. Find "SRV resolution only allowed for primary servers" in domain logs
        2. Lookup user-1
    :expectedresults:
        1. String is found
        2. User is found via the primary server
    :customerscenario: False
    """
    ldap.user("user-1").add()
    client.sssd.domain["ldap_uri"] = f"ldap://{ldap.host.hostname}"
    client.sssd.domain["ldap_backup_uri"] = "_srv_"
    client.sssd.start()

    log = client.fs.read(client.sssd.logs.domain())
    assert "SRV resolution only allowed for primary servers" in log, "'_srv_' in the backup URI list was not rejected!"

    assert client.tools.id("user-1") is not None, "User is not found!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__primary_uri_list_ending_with_srv_falls_back_to_backup(client: Client, ldap: LDAP):
    """
    :title: Failover reaches the backup URI when every primary URI including service discovery fails
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to two invalid servers followed by "_srv_"
        3. Set dns_discovery_domain to a domain that has no LDAP SRV record, so service discovery fails
        4. Set ldap_backup_uri to the LDAP server
        5. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to the LDAP server
        3. Expire the cache and lookup user-1 again
    :expectedresults:
        1. User is found
        2. SSSD is connected to the backup server
        3. User is found, the lookup is served by the backup server
    :customerscenario: False
    """
    ldap.user("user-1").add()
    client.sssd.domain["ldap_uri"] = f"ldap://invalid1.{ldap.domain},ldap://invalid2.{ldap.domain},_srv_"
    # The LDAP topology publishes _ldap._tcp.ldap.test, so service discovery would otherwise
    # succeed and the backup URI would never be reached. Point discovery at a domain that has
    # no SRV record to make the last primary URI fail as well.
    client.sssd.domain["dns_discovery_domain"] = "no-such-srv.test"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://{ldap.host.hostname}"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ldap.host.hostname in status.stdout, f"SSSD is not connected to backup server {ldap.host.hostname}!"

    client.sssctl.cache_expire(everything=True)
    assert client.tools.id("user-1") is not None, "User is not found after the cache was expired!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=921259)
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__empty_element_in_primary_uri_list_is_ignored(client: Client, ldap: LDAP):
    """
    :title: An empty element in the primary URI list is ignored
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to an invalid server, an empty element and the LDAP server
        3. Start SSSD
    :steps:
        1. Lookup user-1
        2. Login as user-1
    :expectedresults:
        1. User is found, the empty element did not break the primary server list
        2. User can login
    :customerscenario: True
    """
    ldap.user("user-1").add(password="Secret123")
    client.sssd.domain["ldap_uri"] = f"ldap://invalid.{ldap.domain}, ,ldap://{ldap.host.hostname}"
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"
    assert client.auth.ssh.password("user-1", "Secret123"), "User login failed!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=921259)
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__empty_element_in_backup_uri_list_is_ignored(client: Client, ldap: LDAP):
    """
    :title: An empty element in the backup URI list is ignored
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to two invalid servers so that the backup list is reached
        3. Set ldap_backup_uri to an invalid server, an empty element and the LDAP server
        4. Start SSSD
    :steps:
        1. Lookup user-1
        2. Login as user-1
        3. Check that SSSD is connected to the LDAP server
    :expectedresults:
        1. User is found, the empty element did not break the backup server list
        2. User can login
        3. SSSD is connected to the backup server
    :customerscenario: True
    """
    ldap.user("user-1").add(password="Secret123")
    client.sssd.domain["ldap_uri"] = f"ldap://invalid1.{ldap.domain},ldap://invalid2.{ldap.domain}"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://invalid-backup.{ldap.domain}, ,ldap://{ldap.host.hostname}"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"
    assert client.auth.ssh.password("user-1", "Secret123"), "User login failed!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ldap.host.hostname in status.stdout, f"SSSD is not connected to backup server {ldap.host.hostname}!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__backup_uri_accepts_ip_address(client: Client, ldap: LDAP):
    """
    :title: Backup URI given as an IP address is used for failover
    :setup:
        1. Create user "user-1"
        2. Resolve the LDAP server IPv4 address
        3. Set ldap_uri to an invalid server
        4. Set ldap_backup_uri to the LDAP server IP address
        5. Disable TLS certificate checks
        6. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check that SSSD is connected to the backup server
    :expectedresults:
        1. User is found
        2. SSSD is connected to the backup server
    :customerscenario: False
    """
    ldap.user("user-1").add()

    result = client.host.conn.run(f"getent ahostsv4 {ldap.host.hostname}", raise_on_error=False)
    assert result.rc == 0, f"Unable to resolve {ldap.host.hostname}!"
    assert result.stdout, f"No IPv4 address returned for {ldap.host.hostname}!"
    ip = result.stdout.split()[0]

    client.sssd.domain["ldap_uri"] = f"ldap://invalid.{ldap.domain}"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://{ip}"
    # The server certificate is issued for the hostname and can never match a bare IP
    # address. The URI is what is under test here, not certificate validation.
    client.sssd.domain["ldap_tls_reqcert"] = "never"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert ip in status.stdout, f"SSSD is not connected to backup server {ip}!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=845251)
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__unresolvable_hostname_does_not_stop_failover(client: Client, ldap: LDAP):
    """
    :title: SSSD tries the next server when a hostname cannot be resolved
    :setup:
        1. Create user "user-1"
        2. Set ldap_uri to an unresolvable hostname followed by the LDAP server
        3. Set ldap_backup_uri to an unresolvable hostname
        4. Start SSSD
    :steps:
        1. Lookup user-1
        2. Login as user-1
        3. Check that SSSD is connected to the LDAP server
    :expectedresults:
        1. User is found
        2. User can login
        3. SSSD skipped the unresolvable hostname and connected to the LDAP server
    :customerscenario: True
    """
    unresolvable = f"unresolvable.{ldap.domain}"

    ldap.user("user-1").add(password="Secret123")
    client.sssd.domain["ldap_uri"] = f"ldap://{unresolvable},ldap://{ldap.host.hostname}"
    client.sssd.domain["ldap_backup_uri"] = f"ldap://unresolvable-backup.{ldap.domain}"
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.enable_responder("ifp")
    client.sssd.start()

    assert client.tools.id("user-1") is not None, "User is not found!"
    assert client.auth.ssh.password("user-1", "Secret123"), "User login failed!"

    assert client.sssd.default_domain is not None, "Default domain is not set!"
    status = client.sssctl.domain_status(client.sssd.default_domain, active=True)
    assert (
        ldap.host.hostname in status.stdout
    ), f"SSSD is not connected to {ldap.host.hostname}, it did not skip the unresolvable hostname!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__chpass_uri_list_falls_back_to_next_uri(client: Client, ldap: LDAP):
    """
    :title: Password change fails over to the next URI in the chpass URI list
    :setup:
        1. Create user "user-1"
        2. Set chpass_provider to ldap
        3. Set ldap_chpass_uri to an invalid server followed by the LDAP server
        4. Start SSSD
    :steps:
        1. Change the password of user-1
        2. Login with the old password
        3. Login with the new password
    :expectedresults:
        1. Password change is successful
        2. User cannot login
        3. User can login
    :customerscenario: False
    """
    old_password = "Secret123"
    new_password = "New_Secret123"

    ldap.user("user-1").add(password=old_password)
    client.sssd.domain["auth_provider"] = "ldap"
    client.sssd.domain["chpass_provider"] = "ldap"
    client.sssd.domain["ldap_chpass_uri"] = f"ldap://invalid.{ldap.domain},ldap://{ldap.host.hostname}"
    client.sssd.start()

    assert client.auth.passwd.password("user-1", old_password, new_password), "Password change failed!"
    assert not client.auth.ssh.password("user-1", old_password), "Login with old password worked!"
    assert client.auth.ssh.password("user-1", new_password), "Login with new password failed!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_failover__chpass_backup_uri_is_used_when_chpass_uri_is_unavailable(client: Client, ldap: LDAP):
    """
    :title: Password change uses the chpass backup URI when the chpass URI is unavailable
    :setup:
        1. Create user "user-1"
        2. Set chpass_provider to ldap
        3. Set ldap_chpass_uri to an invalid server
        4. Set ldap_chpass_backup_uri to the LDAP server
        5. Start SSSD
    :steps:
        1. Change the password of user-1
        2. Login with the old password
        3. Login with the new password
    :expectedresults:
        1. Password change is successful
        2. User cannot login
        3. User can login
    :customerscenario: False
    """
    old_password = "Secret123"
    new_password = "New_Secret123"

    ldap.user("user-1").add(password=old_password)
    client.sssd.domain["auth_provider"] = "ldap"
    client.sssd.domain["chpass_provider"] = "ldap"
    client.sssd.domain["ldap_chpass_uri"] = f"ldap://invalid.{ldap.domain}"
    client.sssd.domain["ldap_chpass_backup_uri"] = f"ldap://{ldap.host.hostname}"
    client.sssd.start()

    assert client.auth.passwd.password("user-1", old_password, new_password), "Password change failed!"
    assert not client.auth.ssh.password("user-1", old_password), "Login with old password worked!"
    assert client.auth.ssh.password("user-1", new_password), "Login with new password failed!"

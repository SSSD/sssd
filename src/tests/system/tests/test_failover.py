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
from sssd_test_framework.topology import KnownTopologyGroup
"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

bash
====
# failover
?:Infinite loop checking kerberos credentials bz795562
?:sssd does not try another server when unable to resolve hostname bz845251
?:Failover does not happen from SRV to etc hosts bz1122873
?:sssd does not handle kerberos server IP change bz721052
?:sssd is not closing sockets properly bz1313014
?:krb5 kpasswd Server1 down Server2 online
?:krb5 kpasswd failover with single server different ports
?:krb5 server Server1 down online after 96s
?:krb5 server failover with single server different ports
?:ldap chpass uri Server1 down Server2 online
?:ldap chpass uri failover with single server different ports
?:ldap chpass uri First Server in the list cannot be resolved
?:ldap connection expire timeout Single Domain
?:ldap connection expire timeout MultiDomain
?:Test Authentication Both Servers Available
?:failover when a ldapserver is reachable but ldapsearch times out
?:Test Authentication Server 1 Unavailable
?:Test Authentication Server 2 Unavailable
?:Test Authentication Server 1 Unavailable Again
?:Test Authentication Both Servers available Again
?:iptables drop connection for server 1
?:iptables reject connection for server 1
?:ldap uri failover with single server different ports
?:multiple srv records with same weight and priority bz1110247
?:Read and use the TTL value when resolving a SRV query
?:krb5 backup kpasswd Server1 down Server2 online
?:krb5 backup kpasswd failover with single server different ports
?:krb5provider One primary server down online after 30s
?:krb5provider IP Address in backup server
?:krb5provider Service lookup in primary
?:krb5provider Service lookup in backup server list
?:krb5provider Primary and Backup list empty
?:krb5provider Primary list is empty should default to Service lookup
?:krb5provider Multiple Primary servers
?:krb5provider Multiple Backup servers
?:krb5provider Primary list has multiple servers and a service entry
?:krb5provider Primary list has multiple servers and a service entry in between
?:krb5provider Backup list has multiple servers and a service entry at the start
?:krb5provider Backup list has multiple krb5 servers and a service entry in between
?:krb5provider Backup list has multiple krb5 servers and a service entry at the end
?:krb5provider Primary list has a typo and ends with service lookup
?:krb5provider Primary and Backup list has a typo and ends with appropriate uri bz921259
?:ldap chpass backup uri Server1 down Server2 online
?:ldap chpass backup uri failover with single server different ports
?:ldap chpass backup uri First Server in the list cannot be resolved
?:ldaprovider One primary server down online after 31s
?:ldaprovider IP Address in backup server
?:ldaprovider Service lookup in primary
?:ldaprovider Service lookup in backup server list
?:ldaprovider Primary and Backup list empty
?:ldaprovider Primary list is empty should default to Service lookup
?:ldaprovider Multiple Primary servers
?:ldaprovider Multiple Backup servers
?:ldaprovider Primary list has multiple ldap uris and a service entry
?:ldaprovider Primary list has multiple ldap uri and a service entry in between
?:ldaprovider Backup list has multiple ldap uri and a service entry at the start
?:ldaprovider Backup list has multiple ldap uri and a service entry in between
?:ldaprovider Backup list has multiple ldap uri and a service entry at the end
?:ldaprovider Primary list has a typo and ends with service lookup bz921259
?:ldaprovider Primary and Backup list has a typo and ends with appropriate uri bz921259

intg
====

multihost
=========
# test_failover.py
?:test_0001_getent
?:test_0002_login
?:test_0003_stopsecondds
"""


@pytest.mark.parametrize("value, expected", [(None, 31), (15, 31), (60, 60)])
@pytest.mark.importance("low")
@pytest.mark.ticket(gh=7375, jira="RHEL-17659")
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

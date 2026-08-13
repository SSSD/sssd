"""
LDAP + krb5 provider tests against IPA topology (389-ds + krb5kdc on IPA server).

SSSD uses ``id_provider = ldap`` and ``auth_provider = krb5`` pointed at the IPA
host, not ``id_provider = ipa``. Same server stack as LDAP_KRB5; IPA directory
uses rfc2307bis (``ldap_schema = ipa_v1``).

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


def _assert_ldap_krb5_srv_records(client: Client, discovery_domain: str) -> None:
    for query in (
        f"_ldap._tcp.{discovery_domain}",
        f"_kerberos._udp.{discovery_domain}",
    ):
        assert client.net.has_srv_record(query), f"No SRV record for {query}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ldap_krb5_ipa__id_lookup_with_ldap_krb5_provider(client: Client, ipa: IPA):
    """
    :title: id lookup works with ldap+krb5 providers against IPA
    :setup:
        1. Add IPA user
        2. Configure SSSD with id_provider=ldap and auth_provider=krb5 (IPA server)
    :steps:
        1. Run id for the user
    :expectedresults:
        1. User resolves via ldap+krb5 domain on IPA backend
    :customerscenario: False
    """
    ipa.user("puser1").add()

    client.authselect.select("sssd")
    client.sssd.common.ldap_krb5_provider(ipa)
    client.sssd.restart(clean=True)

    result = client.tools.id("puser1")
    assert result is not None, "id failed with ldap+krb5 providers against IPA"
    assert result.user.name == "puser1"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ldap_krb5_ipa__gssapi_id_lookup_with_ldap_krb5_provider(client: Client, ipa: IPA):
    """
    :title: GSSAPI LDAP bind with ldap+krb5 providers against IPA
    :setup:
        1. Add IPA user (IPA server already has 389-ds GSSAPI; client uses enrolled host keytab)
        2. Configure SSSD with id_provider=ldap, auth_provider=krb5, ldap_sasl_mech=GSSAPI
    :steps:
        1. Verify host keytab on client
        2. Run id for the user
    :expectedresults:
        1. Client keytab contains the host principal
        2. User resolves via GSSAPI ldap+krb5 domain on IPA backend
    :customerscenario: False
    """
    ipa.user("puser1").add()

    keytab = "/etc/krb5.keytab"
    client_fqdn = client.host.conn.run("hostname -f").stdout.strip()
    klist = client.host.conn.run(f"klist -kt {keytab}", raise_on_error=False)
    assert klist.rc == 0, f"klist -kt {keytab} failed: {klist.stderr or klist.stdout}"
    assert f"host/{client_fqdn}" in (klist.stdout or ""), (
        f"IPA-enrolled client must have host/{client_fqdn} in {keytab}; got: {klist.stdout}"
    )

    client.authselect.select("sssd")
    client.sssd.common.ldap_krb5_provider(ipa, gssapi=True, client_hostname=client_fqdn)
    client.sssd.restart(clean=True)

    result = client.tools.id("puser1")
    assert result is not None, "id failed with GSSAPI ldap+krb5 providers against IPA"
    assert result.user.name == "puser1"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ldap_krb5_ipa__dns_srv_discovery_with_srv_uri(client: Client, ipa: IPA):
    """
    :title: DNS SRV discovery with ldap+krb5 providers against IPA (389-ds + krb5kdc)
    :setup:
        1. Prepare LDAP/Kerberos SRV for the IPA domain on the client
        2. Add user; configure ldap+krb5 with ldap_uri=_srv_ and krb5_server=_srv_
    :steps:
        1. Run id for puser1
        2. Authenticate via SSH
        3. Check logs for LDAP and Kerberos SRV resolution
    :expectedresults:
        1. id succeeds
        2. SSH password auth succeeds
        3. Logs show LDAP and Kerberos SRV marked as resolved
    :customerscenario: False
    """
    discovery_domain = ipa.domain
    server_hostname = ipa.host.hostname

    client.net.prepare_ldap_krb5_srv_discovery(
        discovery_domain=discovery_domain,
        ldap_hostname=server_hostname,
        kdc_hostname=server_hostname,
        client_hostname=client.host.hostname,
    )
    _assert_ldap_krb5_srv_records(client, discovery_domain)

    ipa.user("puser1").add()

    client.authselect.select("sssd")
    client.sssd.common.ldap_krb5_provider(ipa, discovery_domain=discovery_domain)

    client.sssd.domain["ldap_uri"] = "_srv_"
    client.sssd.domain["krb5_server"] = "_srv_"
    client.sssd.domain["debug_level"] = "0xFFF0"

    client.sssd.restart(clean=True)

    assert client.tools.id("puser1"), "id failed for puser1 before SSH login"
    assert client.auth.ssh.password("puser1", "Secret123"), "SSH auth failed with ldap+krb5 on IPA"

    domain = client.sssd.default_domain
    log_content = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")

    assert (
        f"Trying to resolve SRV record of '_ldap._tcp.{discovery_domain}'" in log_content
        or f"Trying to resolve SRV record of '_LDAP._tcp.{discovery_domain}'" in log_content
    ), "LDAP SRV discovery attempt not found in logs!"

    assert (
        "Marking SRV lookup of service 'LDAP' as 'resolved'" in log_content
    ), "LDAP SRV lookup was not marked as resolved!"

    assert (
        f"Trying to resolve SRV record of '_KERBEROS._udp.{discovery_domain}'" in log_content
        or f"Trying to resolve SRV record of '_kerberos._udp.{discovery_domain}'" in log_content
    ), "Kerberos SRV discovery attempt not found in logs!"

    assert (
        "Marking SRV lookup of service 'KERBEROS' as 'resolved'" in log_content
    ), "Kerberos SRV lookup was not marked as resolved!"

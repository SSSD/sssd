"""
SSSD AD Provider Test Cases

:requirement: ad
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(jira="RHEL-65848", gh=7690)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("high")
def test_ad__user_authentication_when_provider_is_set_to_ldap_with_gss_spnego(
    client: Client, provider: GenericADProvider, method: str
):
    """
    :title: Login to AD when id_provider is set to ldap
    :setup:
        1. Add AD user
        2. Update sssd.conf with 'id_provider = ldap', 'ldap_schema = ad',
        'ldap_id_use_start_tls = false', 'auth_provider = ad' and
        'ldap_sasl_mech = gssspengo' and Start SSSD
    :steps:
        1. Check authentication of the user
        2. Check log message in krb5_child.log, UPN [user1@null] should not be logged
    :expectedresults:
        1. Authentication is successful
        2. Get required UPN [user1@<domain_name>] from krb5_child.log
    :customerscenario: False
    """
    provider.user("user1").add()

    client.sssd.config.remove_option("domain/test", "id_provider")

    configurations = {
        "id_provider": "ldap",
        "ldap_schema": "ad",
        "ldap_id_use_start_tls": "False",
        "auth_provider": "ad",
        "ldap_referrals": "False",
        "ldap_sasl_mech": "GSS-SPNEGO",
        "ldap_id_mapping": "True",
    }

    for key, value in configurations.items():
        client.sssd.domain[key] = value

    # id_provider = ldap will not add them automatically if they are not
    # defined on the server side.
    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["override_homedir"] = "/home/%u"

    # `provider.host.domain` is ignored because it is dynamically added
    p_domain = f"{provider.host.domain}"  # type: ignore[attr-defined]

    client.sssd.domain["krb5_realm"] = f"{p_domain.upper()}"
    client.sssd.domain["dns_discovery_domain"] = f"{p_domain}"

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User user1 failed login!"

    log_str = client.fs.read("/var/log/sssd/krb5_child.log")
    assert f"UPN [user1@{p_domain}]" in log_str, f"'UPN [user1@{p_domain}]' not in logs!"  # type: ignore


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=7174)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__using_the_users_email_address(client: Client, ad: AD, method: str, sssd_service_user: str):
    """
    :title: Login using the user's email address
    :description:
        Testing the feature to login using an email address instead of the userid. The username used,
        must match one of the user's LDAP attribute values, "EmailAddress". The login should be
        case-insensitive and permit special characters.
    :setup:
        1. Add AD users with different email addresses
        2. Start SSSD
    :steps:
        1. Authenticate users using their email address and in different cases
    :expectedresults:
        1. Authentication is successful using the email address and is case-insensitive
    :customerscenario: False
    """
    ad.user("user-1").add(password="Secret123", email=f"user-1@{ad.host.domain}")
    ad.user("user-2").add(password="Secret123", email="user-2@alias-domain.com")
    ad.user("user_3").add(password="Secret123", email="user_3@alias-domain.com")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(
        f"user-1@{ad.host.domain}", "Secret123"
    ), f"User user-1@{ad.host.domain} failed login!"
    assert client.auth.parametrize(method).password(
        "user-2@alias-domain.com", "Secret123"
    ), "User user-2@alias-domain.com failed login!"
    assert client.auth.parametrize(method).password(
        "uSEr_3@alias-dOMain.com", "Secret123"
    ), "User uSEr_3@alias-dOMain.com failed login!"


@pytest.mark.ticket(bz=1762415)
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.AD)
def test_ad__force_ldaps_over_636(client: Client, ad: AD):
    """
    :title: Force LDAPS over 636 with AD provider
    :description:
        When plain LDAP port 389 is blocked, SSSD must use LDAPS on port 636 to
        contact the AD domain controller.
    :setup:
        1. Create user
        2. Install AD CA certificate and configure OpenLDAP for LDAPS channel bindings
        3. Block outbound port 389
        4. Configure ``ad_use_ldaps`` and ``ldap_id_mapping``
    :steps:
        1. Lookup user
        2. Check SSSD domain logs
    :expectedresults:
        1. User information is returned correctly
        2. Logs show connection to ldaps:// URI
    :customerscenario: True
    """
    user = ad.user("ldapsuser").add()

    # Remote CI labs may not resolve the DC; SSSD looks up ad_server via DNS.
    ssh_target = ad.host.config.get("conn", {}).get("host", ad.server)
    lookup = client.host.conn.run(f"getent ahostsv4 {ssh_target}", raise_on_error=False)
    if lookup.rc == 0 and lookup.stdout.strip():
        ad_ip = lookup.stdout.split()[0]
        client.fs.write("/etc/resolv.conf", f"search {ad.domain}\nnameserver {ad_ip}\n")

    # getadcacert.ps1: export enterprise CA for LDAPS channel bindings.
    ca = ad.host.conn.run(
        r"""
Import-Module ActiveDirectory
$c = Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CA*" } | Select-Object -First 1
if (-not $c) {
    $c = Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
        $_.Issuer -eq $_.Subject -and $_.Subject -like '*CA*'
    } | Select-Object -First 1
}
if (-not $c) { Write-Error "CA not found"; exit 1 }
"-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') `
    + "`r`n-----END CERTIFICATE-----"
""".strip(),
        raise_on_error=False,
    )
    if ca.rc != 0 or "BEGIN CERTIFICATE" not in (ca.stdout or ""):
        pytest.skip("AD CA certificate not available; install AD Certificate Services on the DC")

    client.fs.mkdir_p("/etc/openldap/certs")
    client.fs.write("/etc/openldap/certs/cacert.pem", ca.stdout.strip() + "\n")
    client.fs.write(
        "/etc/openldap/ldap.conf",
        "SASL_CBINDING tls-endpoint\n" "TLS_CACERT /etc/openldap/certs/cacert.pem\n" "SASL_NOCANON on\n",
    )

    client.firewall.outbound.drop_port((389, "tcp"))

    client.sssd.domain["ad_use_ldaps"] = "True"
    client.sssd.domain["ldap_id_mapping"] = "true"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    time.sleep(3)

    result = client.tools.getent.passwd(f"{user.name}@{ad.domain}")
    assert result is not None, "User lookup failed when LDAPS is forced"
    assert result.name == user.name

    log = client.fs.read(client.sssd.logs.domain())
    assert f"ldaps://{ad.server}" in log, f"Logs should show LDAPS connection to {ad.server}"

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

SMARTCARD_PIN = "123456"


def configure_ad_tls(client: Client, ad: AD) -> None:
    """
    Prepare the client for secure LDAP communication with the AD domain controller.

    Installs the AD CA certificate for TLS verification and configures OpenLDAP
    with tls-endpoint channel binding, which is the binding compatible with
    TLS 1.3 (tls-unique is not available in TLS 1.3).

    :param client: Client role object.
    :type client: Client
    :param ad: AD role object.
    :type ad: AD
    """
    # Remote CI labs may not resolve the DC; SSSD looks up ad_server via DNS.
    ssh_target = ad.host.config.get("conn", {}).get("host", ad.server)
    lookup = client.host.conn.run(f"getent ahostsv4 {ssh_target}", raise_on_error=False)
    if lookup.rc == 0 and lookup.stdout.strip():
        ad_ip = lookup.stdout.split()[0]
        client.fs.write("/etc/resolv.conf", f"search {ad.domain}\nnameserver {ad_ip}\n")

    try:
        ca = ad.export_root_ca_certificate()
    except RuntimeError:
        pytest.skip("AD CA certificate not available; install AD Certificate Services on the DC")

    client.fs.mkdir_p("/etc/openldap/certs")
    client.fs.write("/etc/openldap/certs/cacert.pem", ca)
    client.fs.write(
        "/etc/openldap/ldap.conf",
        "SASL_CBINDING tls-endpoint\nTLS_CACERT /etc/openldap/certs/cacert.pem\nSASL_NOCANON on\n",
    )


def skip_unless_windows_server_2025(ad: AD) -> None:
    """
    Skip the test unless the domain controller runs Windows Server 2025.

    :param ad: AD role object.
    :type ad: AD
    """
    result = ad.host.conn.run(
        "Write-Host (Get-CimInstance Win32_OperatingSystem).Caption",
        raise_on_error=False,
    )
    caption = result.stdout.strip()
    if "2025" not in caption:
        pytest.skip(f"Windows Server 2025 domain controller required, got: {caption or 'unknown version'}")


def enroll_ad_smartcard(client: Client, ad: AD, username: str) -> None:
    """
    Request a certificate from the AD CA for *username* and enroll it onto the
    client's virtual smart card.

    :meth:`AD.ca.request` maps the certificate to the user in AD and returns the
    certificate together with its private key, regardless of whether the
    enrollment agent or the basic path is used.

    :param client: Client role object.
    :type client: Client
    :param ad: AD role object whose CA issues the certificate.
    :type ad: AD
    :param username: AD user the certificate is issued for.
    :type username: str
    """
    cert_path, key_path, _ = ad.ca.request("User", f"CN={username}")

    client.fs.write("/etc/sssd/pki/sssd_auth_ca_db.pem", ad.ca.get_ca_cert())

    client.smartcard.add_cert_key_by_path(cert_path, key_path, source=ad, name=username)


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


@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_ad__group_with_fsp_member(client: Client, provider: GenericADProvider):
    """
    :title: Lookup a group which has a foreign security principal (FSP) as member
    :description:
        Testing groups lookups for AD/Samba groups which have a foreign
        security principal as a member. Since SSSD currently cannot resolve the
        FSPs e.g. to determine if it is a user or a group they should be ignored
        by default without any extra setting in sssd.conf.
    :setup:
        1. Create a test user
        2. Create a test group
        3. Add test user and a FSP by SID to the test group
    :steps:
        1. Lookup test group
    :expectedresults:
        1. Lookup is successful and the test user is returned as a member of
           the test group
    :customerscenario: False
    """

    user = provider.user("testuser").add()
    group = provider.group("testgroup").add().add_member(user)

    # Samba automagically creates an FSP object if a random SID is added to a
    # group. I didn't find a similar way in AD to add a FSP entry to a group.
    # If someone finds a way, the test can be run against AD as well.
    provider.host.conn.run(f"samba-tool group addmembers {group.name} S-1-5-21-123-456-789-1234")

    client.sssd.start()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"Failed to lookup group {group.name}!"
    assert len(result.members) == 1, f"Expecing 1 member of group {group.name} found {len(result.members)}"
    assert user.name in result.members, f"User {user.name} is not a member of {group.name}!"


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


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(jira="IDM-6828")
@pytest.mark.importance("high")
def test_ad__starttls_with_sasl_sealing(client: Client, ad: AD):
    """
    :title: AD provider connects over StartTLS with SASL sealing
    :description:
        Windows Server 2025 domain controllers negotiate TLS 1.3 for StartTLS
        on port 389. AD does not allow SASL sign/seal on a TLS-protected
        connection, so the SASL security layer is disabled and StartTLS
        provides the confidentiality. SSSD must connect, lookup and
        authenticate users without TLS negotiation failures.
    :setup:
        1. Add AD user
        2. Install the AD CA certificate and configure OpenLDAP channel binding
        3. Configure ``ldap_id_use_start_tls`` and start SSSD
    :steps:
        1. Lookup AD user
        2. Authenticate as the AD user
        3. Check SSSD domain logs
    :expectedresults:
        1. User information is returned correctly
        2. Authentication is successful
        3. Logs show StartTLS was executed without TLS failures
    :customerscenario: False
    """
    skip_unless_windows_server_2025(ad)

    user = ad.user("starttlsuser").add()

    configure_ad_tls(client, ad)

    client.sssd.domain["ldap_id_use_start_tls"] = "True"
    # AD rejects SASL sign/seal on a TLS-protected connection ("Cannot bind
    # using sign/seal on a connection on which TLS or SSL is in effect",
    # 00002029). StartTLS provides the confidentiality, so no SASL security
    # layer is requested.
    client.sssd.domain["ldap_sasl_minssf"] = "0"
    client.sssd.domain["ldap_sasl_maxssf"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "true"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    result = client.tools.getent.passwd(f"{user.name}@{ad.domain}")
    assert result is not None, "User lookup failed with StartTLS enabled"
    assert result.name == user.name

    assert client.auth.su.password(user.name, "Secret123"), "User login failed with StartTLS enabled"

    log = client.fs.read(client.sssd.logs.domain())
    assert "Executing START TLS" in log, "Logs should show START TLS operation"
    assert "Could not start TLS" not in log, "StartTLS negotiation failed"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(jira="IDM-6828")
@pytest.mark.importance("high")
def test_ad__ldaps_with_sasl_sealing(client: Client, ad: AD):
    """
    :title: AD provider connects over LDAPS with SASL sealing
    :description:
        Windows Server 2025 domain controllers negotiate TLS 1.3 for LDAPS on
        port 636 and seal SASL traffic for confidentiality. SSSD must connect,
        lookup and authenticate users without TLS negotiation failures.
    :setup:
        1. Add AD user
        2. Install the AD CA certificate and configure OpenLDAP channel binding
        3. Configure ``ad_use_ldaps`` and start SSSD
    :steps:
        1. Lookup AD user
        2. Authenticate as the AD user
        3. Check SSSD domain logs
    :expectedresults:
        1. User information is returned correctly
        2. Authentication is successful
        3. Logs show LDAPS connection to the domain controller
    :customerscenario: False
    """
    skip_unless_windows_server_2025(ad)

    user = ad.user("ldapssealuser").add()

    configure_ad_tls(client, ad)

    client.sssd.domain["ad_use_ldaps"] = "True"
    client.sssd.domain["ldap_id_mapping"] = "true"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    result = client.tools.getent.passwd(f"{user.name}@{ad.domain}")
    assert result is not None, "User lookup failed over LDAPS"
    assert result.name == user.name

    assert client.auth.su.password(user.name, "Secret123"), "User login failed over LDAPS"

    log = client.fs.read(client.sssd.logs.domain())
    assert f"ldaps://{ad.server}" in log, f"Logs should show LDAPS connection to {ad.server}"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(jira="IDM-6828")
@pytest.mark.importance("high")
def test_ad__ldaps_tls13_negotiation(client: Client, ad: AD):
    """
    :title: SSSD uses TLS 1.3 for LDAPS connection to the domain controller
    :description:
        Windows Server 2025 enables TLS 1.3 by default. The domain controller
        must negotiate TLS 1.3 on the LDAPS endpoint and SSSD must connect to
        it with SASL sealing, without TLS negotiation failures or fallback to
        lower TLS versions.
    :setup:
        1. Add AD user
        2. Install the AD CA certificate and configure OpenLDAP channel binding
        3. Check that the DC LDAPS endpoint negotiates TLS 1.3 with openssl
        4. Configure ``ad_use_ldaps`` and start SSSD
    :steps:
        1. Lookup AD user
        2. Authenticate as the AD user
        3. Check SSSD domain logs
    :expectedresults:
        1. User information is returned correctly
        2. Authentication is successful
        3. Logs show LDAPS connection to the domain controller
    :customerscenario: False
    """
    skip_unless_windows_server_2025(ad)

    user = ad.user("tls13user").add()

    configure_ad_tls(client, ad)

    probe = client.host.conn.run(
        f"openssl s_client -connect {ad.server}:636 -brief </dev/null",
        raise_on_error=False,
    )
    if "Protocol version: TLSv1.3" not in (probe.stdout + probe.stderr):
        pytest.skip(f"DC does not negotiate TLS 1.3 over LDAPS: {(probe.stderr or probe.stdout).strip()}")

    client.sssd.domain["ad_use_ldaps"] = "True"
    client.sssd.domain["ldap_id_mapping"] = "true"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    result = client.tools.getent.passwd(f"{user.name}@{ad.domain}")
    assert result is not None, "User lookup failed over LDAPS with TLS 1.3"
    assert result.name == user.name

    assert client.auth.su.password(user.name, "Secret123"), "User login failed over LDAPS with TLS 1.3"

    log = client.fs.read(client.sssd.logs.domain())
    assert f"ldaps://{ad.server}" in log, f"Logs should show LDAPS connection to {ad.server}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_ad__user_authenticates_with_smartcard_certificate(client: Client, ad: AD):
    """
    :title: AD user authenticates using a certificate on a virtual smart card
    :setup:
        1. Add AD user
        2. Request a certificate from the AD CA and enroll it on the virtual smart card
        3. Configure SSSD for smart card authentication with a certmap rule and start SSSD
    :steps:
        1. Authenticate as the AD user using the smart card PIN
    :expectedresults:
        1. Authentication is successful
    :customerscenario: True
    """
    if not ad.ca.is_available:
        pytest.skip("AD Certificate Services is not available")

    username = "certuser1"
    ad.user(username).add()

    enroll_ad_smartcard(client, ad, username)

    base_dn = ",".join(f"DC={part}" for part in ad.domain.split("."))
    domain_name = client.sssd.default_domain

    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.domain["ldap_user_certificate"] = "userCertificate;binary"
    client.sssd.domain["local_auth_policy"] = "only"
    client.sssd.pam["pam_cert_auth"] = "True"

    certmap = client.sssd.section(f"certmap/{domain_name}/{username}")
    certmap["matchrule"] = f"<ISSUER>.*{base_dn}.*"
    certmap["maprule"] = f"(sAMAccountName={username})"

    client.svc.restart("virt_cacard.service")
    client.sssd.start()

    assert client.auth.su.smartcard(username, SMARTCARD_PIN), "Smart card authentication failed!"

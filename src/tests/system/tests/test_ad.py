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


def enroll_ad_smartcard(client: Client, ad: AD, username: str) -> None:
    """
    Request a certificate from the AD CA and enroll it onto the client's virtual smartcard.

    Handles both enrollment agent path (returns key file) and basic fallback
    path (returns PFX file) transparently.

    :param client: Client role object.
    :param ad: AD role object.
    :param username: AD username the certificate is issued for.
    """
    cert_path, second_path, _ = ad.ca.request("User", f"CN={username}")

    cert_content = ad.host.conn.run(f'Get-Content "{cert_path}" -Raw').stdout
    client.fs.write(f"/opt/test_ca/{username}.crt", cert_content)

    if second_path.endswith(".key"):
        key_content = ad.host.conn.run(f'Get-Content "{second_path}" -Raw').stdout
        client.fs.write(f"/opt/test_ca/{username}.key", key_content)
    else:
        pfx_b64 = ad.host.conn.run(
            f"[System.Convert]::ToBase64String(" f'[System.IO.File]::ReadAllBytes("{second_path}"))'
        ).stdout.strip()
        client.fs.write(f"/opt/test_ca/{username}.pfx.b64", pfx_b64)
        client.host.conn.run(f"base64 -d /opt/test_ca/{username}.pfx.b64 > /opt/test_ca/{username}.pfx")
        client.host.conn.run(
            f"openssl pkcs12 -in /opt/test_ca/{username}.pfx -nocerts -nodes "
            f"-password pass:Secret123 -out /opt/test_ca/{username}.key"
        )

        ad.host.conn.run(
            f'$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("{cert_path}"); '
            f"Set-ADUser -Identity {username} -Replace @{{userCertificate=$c.RawData}}"
        )

    client.fs.write("/etc/sssd/pki/sssd_auth_ca_db.pem", ad.ca.get_ca_cert())

    client.smartcard.initialize_card()
    client.smartcard.add_key(f"/opt/test_ca/{username}.key")
    client.smartcard.add_cert(f"/opt/test_ca/{username}.crt")


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_ad__certificate_authentication_basic(client: Client, ad: AD):
    """
    :title: AD user authenticates using certificate on virtual smartcard
    :setup:
        1. Join AD domain to ensure keytab exists
        2. Add AD user
        3. Request certificate from AD CA and enroll on virtual smartcard
        4. Configure authselect with smartcard support
        5. Configure SSSD for local certificate authentication with certmap rule
        6. Start SSSD and virt_cacard
    :steps:
        1. Authenticate as AD user using smartcard PIN via nested su
    :expectedresults:
        1. Authentication is successful and PIN prompt appears
    :customerscenario: True
    """
    if not ad.ca.is_available:
        pytest.skip("AD Certificate Services is not available")

    username = "adcertuser1"
    try:
        ad.user(username).delete()
    except Exception:
        pass
    ad.user(username).add()

    client.host.conn.run("rm -f /etc/krb5.conf /etc/krb5.keytab", raise_on_error=False)
    client.host.conn.run(
        f"realm join {ad.domain}",
        input=ad.host.adminpw,
        raise_on_error=False,
    )

    enroll_ad_smartcard(client, ad, username)

    client.authselect.select("sssd", ["with-smartcard"])

    client.host.conn.run(
        r"sed -i 's/\[default=2 ignore=ignore success=ok\]\s*pam_localuser.so/"
        r"[default=ignore ignore=ignore success=ok]         pam_localuser.so/' "
        r"/etc/pam.d/system-auth",
    )

    client.sssd.config_load()
    client.sssd.default_domain = ad.domain

    if "config_file_version" in client.sssd.sssd:
        del client.sssd.sssd["config_file_version"]

    client.sssd.domain["use_fully_qualified_names"] = "False"
    client.sssd.domain["dyndns_update"] = "False"
    client.sssd.domain["ldap_user_certificate"] = "userCertificate;binary"
    client.sssd.domain["local_auth_policy"] = "only"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.pam["p11_child_timeout"] = "60"

    domain_name = client.sssd.default_domain
    client.sssd.config[f"certmap/{domain_name}/{username}"] = {
        "matchrule": "<ISSUER>.*DC=ad,DC=test.*",
        "maprule": f"(sAMAccountName={username})",
        "priority": "1",
    }

    client.sssd.restart()

    client.svc.restart("virt_cacard.service")
    time.sleep(5)

    fqdn_user = f"{username}@{ad.domain}"
    result = None
    for _attempt in range(10):
        time.sleep(3)
        result = client.tools.getent.passwd(fqdn_user)
        if result is not None:
            break
        if _attempt == 2:
            client.host.conn.run("sss_cache -E", raise_on_error=False)

    assert result is not None, f"User {fqdn_user} not found by SSSD"

    result = client.host.conn.run(
        f"su - {fqdn_user} -c 'su - {fqdn_user} -c whoami'",
        input="123456",
        raise_on_error=False,
    )
    assert result.rc == 0, f"su failed: stdout={result.stdout}, stderr={result.stderr}"
    assert "PIN" in result.stderr, f"PIN prompt not found in stderr: {result.stderr}"
    assert username in result.stdout, f"'{username}' not in whoami output: {result.stdout}"

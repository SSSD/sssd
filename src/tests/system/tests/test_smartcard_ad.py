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


def enroll_ad_smartcard(client: Client, ad: AD, username: str) -> None:
    """
    Request a certificate from the AD CA and enroll it onto the client's virtual smartcard.

    Handles both enrollment agent path (returns key file) and basic fallback
    path (returns PFX file) transparently.

    :param client: Client role object.
    :param ad: AD role object.
    :param username: AD username the certificate is issued for.
    """
    cert_path, second_path, _ = ad.ca.request("SmartcardLogon_IDMTEST", f"CN={username}")

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

    # Finally, set crypto policy to allow smartcard login for direct AD Integration
    client.host.conn.run("update-crypto-policies --set DEFAULT:AD-SUPPORT-LEGACY")


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

#    client.host.conn.run("rm -f /etc/krb5.conf /etc/krb5.keytab", raise_on_error=False)
#    client.host.conn.run(
#        f"realm join {ad.domain}",
#        input=ad.host.adminpw,
#        raise_on_error=False,
#    )

    enroll_ad_smartcard(client, ad, username)

    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.import_domain(ad.domain, ad)
    client.sssd.config.remove_section("domain/test")
#
#    client.host.conn.run(
#        r"sed -i 's/\[default=2 ignore=ignore success=ok\]\s*pam_localuser.so/"
#        r"[default=ignore ignore=ignore success=ok]         pam_localuser.so/' "
#        r"/etc/pam.d/system-auth",
#    )
#
#    client.sssd.config_load()
    client.sssd.default_domain = ad.domain

#    if "config_file_version" in client.sssd.sssd:
#        del client.sssd.sssd["config_file_version"]

    client.sssd.domain["use_fully_qualified_names"] = "False"
    client.sssd.domain["dyndns_update"] = "False"
    client.sssd.domain["ldap_user_certificate"] = "userCertificate;binary"
#    client.sssd.domain["local_auth_policy"] = "only"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.pam["p11_child_timeout"] = "60"

    domain_name = client.sssd.default_domain
    domain_dn = ",".join(f"DC={part}" for part in domain_name.split("."))
    client.sssd.config[f"certmap/{domain_name}/{username}"] = {
        "matchrule": f"<ISSUER>.*{domain_dn}.*",
        "maprule": f"(sAMAccountName={username})",
        "priority": "1",
    }

    client.sssd.restart()

    client.svc.restart("virt_cacard.service")
    # time.sleep(5)

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

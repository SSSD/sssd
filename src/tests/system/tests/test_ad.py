"""
SSSD AD Provider Test Cases

:requirement: ad
"""

from __future__ import annotations

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


SMARTCARD_PIN = "123456"


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

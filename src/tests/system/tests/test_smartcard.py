"""
SSSD smart card authentication test

:requirement: smartcard_authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology

TOKEN1_LABEL = "SC_Token_1"
TOKEN2_LABEL = "SC_Token_2"
TOKEN_PIN = "123456"


def setup_two_tokens(
    client: Client,
    ipa: IPA,
    *,
    token1_username: str,
    token2_username: str,
) -> None:
    """
    Create two SoftHSM tokens, each holding an IPA-signed certificate.

    :param client: Client role object.
    :type client: Client
    :param ipa: IPA role object.
    :type ipa: IPA
    :param token1_username: IPA user whose cert goes onto token 1.
    :type token1_username: str
    :param token2_username: IPA user whose cert goes onto token 2.
    :type token2_username: str
    """
    client.smartcard.enroll_to_token(client, ipa, token1_username, token_label=TOKEN1_LABEL, pin=TOKEN_PIN, init=True)

    client.smartcard.initialize_card(label=TOKEN2_LABEL, user_pin=TOKEN_PIN, reset=False)
    client.smartcard.enroll_to_token(client, ipa, token2_username, token_label=TOKEN2_LABEL, pin=TOKEN_PIN)


def _configure_soft_ocsp_smartcard_and_start(
    client: Client,
    *,
    certificate_verification: str | None = None,
) -> None:
    """Configure SSSD for soft_ocsp smart-card tests and present a virtual card.

    Sets krb5_use_fast=never, access_provider=permit, and selinux_provider=none
    because the soft_ocsp tests redirect ipa-ca to unreachable IPs, which would
    otherwise cause unrelated FAST, HBAC, and SELinux provider failures.

    local_auth_policy=enable:smartcard is required because redirecting ipa-ca
    makes the IPA domain appear offline and Kerberos unavailable.  Without an
    initial online authentication SSSD does not know which methods are allowed,
    so local_auth_policy must explicitly enable smart card authentication.
    """
    client.authselect.select("sssd", ["with-smartcard"])

    if certificate_verification is not None:
        client.sssd.sssd["certificate_verification"] = certificate_verification
    elif "certificate_verification" in client.sssd.sssd:
        del client.sssd.sssd["certificate_verification"]

    client.sssd.domain["access_provider"] = "permit"
    client.sssd.domain["krb5_use_fast"] = "never"
    client.sssd.domain["selinux_provider"] = "none"
    client.sssd.domain["local_auth_policy"] = "enable:smartcard"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.svc.restart("virt_cacard.service")
    client.sssd.start()


def _redirect_ocsp_responder(client: Client, ipa: IPA, target_ip: str) -> None:
    """Point the IPA OCSP responder hostname to *target_ip* via ``/etc/hosts``."""
    ipa_ca_hostname = f"ipa-ca.{ipa.domain}"
    client.fs.append("/etc/hosts", f"\n{target_ip}  {ipa_ca_hostname}\n")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__su_as_local_user(client: Client):
    """
    :title: Test smart card initialization for local user
    :setup:
        1. Setup and initialize smart card for user
    :steps:
        1. Authenticate as local user using smart card and issue command 'whoami'
    :expectedresults:
        1. Login successful and command returns local user
    :customerscenario: True
    """
    client.local.user("localuser1").add()
    client.smartcard.setup_local_card(client, "localuser1")
    result = client.host.conn.run("su - localuser1 -c 'su - localuser1 -c whoami'", input="123456")
    assert "PIN" in result.stderr, "String 'PIN' was not found in stderr!"
    assert "localuser1" in result.stdout, "'localuser1' not found in 'whoami' output!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_smartcard__two_tokens_match_on_first(client: Client, ipa: IPA):
    """
    :title: Two smart cards – valid certificate on the first token
    :setup:
        1. Create IPA user and a decoy IPA user
        2. Initialize two SoftHSM tokens (simulating two smart cards)
        3. Place the target user's IPA certificate on token 1
        4. Place the decoy user's IPA certificate on token 2
        5. Configure SSSD for smart card authentication and start services
    :steps:
        1. Authenticate as the target IPA user via nested ``su`` with the
           smart card PIN
    :expectedresults:
        1. SSSD's ``p11_child`` finds valid certificates on both tokens,
           SSSD maps the token-1 certificate to the target user, prompts
           for PIN, and authentication succeeds
    :customerscenario: True
    """
    username = "scuser_t1"
    decoy = "scdecoy_t1"
    ipa.user(username).add()
    ipa.user(decoy).add()

    setup_two_tokens(client, ipa, token1_username=username, token2_username=decoy)
    client.sssd.common.smartcard_with_softhsm(client.smartcard)
    assert client.auth.su.smartcard(username, TOKEN_PIN)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_smartcard__two_tokens_match_on_second(client: Client, ipa: IPA):
    """
    :title: Two smart cards – valid certificate only on the second token
    :setup:
        1. Create IPA user and a decoy IPA user
        2. Initialize two SoftHSM tokens (simulating two smart cards)
        3. Place the decoy user's IPA certificate on token 1
        4. Place the target user's IPA certificate on token 2
        5. Configure SSSD for smart card authentication and start services
    :steps:
        1. Authenticate as the target IPA user via nested ``su`` with the
           smart card PIN
    :expectedresults:
        1. SSSD's ``p11_child`` does **not** stop at token 1 (whose cert
           maps to the decoy user); it continues to token 2, finds the
           certificate that maps to the target user, prompts for PIN, and
           authentication succeeds
    :customerscenario: True
    """
    username = "scuser_t2"
    decoy = "scdecoy_t2"
    ipa.user(username).add()
    ipa.user(decoy).add()

    setup_two_tokens(client, ipa, token1_username=decoy, token2_username=username)
    client.sssd.common.smartcard_with_softhsm(client.smartcard)
    assert client.auth.su.smartcard(username, TOKEN_PIN)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("cert_selection", [1, 2])
def test_smartcard__two_tokens_match_on_both(client: Client, ipa: IPA, cert_selection: int):
    """
    :title: Two smart cards – valid certificate on both tokens
    :setup:
        1. Create IPA user
        2. Initialize two SoftHSM tokens (simulating two smart cards)
        3. Place a valid IPA certificate for the same user on both tokens
        4. Configure SSSD for smart card authentication and start services
    :steps:
        1. Authenticate as the IPA user via nested ``su`` with the PIN,
           selecting each certificate in turn (``cert_selection`` 1 and 2)
    :expectedresults:
        1. SSSD's ``p11_child`` finds valid certificates on both tokens and
           authentication succeeds for each selected certificate
    :customerscenario: True
    """
    username = "scuser_both"
    ipa.user(username).add()

    setup_two_tokens(client, ipa, token1_username=username, token2_username=username)
    client.sssd.common.smartcard_with_softhsm(client.smartcard)
    assert client.auth.su.smartcard(username, TOKEN_PIN, num_certs=2, cert_selection=cert_selection)


@pytest.mark.ticket(jira="RHEL-5043")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__soft_ocsp_with_unreachable_responder(client: Client, ipa: IPA):
    """
    :title: Smart card authentication succeeds with soft_ocsp when OCSP responder is unreachable
    :setup:
        1. Create an IPA user and enroll a smart card.
        2. Configure ``certificate_verification = soft_ocsp``.
        3. Point ipa-ca to 192.168.123.1 (non-routable, packets silently dropped).
        4. Start SSSD and present the virtual smart card.
    :steps:
        1. Authenticate via ``su`` with the smart card PIN.
    :expectedresults:
        1. PIN prompt appears and authentication succeeds despite the
           unreachable OCSP responder.
    :customerscenario: True
    """
    username = "smartcarduser1"

    ipa.user(username).add()
    client.smartcard.enroll_to_token(client, ipa, username, init=True)

    _redirect_ocsp_responder(client, ipa, "192.168.123.1")
    _configure_soft_ocsp_smartcard_and_start(client, certificate_verification="soft_ocsp")

    assert client.auth.su.smartcard(username, TOKEN_PIN), "Smart card authentication failed!"


@pytest.mark.ticket(jira="RHEL-5043")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__soft_ocsp_with_reachable_responder(client: Client, ipa: IPA):
    """
    :title: Smart card authentication succeeds with soft_ocsp when OCSP responder is reachable
    :setup:
        1. Create an IPA user and enroll a smart card.
        2. Configure ``certificate_verification = soft_ocsp``.
        3. Start SSSD and present the virtual smart card (OCSP responder is reachable).
    :steps:
        1. Authenticate via ``su`` with the smart card PIN.
    :expectedresults:
        1. PIN prompt appears and authentication succeeds; the OCSP check
           completes normally.
    :customerscenario: True
    """
    username = "smartcarduser2"

    ipa.user(username).add()
    client.smartcard.enroll_to_token(client, ipa, username, init=True)

    _configure_soft_ocsp_smartcard_and_start(client, certificate_verification="soft_ocsp")

    assert client.auth.su.smartcard(username, TOKEN_PIN), "Smart card authentication failed!"


@pytest.mark.ticket(jira="RHEL-5043")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__soft_ocsp_with_connection_refused(client: Client, ipa: IPA):
    """
    :title: Smart card authentication succeeds with soft_ocsp when OCSP connection is refused
    :setup:
        1. Create an IPA user and enroll a smart card.
        2. Configure ``certificate_verification = soft_ocsp``.
        3. Point ipa-ca to 127.0.0.7 (loopback, immediate TCP RST).
        4. Start SSSD and present the virtual smart card.
    :steps:
        1. Authenticate via ``su`` with the smart card PIN.
    :expectedresults:
        1. PIN prompt appears and authentication succeeds; the OCSP
           connection is immediately refused and soft_ocsp skips the check.
    :customerscenario: True
    """
    username = "smartcarduser3"

    ipa.user(username).add()
    client.smartcard.enroll_to_token(client, ipa, username, init=True)

    _redirect_ocsp_responder(client, ipa, "127.0.0.7")
    _configure_soft_ocsp_smartcard_and_start(client, certificate_verification="soft_ocsp")

    assert client.auth.su.smartcard(username, TOKEN_PIN), "Smart card authentication failed!"


@pytest.mark.ticket(jira="RHEL-5043")
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__without_soft_ocsp_with_unreachable_responder(client: Client, ipa: IPA):
    """
    :title: Smart card authentication fails without soft_ocsp when OCSP responder is unreachable
    :setup:
        1. Create an IPA user and enroll a smart card.
        2. Do NOT set ``certificate_verification`` (default OCSP behaviour).
        3. Point ipa-ca to 192.168.123.1 (unreachable).
        4. Start SSSD and present the virtual smart card.
    :steps:
        1. Attempt to authenticate via ``su`` with the smart card PIN.
    :expectedresults:
        1. Without ``soft_ocsp``, the certificate check fails because the
           OCSP responder is unreachable.  The user sees a password prompt
           (not a PIN prompt) or the authentication fails outright.
    :customerscenario: True
    """
    username = "smartcarduser4"

    ipa.user(username).add()
    client.smartcard.enroll_to_token(client, ipa, username, init=True)

    _redirect_ocsp_responder(client, ipa, "192.168.123.1")
    _configure_soft_ocsp_smartcard_and_start(client, certificate_verification=None)

    result = client.auth.su.smartcard_with_output(username, TOKEN_PIN)

    assert (
        "PIN" not in result.stderr or result.rc != 0
    ), f"Expected authentication to fail without soft_ocsp when OCSP is unreachable! rc={result.rc}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__login_fails_when_wrong_pin_is_entered(client: Client):
    """
    :title: Smartcard login fails when the wrong pin is entered.
    :setup:
        1. Create a local user and initialize a smart card mapped to the user
    :steps:
        1. Authenticate as the user via 'su' with an incorrect PIN
    :expectedresults:
        1. Authentication fails
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")

    assert not client.auth.su.smartcard("user1", "000000"), "Authentication should have failed with a wrong PIN!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__login_fails_when_card_is_not_mapped(client: Client):
    """
    :title: Smartcard authentication fails when card is not mapped to the user
    :setup:
        1. Create two local users and initialize a smart card mapped to only the first user
    :steps:
        1. Authenticate as the first user via 'su' with the smart card PIN
        2. Attempt to authenticate as the second user via 'su' with the same smart card PIN
    :expectedresults:
        1. Authentication succeeds using the certificate
        2. Authentication fails because the certificate does not map to the second user
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.local.user("user2").add()
    client.smartcard.setup_local_card(client, "user1")

    assert client.auth.su.smartcard("user1", TOKEN_PIN), "Smart card authentication failed for the mapped user!"
    assert not client.auth.su.smartcard(
        "user2", TOKEN_PIN
    ), "Authentication should fail for a user the certificate does not map to!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize(
    "pam_p11_allowed_services, expect_cert_auth",
    [(None, True), ("-su-l", False)],
    ids=["su_l_allowed_by_default", "su_l_removed_from_allowed_services"],
)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__certificate_authentication_is_limited_to_allowed_pam_services(
    client: Client, pam_p11_allowed_services: str | None, expect_cert_auth: bool
):
    """
    :title: Smartcard authentication is only used for PAM services allowed by pam_p11_allowed_services
    :setup:
        1. Optionally remove the 'su-l' service (used by ``su -``) from 'pam_p11_allowed_services'
        2. Create a local user and initialize a smart card mapped to the user
    :steps:
        1. Authenticate as the user via 'su -' presenting the smart card PIN
    :expectedresults:
        1. Authentication uses the certificate when 'su-l' is an allowed service; when it is not,
           'su -' does not prompt for a PIN and the PIN is rejected as a regular password
    :customerscenario: True
    """
    client.local.user("user1").add()
    if pam_p11_allowed_services is not None:
        client.sssd.pam["pam_p11_allowed_services"] = pam_p11_allowed_services
    client.smartcard.setup_local_card(client, "user1")

    result = client.auth.su.smartcard_with_output("user1", TOKEN_PIN)
    if expect_cert_auth:
        assert result.rc == 0, "Smart card authentication should have succeeded!"
        assert "PIN" in result.stderr, "'su -' should have prompted for a PIN!"
    else:
        assert "PIN" not in result.stderr, "'su -' should not prompt for a PIN when it is not an allowed service!"
        assert result.rc != 0, f"'{TOKEN_PIN}' should not be accepted as user1's login password!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__login_succeeds_when_cert_auth_required(client: Client):
    """
    :title: Smartcard login succeeds when certificate authentication is required
    :setup:
        1. Create a local user and initialize a smart card mapped to the user
        2. Require certificate-based authentication (authselect 'with-smartcard-required')
    :steps:
        1. Authenticate as the user via 'su' with the smart card PIN
    :expectedresults:
        1. Authentication succeeds
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")
    client.authselect.select("sssd", ["with-smartcard-required"])

    assert client.auth.su.smartcard("user1", TOKEN_PIN), "Smart card authentication failed!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__login_fails_when_cert_auth_required_without_card(client: Client):
    """
    :title: Smartcard login fails when certificate authentication is required and no card is present
    :setup:
        1. Create a local user
        2. Reduce the smart card wait timeouts
        3. Initialize a smart card mapped to the user and require certificate-based
           authentication (authselect 'with-smartcard-required')
        4. Remove the smart card
    :steps:
        1. Attempt to authenticate as the user via 'su'
    :expectedresults:
        1. Authentication fails because no smart card was inserted before the timeout
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.sssd.pam["p11_child_timeout"] = "1"
    client.sssd.pam["p11_wait_for_card_timeout"] = "1"
    client.smartcard.setup_local_card(client, "user1")
    client.authselect.select("sssd", ["with-smartcard-required"])
    client.smartcard.remove_card()

    assert not client.auth.su.smartcard("user1", TOKEN_PIN), "Authentication should have failed without a card!"

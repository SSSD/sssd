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
def test_smartcard__unlock_console_with_vlock(client: Client):
    """
    :title: Use smart card to unlock console with vlock
    :setup:
        1. Create local user and setup smart card authentication
    :steps:
        1. Login as user and lock terminal with vlock
        2. Enter incorrect pin
        3. Enter correct pin
    :expectedresults:
        1. User logged in and vlock locks the terminal and prompts for PIN
        2. Authentication is unsuccessful
        3. Authentication is successful
    :customerscenario: False
    """
    if "Fedora" in client.host.distro_name and client.host.distro_major == 45:
        pytest.skip("virt_cacard crashes on Fedora 45 due to OpenSSL 4.x incompatibility")

    username = "localuser1"
    client.local.user(username).add()
    client.smartcard.setup_local_card(client, username)

    assert client.auth.su.vlock_smartcard(username, TOKEN_PIN), "vlock smartcard authentication failed"


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
        1. Authenticate as the user via ``sssctl user-checks`` with the ``login`` PAM
           service and the smart card PIN
    :expectedresults:
        1. Authentication succeeds
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")
    client.authselect.select("sssd", ["with-smartcard-required"])

    result = client.sssctl.user_checks("user1", action="auth", service="login", auth_input=TOKEN_PIN)
    assert "pam_authenticate for user [user1]: Success" in result.stderr


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
        1. Attempt to authenticate as the user via ``sssctl user-checks`` with the
           ``login`` PAM service
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

    result = client.sssctl.user_checks("user1", action="auth", service="login", auth_input=TOKEN_PIN)
    assert (
        "Authentication service cannot retrieve authentication info" in result.stderr
    ), "Authentication should have failed without a card!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__try_cert_auth_never_used_for_root(client: Client):
    """
    :title: try_cert_auth never routes root's own login through certificate authentication
    :description:
        pam_sss.so unconditionally refuses to handle the 'root' identity. When 'try_cert_auth'
        is set, that refusal must surface as PAM_AUTHINFO_UNAVAIL (so the PAM stack falls back
        to another module), not as a successful or user-unknown result. This is verified via
        'sssctl user-checks' against a minimal 'auth required pam_sss.so try_cert_auth' service,
        since there is no way to originate a fresh authentication attempt for the 'root' identity
        itself via 'su'/'ssh' (root already owns the control connection).
    :setup:
        1. Create a local user and initialize a smart card mapped to the user
        2. Install a minimal PAM service with 'pam_sss.so try_cert_auth'
    :steps:
        1. Run 'sssctl user-checks root' against that service
    :expectedresults:
        1. Authentication is reported unavailable, never routed through certificate auth
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")
    client.fs.write(
        "/etc/pam.d/pam_sss_try_sc",
        """
        auth        required        pam_sss.so try_cert_auth
        account     required        pam_sss.so
        password    required        pam_sss.so
        session     required        pam_sss.so
        """,
    )

    result = client.sssctl.user_checks("root", action="auth", service="pam_sss_try_sc", auth_input=TOKEN_PIN)
    assert (
        "pam_authenticate for user [root]: Authentication service cannot retrieve authentication info" in result.stderr
    ), f"root should never be routed through certificate authentication! stderr={result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("username_input", ["", " "], ids=["empty_name", "whitespace_only_name"])
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__certificate_owner_resolved_when_username_is_missing(client: Client, username_input: str):
    """
    :title: allow_missing_name resolves the certificate owner when no username is given
    :setup:
        1. Create a local user and initialize a smart card mapped to the user
    :steps:
        1. Authenticate against the 'smartcard-auth' service with an empty or
           whitespace-only username and the smart card PIN
    :expectedresults:
        1. Authentication succeeds and is resolved to the certificate's mapped user
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")
    client.authselect.select("sssd", ["with-smartcard-required"])
    client.sssd.pam["pam_p11_allowed_services"] = "+smartcard-auth"
    client.sssd.restart()

    result = client.sssctl.user_checks(username_input, action="auth", service="smartcard-auth", auth_input=TOKEN_PIN)
    assert (
        "pam_authenticate for user [user1]: Success" in result.stderr
    ), f"Certificate owner was not resolved! stderr={result.stderr}"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__certificate_owner_resolved_with_full_name_format(client: Client):
    """
    :title: allow_missing_name respects full_name_format when resolving the certificate owner
    :setup:
        1. Create a local user and initialize a smart card mapped to the user
        2. Enable fully-qualified names with a custom 'full_name_format'
    :steps:
        1. Authenticate against the 'smartcard-auth' service with no username and the smart card PIN
    :expectedresults:
        1. Authentication succeeds and the resolved user name matches 'full_name_format'
    :customerscenario: True
    """
    client.local.user("user1").add()
    client.smartcard.setup_local_card(client, "user1")
    client.authselect.select("sssd", ["with-smartcard-required"])
    client.sssd.pam["pam_p11_allowed_services"] = "+smartcard-auth"
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.domain["full_name_format"] = "%2$s\\%1$s"
    client.sssd.restart(clean=True)

    result = client.sssctl.user_checks("", action="auth", service="smartcard-auth", auth_input=TOKEN_PIN)
    assert (
        "pam_authenticate for user [local\\user1]: Success" in result.stderr
    ), f"Certificate owner was not resolved with full_name_format applied! stderr={result.stderr}"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("cert_selection", [1, 2])
def test_smartcard__certificate_owner_resolved_with_two_tokens_and_missing_name(client: Client, cert_selection: int):
    """
    :title: allow_missing_name resolves the certificate owner when two tokens are present
    :setup:
        1. Create a local user
        2. Reset the certificate CA trust store to a clean state
        3. Initialize two SoftHSM tokens, each holding a certificate mapped to the user,
           and trust both certificates in the CA trust store
        4. Configure SSSD for smart card authentication and start services
    :steps:
        1. Authenticate against the 'smartcard-auth' service with no username, selecting
           each certificate in turn
    :expectedresults:
        1. Authentication succeeds and is resolved to the certificate's mapped user for
           either certificate selection
    :customerscenario: True
    """
    username = "user1"
    client.local.user(username).add()
    client.host.fs.rm("/etc/sssd/pki/sssd_auth_ca_db.pem")

    key1, cert1 = client.smartcard.generate_cert(key_path="/tmp/sc_token1.key", cert_path="/tmp/sc_token1.crt")
    client.smartcard.initialize_card(label=TOKEN1_LABEL, user_pin=TOKEN_PIN, reset=True)
    client.smartcard.add_key(key1, token_label=TOKEN1_LABEL, label=username)
    client.smartcard.add_cert(cert1, token_label=TOKEN1_LABEL, label=username)
    key2, cert2 = client.smartcard.generate_cert(key_path="/tmp/sc_token2.key", cert_path="/tmp/sc_token2.crt")
    client.smartcard.initialize_card(label=TOKEN2_LABEL, user_pin=TOKEN_PIN, reset=False)
    client.smartcard.add_key(key2, token_label=TOKEN2_LABEL, label=username)
    client.smartcard.add_cert(cert2, token_label=TOKEN2_LABEL, label=username)

    client.sssd.common.local()
    client.sssd.section(f"certmap/local/{username}")["matchrule"] = "<SUBJECT>.*CN=Test Cert.*"
    client.sssd.pam["pam_cert_auth"] = "True"
    for cert in (cert1, cert2):
        # dedent=False is required here: fs.append() strips trailing whitespace,
        # by default which will corrupt the CA bundle.
        client.host.fs.append(
            "/etc/sssd/pki/sssd_auth_ca_db.pem", client.host.fs.read(cert).strip() + "\n", dedent=False
        )
    client.sssd.common.smartcard_with_softhsm(client.smartcard)
    client.authselect.select("sssd", ["with-smartcard-required", "with-mkhomedir"])
    client.sssd.pam["pam_p11_allowed_services"] = "+smartcard-auth"
    client.sssd.restart()

    result = client.sssctl.user_checks(
        "", action="auth", service="smartcard-auth", auth_input=f"{cert_selection}\n{TOKEN_PIN}"
    )
    assert (
        f"pam_authenticate for user [{username}]: Success" in result.stderr
    ), f"Certificate owner was not resolved! stderr={result.stderr}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
@pytest.mark.parametrize(
    "local_auth_policy, auth_input, expected",
    [
        (None, None, "Password:"),
        ("enable:smartcard", TOKEN_PIN, "pam_authenticate for user [user1]: Success"),
    ],
    ids=["password_fallback_when_smartcard_not_enabled", "smartcard_when_local_auth_policy_enables_it"],
)
def test_smartcard__proxy_auth_uses_password_or_smartcard_based_on_local_auth_policy(
    client: Client, local_auth_policy: str | None, auth_input: str | None, expected: str
):
    """
    :title: Proxy domain falls back to password unless local smartcard auth is enabled
    :description:
        With a smart card present, a proxy domain only offers password auth by default
        (``local_auth_policy`` match). Enabling ``enable:smartcard`` switches the prompt
        to the smart card PIN and authenticates with the certificate.
    :setup:
        1. Create a local user with a password
        2. Enroll a smart card certificate mapped to the user
        3. Install a minimal PAM service that only stacks ``pam_sss.so``
    :steps:
        1. Configure a proxy/files domain with ``pam_cert_auth`` and the parametrized
           ``local_auth_policy``, then start SSSD
        2. Authenticate via ``sssctl user-checks`` against that PAM service
    :expectedresults:
        1. SSSD starts with the requested local authentication policy
        2. Without smartcard enabled a password prompt is shown; with
           ``enable:smartcard`` authentication succeeds with the PIN
    :customerscenario: True
    :requirement: smartcard_authentication
    """
    client.local.user("user1").add(password="Secret123")

    client.host.fs.rm("/etc/sssd/pki/sssd_auth_ca_db.pem")
    key, cert = client.smartcard.generate_cert()
    client.smartcard.initialize_card()
    client.smartcard.add_key(key)
    client.smartcard.add_cert(cert)
    client.authselect.select("sssd", ["with-smartcard"])
    client.svc.restart("virt_cacard.service")

    client.fs.write(
        "/etc/pam.d/pam_sss_service",
        """
        auth        required        pam_sss.so
        account     required        pam_sss.so
        password    required        pam_sss.so
        session     required        pam_sss.so
        """,
    )

    client.sssd.common.local()
    if local_auth_policy is not None:
        client.sssd.dom("local")["local_auth_policy"] = local_auth_policy
    client.sssd.section("certmap/local/user1")["matchrule"] = "<SUBJECT>.*CN=Test Cert.*"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.pam["pam_p11_allowed_services"] = "+pam_sss_service"
    client.host.fs.append("/etc/sssd/pki/sssd_auth_ca_db.pem", client.host.fs.read(cert), dedent=False)
    client.sssd.start()

    result = client.host.conn.exec(
        ["sssctl", "user-checks", "user1", "-a", "auth", "-s", "pam_sss_service"],
        input=auth_input,
        raise_on_error=False,
    )
    assert expected in result.stderr, f"Unexpected authentication prompt or result! stderr={result.stderr}"

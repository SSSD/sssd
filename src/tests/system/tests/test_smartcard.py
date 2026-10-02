"""
SSSD smart card authentication test

:requirement: smartcard_authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

TOKEN_PIN = "123456"


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


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="virtualsmartcard")
@pytest.mark.parametrize(
    "local_auth_policy, auth_input, expected",
    [
        (None, "Secret123", "Password: pam_authenticate for user [user1]: Success"),
        ("enable:smartcard", TOKEN_PIN, "PIN for Test Cert: pam_authenticate for user [user1]: Success"),
    ],
    ids=["password_fallback_when_smartcard_not_enabled", "smartcard_when_local_auth_policy_enables_it"],
)
def test_smartcard__proxy_auth_uses_password_or_smartcard_based_on_local_auth_policy(
    client: Client, local_auth_policy: str | None, auth_input: str, expected: str
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
        3. Install a PAM service that tries certificate auth then falls back to ``pam_unix.so``
    :steps:
        1. Configure a proxy/files domain with ``pam_cert_auth`` and the parametrized
           ``local_auth_policy``, then start SSSD
        2. Authenticate via ``sssctl user-checks`` against that PAM service
    :expectedresults:
        1. SSSD starts with the requested local authentication policy
        2. Without smartcard enabled password authentication succeeds; with
           ``enable:smartcard`` PIN authentication succeeds
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
        auth        sufficient      pam_sss.so try_cert_auth
        auth        sufficient      pam_unix.so
        auth        required        pam_deny.so
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

    result = client.sssctl.user_checks("user1", action="auth", service="pam_sss_service", auth_input=auth_input)
    assert expected in result.stderr, f"Unexpected authentication prompt or result! stderr={result.stderr}"

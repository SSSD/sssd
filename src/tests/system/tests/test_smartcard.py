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

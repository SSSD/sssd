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

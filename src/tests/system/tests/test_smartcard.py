"""
SSSD smart card authentication test

:requirement: smartcard_authentication
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology

TOKEN1_LABEL = "SC_Token_1"
TOKEN2_LABEL = "SC_Token_2"
TOKEN_PIN = "123456"


def enroll_to_token(
    client: Client,
    ipa: IPA,
    username: str,
    *,
    token_label: str,
    cert_id: str = "01",
    pin: str = TOKEN_PIN,
) -> None:
    """
    Request an IPA-signed certificate for *username* and store it on *token_label*.

    :param client: Client role object.
    :type client: Client
    :param ipa: IPA role object whose CA issues the certificate.
    :type ipa: IPA
    :param username: IPA principal to issue the certificate for.
    :type username: str
    :param token_label: SoftHSM token label to write the objects to.
    :type token_label: str
    :param cert_id: PKCS#11 object ID, defaults to "01".
    :type cert_id: str, optional
    :param pin: User PIN for the token, defaults to TOKEN_PIN.
    :type pin: str, optional
    """
    cert, key, _ = ipa.ca.request(username)
    cert_content = ipa.fs.read(cert)
    key_content = ipa.fs.read(key)

    cert_path = f"/opt/test_ca/{username}_{token_label}.crt"
    key_path = f"/opt/test_ca/{username}_{token_label}.key"

    client.fs.write(cert_path, cert_content)
    client.fs.write(key_path, key_content)

    client.smartcard.add_key(key_path, key_id=cert_id, pin=pin, token_label=token_label, label=username)
    client.smartcard.add_cert(cert_path, cert_id=cert_id, pin=pin, token_label=token_label, label=username)


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
    client.smartcard.initialize_card(label=TOKEN1_LABEL, user_pin=TOKEN_PIN)
    enroll_to_token(client, ipa, token1_username, token_label=TOKEN1_LABEL)

    client.smartcard.initialize_additional_token(label=TOKEN2_LABEL, user_pin=TOKEN_PIN)
    enroll_to_token(client, ipa, token2_username, token_label=TOKEN2_LABEL)


def configure_sssd_for_smartcard(client: Client) -> None:
    """
    Configure SSSD and the client for smart card authentication with SoftHSM multi-token support.

    :param client: Client role object.
    :type client: Client
    """
    client.smartcard.register_for_p11_child()
    client.authselect.select("sssd", ["with-smartcard", "with-mkhomedir"])
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.domain["local_auth_policy"] = "enable:smartcard"
    client.sssd.start()


def authenticate_with_smartcard(client: Client, username: str, pin: str, *, num_certs: int = 1) -> None:
    """
    Wait for the user to become resolvable then authenticate via nested ``su`` with the PIN.

    :param client: Client role object.
    :type client: Client
    :param username: IPA username to authenticate as.
    :type username: str
    :param pin: Smart card PIN.
    :type pin: str
    :param num_certs: Number of certificates that map to the user, defaults to 1.
    :type num_certs: int, optional
    """
    cached = None
    for attempt in range(15):
        time.sleep(2)
        cached = client.tools.getent.passwd(username)
        if cached is not None:
            break
        if attempt == 3:
            client.host.conn.run("sss_cache -E", raise_on_error=False)

    assert cached is not None, f"User '{username}' was not resolvable by SSSD after multiple attempts"

    su_input = f"1\n{pin}" if num_certs > 1 else pin

    result = client.host.conn.run(
        f"su - {username} -c 'su - {username} -c whoami'",
        input=su_input,
        raise_on_error=False,
    )
    assert result.rc == 0, f"su failed (rc={result.rc}):\nstdout={result.stdout}\nstderr={result.stderr}"
    assert (
        "PIN" in result.stderr
    ), f"PIN prompt not found in stderr — smart card auth was not triggered.\nstderr={result.stderr}"
    assert username in result.stdout, f"'{username}' not found in whoami output.\nstdout={result.stdout}"


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
@pytest.mark.builtwith(client="virtualsmartcard")
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
    configure_sssd_for_smartcard(client)
    authenticate_with_smartcard(client, username, TOKEN_PIN)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
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
    configure_sssd_for_smartcard(client)
    authenticate_with_smartcard(client, username, TOKEN_PIN)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="virtualsmartcard")
def test_smartcard__two_tokens_match_on_both(client: Client, ipa: IPA):
    """
    :title: Two smart cards – valid certificate on both tokens
    :setup:
        1. Create IPA user
        2. Initialize two SoftHSM tokens (simulating two smart cards)
        3. Place a valid IPA certificate for the same user on both tokens
        4. Configure SSSD for smart card authentication and start services
    :steps:
        1. Authenticate as the IPA user via nested ``su`` with the PIN of
           the first token
    :expectedresults:
        1. SSSD's ``p11_child`` finds valid certificates on both tokens and
           authentication succeeds regardless of which token is tried first
    :customerscenario: True
    """
    username = "scuser_both"
    ipa.user(username).add()

    setup_two_tokens(client, ipa, token1_username=username, token2_username=username)
    configure_sssd_for_smartcard(client)
    authenticate_with_smartcard(client, username, TOKEN_PIN, num_certs=2)

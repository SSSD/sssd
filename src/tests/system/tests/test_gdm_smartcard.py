"""
SSSD Passwordless GDM Smart Card Tests

:requirement: Passwordless GDM
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


def client_setup_for_smartcard(client: Client, provider: IPA | LDAP):
    """
    Setup client for smart card authentication testing.

    This helper function configures the SSSD client with all necessary
    settings for smart card authentication against an IPA server, including
    certificate enrollment and authselect configuration.

    :param client: Client role object for SSSD configuration
    :type client: Client
    :param provider: Provider role object to determine some settings
    :type provider: IPA | LDAP
    """

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir", "with-smartcard", "with-switchable-auth"])
    client.sssd.import_domain(provider.domain, provider)
    client.sssd.config.remove_section("domain/test")
    client.sssd.default_domain = provider.domain
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["passkey_child_timeout"] = "30"

    if provider.name.lower() != "ldap":
        client.sssd.pam["pam_cert_auth"] = "True"
    else:
        client.sssd.domain["local_auth_policy"] = "enable:passkey"

    client.sssd.start()


def enroll_smartcard(client: Client, provider: IPA, username: str, id: str = "01", init: bool = True):
    """
    Enroll smart card with IPA provider

    :param client: Client role object for setting up smart card
    :type client: Client
    :param provider: Provider role object to request certificate from CA
    :type provider: IPA is the only type currently supported
    :param username: Username for certificate request
    :type username: str
    :param id: Smart card certificate ID number
    :type id: str
    :param init: Determine if the smart card should be initialized
    :type init: bool
    """
    cert, key, _ = provider.ca.request(username)
    cert_content = provider.fs.read(cert)
    key_content = provider.fs.read(key)
    client.fs.write(f"/opt/test_ca/{username}_{id}.crt", cert_content)
    client.fs.write(f"/opt/test_ca/{username}_{id}.key", key_content)
    if init:
        client.smartcard.initialize_card()
    client.smartcard.add_key(f"/opt/test_ca/{username}_{id}.key", key_id=id)
    client.smartcard.add_cert(f"/opt/test_ca/{username}_{id}.crt", cert_id=id)
    client.svc.restart("virt_cacard.service")


@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.builtwith(client="gdm")
def test_gdm__smartcard_login_with_pin(client: Client, ipa: IPA):
    """
    :title: Login via GDM using smart card with PIN
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Add user to domain
        3. Enroll smart card in domain for user
    :steps:
        1. Login through GDM using smart card with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "ipacertuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_smartcard(client, ipa)

    # Add IPA User
    ipa.user(testuser).add()

    # Enroll smartcard with first key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser, id="01")

    # Authenticate to GDM with smart card
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("PIN")
    client.gdm.kb_write(pin)
    assert client.gdm.check_home_screen()
    client.gdm.done()


@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="vfido")
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__smartcard_login_with_incorrect_pin(client: Client, ipa: IPA):
    """
    :title: Login via GDM using smart card with incorrect PIN
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Add user to domain
        3. Enroll smart card with domain for user
    :steps:
        1. Attempt to login through GDM using smart card with incorrect PIN
    :expectedresults:
        1. Authentication denied and user prompted to re-enter PIN
    :customerscenario: False
    """

    testuser = "ipacertuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_smartcard(client, ipa)

    # Add IPA User
    ipa.user(testuser).add()

    # Enroll smartcard with key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser)

    # Authenticate to GDM with smart card
    client.gdm.click_on("listed?")
    client.gdm.kb_send("tab")
    client.gdm.click_on("Username")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.kb_send("enter")
    client.gdm.click_on("Smartcard")

    client.gdm.kb_write(pin[:-1])
    time.sleep(5)
    assert client.gdm.assert_text("PIN"), "No new PIN prompt! User may have logged in with incorrect PIN!"
    client.gdm.done()


@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.builtwith(client="gdm")
def test_gdm__smartcard_login_with_certs_and_passkey(client: Client, ipa: IPA):
    """
    :title: Login via GDM using smart card and passkey
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service
        3. Add user to domain and set auth type to passkey
        4. Enroll smart card with domain for user
        5. Enroll smart card with second set of Key/Certs
        6. Register passkey with domain user
    :steps:
        1. Login through GDM using smart card with PIN
        2. Reset Journal cursor to avoid false match in wait_for_login
        3. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
        2. Journal cursor reset with no errors
        3. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "ipacertuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_smartcard(client, ipa)

    # Start virtual passkey service with PIN enabled and set
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add(user_auth_type=["passkey"])

    # Enroll smartcard with first key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser, id="01")

    # Enroll smartcard with second key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser, id="02", init=False)

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    # Authenticate to GDM with smart card
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("CAC ID Certificate")
    client.gdm.kb_write(pin)
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen()
    client.gdm.done()

    # Reset journal cursor to avoid false match in wait_for_login
    # from previous login
    client.journald.clear()

    # Authenticate to GDM with passkey
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.kb_send("tab")
    client.gdm.kb_send("enter")
    client.gdm.click_on("Passkey")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen()
    client.gdm.done()

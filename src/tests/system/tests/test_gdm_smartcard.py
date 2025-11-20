from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


def client_setup_for_smartcard(client, provider: IPA | LDAP | GenericProvider, pin: str | int | None = None):
    # Configure SSSD
    client.authselect.select(
        "sssd", ["with-mkhomedir", "with-smartcard", "with-switchable-auth"]
    )
    client.sssd.import_domain(provider.domain, provider)
    client.sssd.config.remove_section("domain/test")
    client.sssd.default_domain = provider.domain
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"

    if provider.name.lower() != "ldap":
        client.sssd.pam["pam_cert_auth"] = "True"
    else:
        client.sssd.domain["local_auth_policy"] = "enable:passkey"

    client.sssd.start()


def enroll_smartcard(client, provider: IPA, username: str, id: str = "01", init: bool = True):
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


@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="vfido")
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__smartcard_login_with_incorrect_pin(client: Client, ipa: IPA):
    testuser = "ipacertuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_smartcard(client, ipa, pin=pin)

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
    assert client.gdm.assert_text(
        f"Smartcard PIN"
    ), "No new PIN prompt! User may have logged in with incorrect PIN!"
    client.gdm.done()


@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.builtwith(client="gdm")
def test_gdm__smartcard_login_with_certs_and_passkey(client: Client, ipa: IPA):
    testuser = "ipacertuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_smartcard(client, ipa, pin=pin)

    # Start virtual passkey service with PIN enabled and set
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Enroll smartcard with first key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser, id="01")

    time.sleep(1)

    # Enroll smartcard with second key/cert issued from IPA
    enroll_smartcard(client, ipa, testuser, id="02", init=False)

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type=["passkey", "pkinit"])

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    # Authenticate to GDM with smart card
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("CAC ID Certificate")
    client.gdm.kb_write(pin)
    time.sleep(5)
    client.gdm.check_home_screen()
    client.gdm.done()

    # Authenticate to GDM with passkey
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.kb_send("tab")
    client.gdm.kb_send("enter")
    client.gdm.click_on("Passkey")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    time.sleep(5)
    client.gdm.check_home_screen()
    client.gdm.done()

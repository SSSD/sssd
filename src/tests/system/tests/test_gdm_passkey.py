"""
SSSD Passwordless GDM Passkey Tests

:requirement: Passwordless GDM
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


def client_setup_for_passkey(client, provider: IPA | LDAP | GenericProvider, pin: str | int | None = None):
    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir", "with-smartcard", "with-switchable-auth"])
    client.sssd.import_domain(provider.domain, provider)
    client.sssd.config.remove_section("domain/test")
    client.sssd.default_domain = provider.domain
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"

    if provider.name.lower() != "ldap":
        client.sssd.pam["pam_cert_auth"] = "True"
    else:
        client.sssd.domain["local_auth_policy"] = "enable:passkey"

    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    if pin is not None:
        client.vfido.pin_enable()
        client.vfido.pin_set(pin)
    else:
        client.vfido.pin_disable()
    client.vfido.start()


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_with_pin(client: Client, ipa: IPA):
    """
    :title: Login via GDM using passkey with PIN
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey
        5. Register passkey with IPA user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=pin)

    # Add IPA User
    ipa.user(testuser).add(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_no_pin(client: Client, ipa: IPA):
    """
    :title:  Login via GDM using passkey with no PIN set
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service with PIN disabled
        4. Add user to IPA and set auth_type to passkey
        5. Allow authentication without PIN for IPA users
        6. Register passkey with IPA user
    :steps:
        1. Login through GDM using Passkey without PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=None)

    # Add IPA User
    ipa.user(testuser).add(user_auth_type="passkey")

    # Allow authentication without PIN for IPA users
    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=False", raise_on_error=False)

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=None, virt_type="vfido")

    # Login through GDM without PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_send("enter")
    client.gdm.kb_send("tab")
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"

    # Make sure verification is set to true
    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=True", raise_on_error=False)


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_with_password(client: Client, ipa: IPA):
    """
    :title: Login via GDM with password as user with passkey registered

    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey and password
        6. Register passkey with IPA user
    :steps:
        1. Login through GDM using Password
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"
    password = "Secret123"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=pin)

    # Add IPA User
    ipa.user(testuser).add(password=password, user_auth_type=["passkey", "password"])

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    # Change login from passkey to password and login
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.kb_send("enter")
    # First select Password from authentication method selection
    client.gdm.click_on("Password")
    # Then select Password entry field
    client.gdm.click_on("Password")
    client.gdm.kb_write(password)
    client.gdm.wait_for_login(client)

    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_with_multiple_keys(client: Client, ipa: IPA):
    """
    :title: Login via GDM with passkey as user with multiple keys on device

    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey
        5. Register passkey with IPA user
        6. Register another passkey with IPA user on same device
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=pin)

    # Add IPA User
    ipa.user(testuser).add(user_auth_type="passkey")

    time.sleep(1)

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    time.sleep(1)

    # Register passkey with IPA User again to get second key
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_remove_passkey_mapping(client: Client, ipa: IPA):
    """
    :title: Login via GDM fails when passkey mapping removed from user
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey
        5. Register passkey with IPA user
        6. Remove user passkey mapping from IPA
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login unsuccessful and user prompted for password
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=pin)

    # Add IPA User
    ipa.user(testuser).add(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    result = ipa.user(testuser).get(["ipapasskey"])
    if result is not None:
        ipa.user(testuser).passkey_remove(result["ipapasskey"][0])
    else:
        raise ValueError(f"ipa.user({testuser}) passkey mapping not found")

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    assert client.gdm.assert_text("Password"), "User was not prompted for Password as expected!"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_with_unregistered_mapping(client: Client, ipa: IPA):
    """
    :title: Login via GDM fails with unregistered passkey mapping
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey
        5. Register passkey with IPA user
        6. Remove user passkey mapping from IPA
        7. Add bad passkey mapping to user in IPA
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login unsuccessful and user is prompted again for PIN
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"
    bad_mapping = (
        "passkey:oMpNJz5y4YLCB48dJGmAJQ==,"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEd6cT8vlg7JHt6VJ"
        "/NfE7TW+T/NrbNLZJdK2qewFUMicptYaD8FWDWYboeKPt17ukFRnDZj2VrDx70UYMMsXFA=="
    )

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ipa, pin=pin)

    # Add IPA User
    ipa.user(testuser).add(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    pytest.set_trace()

    # Remove passkey mapping
    result = ipa.user(testuser).get(["ipapasskey"])
    if result is not None:
        ipa.user(testuser).passkey_remove(result["ipapasskey"][0])
    else:
        raise ValueError(f"ipa.user({testuser}) passkey mapping not found")

    # Add bad passkey mapping instead
    ipa.user(testuser).passkey_add(bad_mapping)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)

    client.gdm.kb_send("tab")
    assert client.gdm.assert_text("Security key PIN"), "User was not prompted again for PIN as expected!"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_gdm__passkey_local_with_pin(client: Client, ldap: LDAP):
    """
    :title: Login via GDM using passkey with PIN with a local setup
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to IPA and set auth_type to passkey
        5. Register passkey with IPA user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ldap, pin=pin)

    # Add IPA User
    ldap.user(testuser).add()

    # Register passkey with sssctl command locally on the client
    mapping = client.sssctl.passkey_register(username=testuser, domain="ldap.test", pin=123456, virt_type="vfido")

    # Add passkey mapping to user in ldap
    ldap.user(testuser).passkey_add(mapping)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    client.gdm.wait_for_login(client)

    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.skip(reason="local no pin test not yet working")
@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_gdm__passkey_local_no_pin(client: Client, ldap: LDAP):
    """
    :title: Login via GDM using passkey with no PIN set with a local setup
    :setup:
        1. Configure SSSD for gdm-switchable-auth
        2. Start SSSD
        3. Start virtual passkey service
        4. Add user to LDAP
        5. Register passkey with sssctl for LDAP user
        6. Add passkey mapping to LDAP user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"

    # Configure SSSD and vfido
    client_setup_for_passkey(client, ldap, pin=None)

    # Add IPA User
    ldap.user(testuser).add()

    # Register passkey with sssctl command locally on the client
    mapping = client.sssctl.passkey_register(username=testuser, domain="ldap.test", pin=None, virt_type="vfido")

    # Add passkey mapping to user in ldap
    ldap.user(testuser).passkey_add(mapping)

    # Login through GDM without PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_send("enter")
    client.gdm.kb_send("tab")
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"

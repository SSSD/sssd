from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.GDM_IPA)
def test_gdm__passkey_login(client: Client, ipa: IPA):
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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    time.sleep(5)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


# Currently failing.  appears to not recognize touch action
@pytest.mark.topology(KnownTopology.GDM_IPA)
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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service with PIN disabled
    client.vfido.reset()
    client.vfido.pin_disable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type="passkey")

    # Allow authentication without PIN for IPA users
    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=False", raise_on_error=False)

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client)

    pytest.set_trace()

    # Login through GDM without PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    time.sleep(5)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


# Currently failing.   Does not fallback to Password prompt with empty PIN
@pytest.mark.topology(KnownTopology.GDM_IPA)
def test_gdm__passkey_login_with_password(client: Client, ipa: IPA):
    """
    :title: Login via GDM with password as user with passkey registered

    !!!Currently no key selection presented to user.  May require updates.!!!

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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add(password=password)

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type=["passkey", "password"])

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    # Currently does not fallback to Password prompt with empty PIN
    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_send("enter")
    client.gdm.kb_send("tab")
    client.gdm.click_on("Password")
    assert client.gdm.kb_write(password)
    time.sleep(5)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.topology(KnownTopology.GDM_IPA)
def test_gdm__passkey_login_with_multiple_keys(client: Client, ipa: IPA):
    """
    :title: Login via GDM with passkey as user with multiple keys on device

    !!!Currently no key selection presented to user.  May require updates.!!!

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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    # Register passkey with IPA User again to get second key
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.vfido.touch()
    time.sleep(5)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.topology(KnownTopology.GDM_IPA)
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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    result = ipa.host.conn.run("ipa user-show pkgdmuser1 --raw |grep ipapasskey:|awk '{print $2}'")
    ipa.user(testuser).passkey_remove(result.stdout)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    assert client.gdm.assert_text("Password"), "User was not prompted for Password as expected!"


@pytest.mark.topology(KnownTopology.GDM_IPA)
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

    # Configure SSSD
    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.pam["pam_p11_allowed_services"] = "+gdm-switchable-auth"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.start()

    # Start virtual passkey service
    client.vfido.reset()
    client.vfido.pin_set(pin)
    client.vfido.pin_enable()
    client.vfido.start()

    # Add IPA User
    ipa.user(testuser).add()

    # Set user_auth_type to passkey
    ipa.user(testuser).modify(user_auth_type="passkey")

    # Register passkey with IPA User
    ipa.user(testuser).vfido_passkey_add_register(client, pin=pin)

    # Remove passkey mapping
    result = ipa.host.conn.run("ipa user-show pkgdmuser1 --raw |grep ipapasskey:|awk '{print $2}'")
    ipa.user(testuser).passkey_remove(result.stdout)

    # Add bad passkey mapping instead
    ipa.user(testuser).passkey_add(bad_mapping)

    # Login through GDM with PIN
    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)

    # Need a better check for failure?
    # client.gdm.assert_text("Sorry") # doesn't remain long enough to capture
    client.gdm.kb_send("tab")
    assert client.gdm.assert_text("Security key PIN"), "User was not prompted again for PIN as expected!"

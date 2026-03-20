"""
SSSD Passwordless GDM Tests

:requirement: Passwordless GDM
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology
from sssd_test_framework.utils.authentication import KerberosAuthenticationUtils as kerberos


def client_setup_vfido(client: Client, pin: str | int | None = None):
    """
    Setup virtual passkey for authentication testing

    :param client: Client object
    :type client: Client
    :param pin: passkey PIN. If None, disable in vfido, else set PIN
    :type pin: str | int | None
    """
    # Start virtual passkey service
    client.vfido.reset()
    if pin is not None:
        client.vfido.pin_enable()
        client.vfido.pin_set(pin)
    else:
        client.vfido.pin_disable()
    client.vfido.start()


def client_setup_sssd(client: Client, provider: IPA | LDAP):
    """
    Setup client SSSD configuration for testing smart card and passkey

    :param client: Client object
    :type client: Client
    :param provider: Provider object
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


def client_setup_xidp(client: Client, ipa: IPA, keycloak: Keycloak, testuser: str):
    """
    Setup client host and creates and maps test user in keycloak and ipa for
    External IdP Authentication

    :param client: Client object
    :type client: Client
    :param ipa: IPA object
    :type ipa: IPA
    :param keycloak: Keycloak object
    :type keycloak: Keycloak
    :param testuser: User to configure for External IdP authentication
    """
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-switchable-auth"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)


def enroll_smartcard(client: Client, provider: IPA, username: str, id: str = "01", init: bool = True):
    """
    Enroll smart card with IPA provider

    :param client: Client object
    :type client: Client
    :param provider: Provider object
    :type provider: IPA is the only type currently supported
    :param username: Username for certificate request
    :type username: str
    :param id: Smart card certificate ID number
    :type id: str
    :param init: Initialize smart card
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


@pytest.mark.importance("critical")
@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_succeeds_with_pin(client: Client, ipa: IPA):
    """
    :title: Login via GDM using passkey with PIN
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to IPA and set auth_type to passkey
        4. Register passkey with IPA user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=pin)

    ipa.user(testuser).add(user_auth_type="passkey")

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_succeeds_when_pin_disabled(client: Client, ipa: IPA):
    """
    :title:  Login via GDM using passkey with no PIN set
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service with PIN disabled and start SSSD
        3. Add user to IPA and set auth_type to passkey
        4. Allow authentication without PIN for IPA users
        5. Register passkey with IPA user
    :steps:
        1. Login through GDM using Passkey without PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=None)

    ipa.user(testuser).add(user_auth_type="passkey")

    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=False", raise_on_error=False)

    ipa.user(testuser).passkey_add_register(client=client, pin=None, virt_type="vfido")

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_send("enter")
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"

    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=True", raise_on_error=False)


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_succeeds_with_password_instead_of_pin(client: Client, ipa: IPA):
    """
    :title: Login via GDM with password as user with passkey registered

    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to IPA and set auth_type to passkey and password
        4. Register passkey with IPA user
    :steps:
        1. Login through GDM using Password
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"
    password = "Secret123"

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=pin)

    ipa.user(testuser).add(password=password, user_auth_type=["passkey", "password"])

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

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
def test_gdm__passkey_login_succeeds_with_multiple_keys(client: Client, ipa: IPA):
    """
    :title: Login via GDM with passkey as user with multiple keys on device

    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to IPA and set auth_type to passkey
        4. Register passkey with IPA user
        5. Register another passkey with IPA user on same device
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=pin)

    ipa.user(testuser).add(user_auth_type="passkey")

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_rejected_when_passkey_mapping_removed(client: Client, ipa: IPA):
    """
    :title: Login via GDM fails when passkey mapping removed from user
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to IPA and set auth_type to passkey
        4. Register passkey with IPA user
        5. Remove user passkey mapping from IPA
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login unsuccessful and user prompted for password
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=pin)

    ipa.user(testuser).add(user_auth_type="passkey")

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    result = ipa.user(testuser).get(["ipapasskey"])
    if result is not None:
        ipa.user(testuser).passkey_remove(result["ipapasskey"][0])
    else:
        raise ValueError(f"ipa.user({testuser}) passkey mapping not found")

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    assert client.gdm.assert_text("Password"), "User was not prompted for Password as expected!"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareIPA)
def test_gdm__passkey_login_rejected_with_unregistered_mapping(client: Client, ipa: IPA):
    """
    :title: Login via GDM fails with unregistered passkey mapping
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to IPA and set auth_type to passkey
        4. Register passkey with IPA user
        5. Remove user passkey mapping from IPA
        6. Add bad passkey mapping to user in IPA
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

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin=pin)

    ipa.user(testuser).add(user_auth_type="passkey")

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

    result = ipa.user(testuser).get(["ipapasskey"])
    if result is not None:
        ipa.user(testuser).passkey_remove(result["ipapasskey"][0])
    else:
        raise ValueError(f"ipa.user({testuser}) passkey mapping not found")

    ipa.user(testuser).passkey_add(bad_mapping)

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    assert client.gdm.assert_text("Security key PIN"), "User was not prompted again for PIN as expected!"


@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_gdm__passkey_local_login_succeeds_with_pin(client: Client, ldap: LDAP):
    """
    :title: Login via GDM using passkey with PIN with a local setup
    :setup:
        1. Configure SSSD for gdm-switchable-auth and pam_cert_auth
        2. Start virtual passkey service and start SSSD
        3. Add user to LDAP
        4. Register passkey with LDAP user
        5. Add passkey mapping to LDAP user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"
    pin = "123456"

    client_setup_sssd(client, ldap)

    client_setup_vfido(client, pin=pin)

    ldap.user(testuser).add()

    mapping = client.sssctl.passkey_register(username=testuser, domain="ldap.test", pin=123456, virt_type="vfido")

    ldap.user(testuser).passkey_add(mapping)

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_write(pin)
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.skip(reason="local no pin test not yet working")
@pytest.mark.builtwith(client=["gdm", "passkey", "vfido"])
@pytest.mark.topology(KnownTopology.BareLDAP)
def test_gdm__passkey_local_login_succeeds_with_no_pin(client: Client, ldap: LDAP):
    """
    :title: Login via GDM using passkey with no PIN set with a local setup
    :setup:
        1. Configure SSSD for gdm-switchable-auth
        2. Start virtual passkey service and start SSSD
        3. Configure SSSD passkey user_verification to False
        4. Restart SSSD
        5. Add user to LDAP
        6. Register passkey with sssctl for LDAP user
        7. Add passkey mapping to LDAP user
    :steps:
        1. Login through GDM using Passkey with PIN
    :expectedresults:
        1. Login successful and user sees home screen
    :customerscenario: False
    """
    testuser = "pkgdmuser1"

    client_setup_sssd(client, ldap)

    client_setup_vfido(client, pin=None)

    client.sssd.sssd["passkey_verification"] = "user_verification=false"

    client.sssd.restart()

    ldap.user(testuser).add()

    mapping = client.sssctl.passkey_register(username=testuser, domain="ldap.test", pin=None, virt_type="vfido")

    ldap.user(testuser).passkey_add(mapping)

    client.gdm.click_on("listed?")
    client.gdm.kb_write(testuser)
    client.gdm.kb_send("tab")
    client.gdm.click_on("Security key PIN")
    client.gdm.kb_send("enter")
    client.gdm.assert_text("Touch security key")
    client.vfido.touch()
    client.gdm.wait_for_login(client)
    assert client.gdm.check_home_screen(), "User unable to login or see home screen"


@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.builtwith(client="gdm")
def test_gdm__smartcard_login_succeeds_with_pin(client: Client, ipa: IPA):
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

    client_setup_sssd(client, ipa)

    ipa.user(testuser).add()

    enroll_smartcard(client, ipa, testuser, id="01")

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
def test_gdm__smartcard_login_fails_with_incorrect_pin(client: Client, ipa: IPA):
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

    client_setup_sssd(client, ipa)

    ipa.user(testuser).add()

    enroll_smartcard(client, ipa, testuser)

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


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.BareIPA)
@pytest.mark.builtwith(client="gdm")
def test_gdm__smartcard_login_succeeds_with_certs_and_passkey(client: Client, ipa: IPA):
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

    client_setup_sssd(client, ipa)

    client_setup_vfido(client, pin)

    ipa.user(testuser).add(user_auth_type=["passkey"])

    enroll_smartcard(client, ipa, testuser, id="01")

    enroll_smartcard(client, ipa, testuser, id="02", init=False)

    ipa.user(testuser).passkey_add_register(client=client, pin=pin, virt_type="vfido")

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


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_rejected_for_invalid_password(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected with invalid password
    :setup:
        1. Setup client and creates and maps user in keycloak and ipa for External IdP Authentication
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login fails with invalid password
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"

    client_setup_xidp(client, ipa, keycloak, testuser)

    assert not client.gdm.login_idp(
        client, testuser, password[:-1]
    ), "GDM EIdP Login passed when it should have failed!"


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_rejected_when_user_disabled(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected when login is disabled
    :setup:
        1. Setup client and creates and maps user in keycloak and ipa for External IdP Authentication
        2. Disable user in Keycloak
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login fails for disabled user
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"

    client_setup_xidp(client, ipa, keycloak, testuser)

    keycloak.user(testuser).modify(enabled=False)

    assert not client.gdm.login_idp(client, testuser, password), "GDM EIdP Login passed when it should have failed!"


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_user_is_forced_to_change_password_before_login(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP when user must change their password
    :setup:
        1. Setup client and creates and maps user in keycloak and ipa for External IdP Authentication
        2. Set user to require password change at login in Keycloak
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login succeeds with password change and user sees the home screen.
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"

    client_setup_xidp(client, ipa, keycloak, testuser)

    keycloak.user(testuser).password_change_at_logon()

    assert client.gdm.login_idp(
        client, testuser, f"{password}:::NewPa55"
    ), "GDM EIdP Login with password change failed!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_succeeds_and_gets_kerberos_ticket(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user
    :setup:
        1. Setup client and creates and maps user in keycloak and ipa for External IdP Authentication
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
        2. Check if user has Kerberos ticket
    :expectedresults:
        1. Login succeeds and user sees the home screen.
        2. User has Kerberos ticket
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"

    client_setup_xidp(client, ipa, keycloak, testuser)

    assert client.gdm.login_idp(client, testuser, password), "GDM EIdP Login failed!"

    assert kerberos(client.host).user_has_tgt("kcgdmuser1", ipa.realm), "Kerberos ticket not found!"

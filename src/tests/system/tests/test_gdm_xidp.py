"""
SSSD Passwordless GDM External IdP Tests

:requirement: Passwordless GDM
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology
from sssd_test_framework.utils.authentication import KerberosAuthenticationUtils as kerberos


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_rejected_for_invalid_password(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected with invalid password
    :setup:
        1. Configure IPA for External IdP support
        2. Configure SSSD pam_json_services = gdm-switchable-auth
        3. Start SSSD
        4. Add user to Keycloak and set email address
        5. Add matching IPA user with idp user auth type
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login fails with invalid password
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-switchable-auth"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    assert not client.gdm.login_idp(
        client, testuser, password[:-1]
    ), "GDM EIdP Login passed when it should have failed!"


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_disabled(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected when login is disabled
    :setup:
        1. Configure IPA for External IdP support
        2. Configure SSSD pam_json_services = gdm-switchable-auth
        3. Start SSSD
        4. Add user to Keycloak and set email address
        5. Add matching IPA user with idp user auth type
        6. Disable user in Keycloak
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login fails for disabled user
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-switchable-auth"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)
    keycloak.user(testuser).modify(enabled=False)

    assert not client.gdm.login_idp(client, testuser, password), "GDM EIdP Login passed when it should have failed!"


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_password_change(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP when user must change their password
    :setup:
        1. Configure IPA for External IdP support
        2. Configure SSSD pam_json_services = gdm-switchable-auth
        3. Start SSSD
        4. Add user to Keycloak and set email address
        5. Add matching IPA user with idp user auth type
        6. Set user to require password change at login in Keycloak
    :steps:
        1. Login through GDM by authenticating with Keycloak from an external browser.
    :expectedresults:
        1. Login succeeds with password change and user sees the home screen.
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-switchable-auth"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    keycloak.user(testuser).password_change_at_logon()

    assert client.gdm.login_idp(
        client, testuser, f"{password}:::NewPa55"
    ), "GDM EIdP Login with password change failed!"


@pytest.mark.topology(KnownTopology.GDM)
@pytest.mark.builtwith(client="gdm")
@pytest.mark.builtwith(client="idp-provider")
def test_gdm__xidp_login_get_kerberos_ticket(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user
    :setup:
        1. Configure IPA for External IdP support
        2. Configure SSSD pam_json_services = gdm-switchable-auth
        3. Start SSSD
        4. Add user to Keycloak and set email address
        5. Add matching IPA user with idp user auth type
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
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-switchable-auth"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    assert client.gdm.login_idp(client, testuser, password), "GDM EIdP Login failed!"
    assert kerberos(client.host).user_has_tgt("kcgdmuser1", ipa.realm), "Kerberos ticket not found!"

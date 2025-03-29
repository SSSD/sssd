"""
SSSD Passwordless GDM Tests

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
def test_gdm__xidp_login(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. Follow IdP redirect url and follow steps to authorize request
        3. Complete login in GDM (select Done)
        4. Confirm user logged in by checking for home screen
    :expectedresults:
        1. User selected and login method (EIdP) chosen
        2. User connects to remote URL with browser and authorized request successfully
        3. User is logged into system
        4. User can see login home screen after login
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.import_domain("ipa.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    assert client.gdm.login_idp(client, testuser, password), "GDM EIdP Login failed!"


@pytest.mark.topology(KnownTopology.GDM)
def test_gdm__xidp_login_rejected_for_invalid_password(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected with invalid password
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user with authtype only set to 'idp'
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. Follow IdP redirect url and use invalid password to login via External IdP site
        3. Check logs for login denial
    :expectedresults:
        1. User selected and login method (EIdP) chosen
        2. User should see login rejected/denied error for invalid password
        3. Should see login denial in logs
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.sssd.import_domain("gdm.test", ipa)
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
def test_gdm__xidp_login_disabled(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected when login is disabled
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user with authtype only set to 'idp'
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. Follow IdP redirect url and login as user via External IdP site
        3. Check logs for login denial
    :expectedresults:
        1. User selected and login method (EIdP) chosen
        2. User connects to remote URL with browser and sees login is disabled
        3. Should see login denial in logs
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.sssd.import_domain("gdm.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)
    keycloak.user(testuser).modify(enabled=False)

    assert not client.gdm.login_idp(client, testuser, password), "GDM EIdP Login passed when it should have failed!"


@pytest.mark.topology(KnownTopology.GDM)
def test_gdm__xidp_login_password_change(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user is rejected when login is disabled
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user with authtype only set to 'idp'
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. Follow IdP redirect url and login as user via External IdP site
        3. Check logs for login denial
    :expectedresults:
        1. User selected and login method (EIdP) chosen
        2. User connects to remote URL with browser and sees login is disabled
        3. Should see login denial in logs
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.sssd.import_domain("gdm.test", ipa)
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
def test_gdm__xidp_login_get_kerberos_ticket(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user with authtype only set to 'idp'
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. Follow IdP redirect url and login as user via External IdP site
        3. Complete login in GDM (select Done)
        4. Confirm user logged in by checking for home screen
        5. Open terminal and check for Kerberos ticket
    :expectedresults:
        1. User selected and login method (EIdP) chosen
        2. User connects to remote URL with browser and enters login info successfully
        3. User is logged into system
        4. User can see login home screen after login
        5. User can see Kerberos ticket has been issued
    :customerscenario: False
    """
    testuser = "kcgdmuser1"
    password = "Secret123"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"

    client.sssd.import_domain("gdm.test", ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    assert client.gdm.login_idp(client, testuser, password), "GDM EIdP Login failed!"
    assert kerberos(client.host).user_has_tgt("kcgdmuser1", ipa.realm), "Kerberos ticket not found!"

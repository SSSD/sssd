from __future__ import annotations

import re
import json

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology
#from sssd_test_framework.roles.ad import AD


#@pytest.mark.topology(KnownTopology.AD)
#def test_gdm__AD(client: Client, ad: AD):
    #print(ad.host.conn.ssh.username)


#@pytest.mark.topology(KnownTopology.GDM)
def test_gdm1__xidp_login(client: Client, ipa: IPA, keycloak: Keycloak):
    """
    :title: Login via GDM with external IdP user
    :setup:
        1. Configure IPA for External IdP support
        2. Add user to IPA as IdP user
        3. Configure SSSD pam_json_services = gdm-switchable-auth
    :steps:
        1. Select user from list (if not listed, use Other and enter user)
        2. 
    :expectedresults:
    """
    testuser = "kcgdmuser1"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"
    client.sssd.import_domain('ipa.test', ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    client.journald.clear()

    client.gdm.init() 
    client.gdm.click_on("listed?")
    client.gdm.kb_send("tab")
    client.gdm.click_on("Username")
    client.gdm.kb_write(testuser)
    client.gdm.click_on("Log")

    log = client.journald.journalctl(grep="adding.*eidp.*code", args=["_COMM=gnome-shell"])    
    match = re.search(r'\{.*\}', log.stdout_lines[-1])
    json_string = match.group()
    data = json.loads(json_string)
    uri = data['uri']
    code = data['code']
    test_uri = f"{uri}?user_code={code}"
    username = testuser
    password = "Secret123"

    client.auth.idp.keycloak(test_uri, username, password)

    #pytest.set_trace()

    #client.gdm.click_on("Done")
    client.gdm.kb_send("enter")

    client.gdm.check_home_screen()
    client.gdm.done()


#@pytest.mark.topology(KnownTopology.GDM)
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
    """
    testuser = "kcgdmuser1"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"
    client.sssd.import_domain('gdm.test', ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    client.journald.clear()

    client.gdm.init() 
    client.gdm.click_on("listed?")
    client.gdm.assert_text("Username")
    client.gdm.kb_write(testuser)
    client.gdm.click_on("Log")

    log = client.journald.journalctl(grep="eidp", args=["_COMM=gnome-shell"])    
    match = re.search(r'\{.*\}', log.stdout_lines[1])
    json_string = match.group()
    data = json.loads(json_string)
    uri = data['eidp']['uri']
    code = data['eidp']['code']
    test_uri = f"{uri}?user_code={code}"
    username = testuser
    password = "Secret123"

    # Assert failure when using incorrect password
    assert not client.auth.idp.keycloak(test_uri, username, password[:-1])

    client.gdm.done()


#@pytest.mark.topology(KnownTopology.GDM)
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
    """
    testuser = "kcgdmuser1"
    testuser_idp = f"{testuser}@{keycloak.host.hostname}"
    client.sssd.import_domain('gdm.test', ipa)
    client.sssd.pam["pam_json_services"] = "gdm-switchable-auth"
    client.sssd.start()

    keycloak.user(testuser).add()
    keycloak.user(testuser).modify(email=f"{testuser_idp}")
    ipa.user(testuser).add()
    ipa.user(testuser).modify(user_auth_type="idp", idp="keycloak", idp_user_id=testuser_idp)

    client.journald.clear()

    client.gdm.init() 
    client.gdm.click_on("listed?")
    client.gdm.assert_text("Username")
    client.gdm.kb_write(testuser)
    client.gdm.click_on("Log")

    log = client.journald.journalctl(grep="eidp", args=["_COMM=gnome-shell"])    
    match = re.search(r'\{.*\}', log.stdout_lines[1])
    json_string = match.group()
    data = json.loads(json_string)
    uri = data['eidp']['uri']
    code = data['eidp']['code']
    test_uri = f"{uri}?user_code={code}"
    username = testuser
    password = "Secret123"

    client.auth.idp.keycloak(test_uri, username, password)
    client.gdm.click_on("Done")
    client.gdm.check_home_screen()

    klist = client.host.conn.run(f'su - {testuser} -c klist')
    client.host.conn.run
    assert f'krbtgt/{ipa.realm}@{ipa.realm}' in klist.stdout

    client.gdm.done()
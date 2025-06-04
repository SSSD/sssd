from __future__ import annotations

import re
import json

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology

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
        2. 
    :expectedresults:
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

    pytest.set_trace()

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

    print(f"Now I need to login to {test_uri} as {username} with {password}")

    client.auth.idp.keycloak(test_uri, username, password)

    client.gdm.click_on("Done")

    client.gdm.check_home_screen()

    client.gdm.done()
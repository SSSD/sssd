"""
SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__change_password(client: Client, ldap: LDAP, modify_mode: str):
    """
    :title: Change password with "ldap_pwmodify_mode" set to @modify_mode
    :setup:
        1. Add user to SSSD, set his password
        2. Allow user to change his password
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Authenticate user with old password
        2. Change password of user to new password
        3. Authenticate user with new password
        4. Authenticate user with old password
    :expectedresults:
        1. User is authenticated
        2. Password is changed successfully
        3. User is authenticated
        4. User is not authenticated
    :customerscenario: False
    """
    user = "user1"
    old_pass = "Secret123"
    new_pass = "New_password123"

    ldap.user(user).add(password=old_pass)
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.start()

    assert client.auth.ssh.password(user, old_pass), "Authentication with old correct password failed"

    assert client.auth.passwd.password(user, old_pass, new_pass), "Password change was not successful"

    assert client.auth.ssh.password(user, new_pass), "Authentication with new correct password failed"
    assert not client.auth.ssh.password(user, old_pass), "Authentication with old incorrect password did not fail"

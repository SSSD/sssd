"""
LDAP Shadow attributes tests.

:requirement: IDM-SSSD-REQ : LDAP Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.schema
@pytest.mark.ticket(bz=1507035)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_shadow__password_change(client: Client, ldap: LDAP, method: str):
    """
    :title: Change password with shadow ldap password policy
    :setup:
        1. Allow user to change its own password in LDAP
        2. Create LDAP user "tuser" with shadowLastChange = 0
        3. Set ldap_pwd_policy to "shadow"
        4. Set ldap_chpass_update_last_change to "True"
        5. Start SSSD
    :steps:
        1. Autheticate as "tuser" with old password
        2. Autheticate as "tuser" with new password
    :expectedresults:
        1. Password was expired and new password was expected and provided
        2. Authentication with new password was successful
    :customerscenario: True
    """
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')
    ldap.user("tuser").add(
        uid=999011, gid=999011, shadowMin=0, shadowMax=99999, shadowWarning=7, shadowLastChange=0, password="Secret123"
    )

    client.sssd.domain["ldap_pwd_policy"] = "shadow"
    client.sssd.domain["ldap_chpass_update_last_change"] = "True"
    client.sssd.start()

    # Password is expired, change it
    assert client.auth.parametrize(method).password_expired("tuser", "Secret123", "Redhat@321")

    # Authenticate with new password
    assert client.auth.parametrize(method).password("tuser", "Redhat@321")

"""
SSSD Sanity Test Cases

:requirement: offline
"""
from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_authentication__login(client: Client, provider: GenericProvider, method: str):
    """
    :title: ssh/su login
    :setup:
        1. Add user to SSSD
        2. Set password for user
        3. Start SSSD
    :steps:
        1. Authenticate user with correct password
        2. Authenticate user with incorrect password
    :expectedresults:
        1. User is authenticated
        2. User is not authenticated
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "login with correct password failed"
    assert not client.auth.parametrize(method).password("user1", "NOTSecret123"), "login with wrong password succeeded"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_authentication__offline_login(client: Client, provider: GenericProvider, method: str):
    """
    :title: Offline ssh/su login
    :setup:
        1. Add user to SSSD and set its password
        2. In SSSD domain change "cache_credentials" and "krb5_store_password_if_offline" to "True"
        3. In SSSD pam change "offline_credentials_expiration" to "0"
        4. Start SSSD
    :steps:
        1. Authenticate user with wrong password
        2. Authenticate user with correct password
        3. Make server offline (by removing firewall rules for LDAP, KDC and Global Catalog ports)
        4. Bring SSSD offline explicitly
        5. Offline authentication of user with correct password
        6. Offline authentication of user with wrong password
    :expectedresults:
        1. User is not authenticated
        2. User is authenticated
        3. Firewall rules dropped
        4. SSSD is offline
        5. Offline authentication is successful
        6. Offline authentication is not successful
    :customerscenario: False
    """
    user = "user1"
    correct = "Secret123"
    wrong = "Wrong123"
    provider.user(user).add(password=correct)

    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(user, wrong), "login with wrong password succeeded"
    assert client.auth.parametrize(method).password(user, correct), "login with correct password failed"

    # Block KDC, LDAP and Global Catalog ports.
    provider.firewall.drop([88, 389, 3268])

    # There might be active connections that are not terminated by creating firewall rule.
    # We need to terminated it by bringing SSSD to offline state explicitly.
    client.sssd.bring_offline()

    assert client.auth.parametrize(method).password(user, correct), "offline login with correct password failed"
    assert not client.auth.parametrize(method).password(user, wrong), "offline login with wrong password succeeded"

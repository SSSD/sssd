"""
Proxy Provider tests.

:requirement: Proxy Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_proxy__lookup_and_authenticate_user_using_pam_ldap_and_nslcd(client: Client, ldap: LDAP):
    """
    :title: Lookup and authenticate user using PAM LDAP and NSLCD.
    :setup:
        1. Setup SSSD to use PAM LDAP and NSLCD.
        2. Create OU, and create a user in the new OU.
    :steps:
        1. Lookup user.
        2. Login in as user.
    :expectedresults:
        1. User found.
        2. User logged in.
    :customerscenario: True
    """
    client.sssd.common.proxy("ldap", ["id", "auth", "chpass"], server_hostname=ldap.host.hostname)
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()
    ou_users = ldap.ou("users").add()
    user = ldap.user("user-1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    assert client.tools.id(user.name) is not None, "User not found!"
    assert client.auth.ssh.password(user.name, password="Secret123"), "User login failed!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.ticket(bz=895570)
def test_proxy__lookup_user_using_pam_ldap_and_nslcd_with_proxy_fast_alias_enabled(client: Client, ldap: LDAP):
    """
    :title: Lookup user using PAM LDAP and NSLCD with proxy_fast_alias enabled.
    :description: This bugzilla was created to squash 'ldb_modify failed' message when proxy_fast_alias is enabled.
    :setup:
        1. Setup SSSD to use PAM LDAP and NSLCD and set "proxy_fast_alias = true".
        2. Create OU, and create a user in the new OU.
    :steps:
        1. Lookup user.
        2. Check logs for ldb_modify errors.
    :expectedresults:
        1. User found.
        2. No error messages in log.
    :customerscenario: True
    """
    client.sssd.common.proxy("ldap", ["id", "auth", "chpass"], server_hostname=ldap.host.hostname)
    client.sssd.domain["proxy_fast_alias"] = "True"
    client.sssd.svc.restart("nslcd")
    client.sssd.restart()
    ou_users = ldap.ou("users").add()
    user = ldap.user("user-1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    assert client.tools.id(user.name) is not None, "User not found!"

    log = client.fs.read(client.sssd.logs.domain())
    assert "ldb_modify failed: [Invalid attribute syntax]" not in log, "'ldb_modify failed' message found in logs!"

"""
SSSD IdP provider Test Cases

:requirement: IDP
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology

configurations = {
    "enabled": "true",
    "idp_type": "keycloak:https://master.keycloak.test:8443/auth/admin/realms/master/",
    "id_provider": "idp",
    "auto_private_groups": "true",
    "use_fully_qualified_names": "true",
    "debug_level": "9",
    "idp_client_id": "myclient",
    "idp_client_secret": "ClientSecret123",
    "idp_token_endpoint": "https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/token",
    "idp_userinfo_endpoint": "https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/userinfo",
    "idp_device_auth_endpoint": "https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/"
    "auth/device",
    "idp_id_scope": "profile",
    "idp_auth_scope": "openid profile email",
}


@pytest.mark.skipif(True, reason="Missing oidc_child patch")
@pytest.mark.topology(KnownTopology.Keycloak)
# @pytest.mark.builtwith(client="idp-provider")
def test_idp__user(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
    :steps:
        1. Lookup user with 'getent passwd'
    :expectedresults:
        1. username, home directory and shell match expectations
    :customerscenario: False
    """

    keycloak.user("user1").add(password="Secret123")

    for key, value in configurations.items():
        client.sssd.dom("keycloak")[key] = value

    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["fallback_homedir"] = "/home/%f"

    client.sssd.start(check_config=False)

    out = client.host.conn.run("getent passwd user1@keycloak")
    assert out.stdout.startswith("user1@keycloak:*:")
    assert out.stdout.endswith(":/home/user1@keycloak:/bin/bash")


@pytest.mark.skipif(True, reason="Missing oidc_child patch")
@pytest.mark.topology(KnownTopology.Keycloak)
# @pytest.mark.builtwith(client="idp-provider")
def test_idp__group(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create group
    :steps:
        1. Lookup group with 'getent group'
    :expectedresults:
        1. groupname matches expectations and no members are returned
    :customerscenario: False
    """

    keycloak.group("group1").add()

    for key, value in configurations.items():
        client.sssd.dom("keycloak")[key] = value

    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["fallback_homedir"] = "/home/%f"

    client.sssd.start(check_config=False)

    out = client.host.conn.run("getent group group1@keycloak")
    assert out.stdout.startswith("group1@keycloak:*:")
    assert out.stdout.endswith(":")


@pytest.mark.skipif(True, reason="Missing oidc_child patch")
@pytest.mark.topology(KnownTopology.Keycloak)
# @pytest.mark.builtwith(client="idp-provider")
def test_idp__user_groups(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup groups of user with 'groups'
    :expectedresults:
        1. user is member of added group and the auto-private group
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    for key, value in configurations.items():
        client.sssd.dom("keycloak")[key] = value

    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["fallback_homedir"] = "/home/%f"

    client.sssd.start(check_config=False)

    out = client.host.conn.run("groups user1@keycloak")
    assert out.stdout == "user1@keycloak : user1@keycloak group1@keycloak"


@pytest.mark.skipif(True, reason="Missing oidc_child patch")
@pytest.mark.topology(KnownTopology.Keycloak)
# @pytest.mark.builtwith(client="idp-provider")
def test_idp__group_members(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup group with 'getent group'
    :expectedresults:
        1. Added user is member of the group
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    for key, value in configurations.items():
        client.sssd.dom("keycloak")[key] = value

    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["fallback_homedir"] = "/home/%f"

    client.sssd.start(check_config=False)

    out = client.host.conn.run("getent group group1@keycloak")
    assert out.stdout.startswith("group1@keycloak:*:")
    assert out.stdout.endswith(":user1@keycloak")

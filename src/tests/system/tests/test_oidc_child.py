"""
SSSD oidc_child Test Cases

:requirement: oidc_child
"""

from __future__ import annotations

import json

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology

oidc_child_path = "/usr/libexec/sssd/oidc_child"
args = (
    "--libcurl-debug -d 9 --logger=stderr "
    "--idp-type=keycloak:https://master.keycloak.test:8443/auth/admin/realms/master/ "
    "--token-endpoint=https://master.keycloak.test:8443/auth/realms/master/protocol/openid-connect/token "
    "--client-id=myclient --client-secret=ClientSecret123 --scope='profile'"
)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_user(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
    :steps:
        1. Lookup user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    :customerscenario: False
    """

    keycloak.user("user1").add(password="Secret123")

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user --name=user1")
    data = json.loads(out.stdout)
    assert data[0]["posixUsername"] == "user1"
    assert data[0]["posixObjectType"] == "user"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_group(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create group
    :steps:
        1. Lookup group with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    :customerscenario: False
    """

    keycloak.group("group1").add()

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group --name=group1")
    data = json.loads(out.stdout)
    assert data[0]["posixGroupname"] == "group1"
    assert data[0]["posixObjectType"] == "group"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_user_groups(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup groups of user with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixGroupname and posixObjectType are correct
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-user-groups --name=user1")
    data = json.loads(out.stdout)
    assert data[0]["posixGroupname"] == "group1"
    assert data[0]["posixObjectType"] == "group"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Keycloak)
def test_oidc_child__get_group_members(client: Client, keycloak: Keycloak):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
    :steps:
        1. Lookup group members with oidc_child
    :expectedresults:
        1. oidc_child is successful and posixUsername and posixObjectType are correct
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    out = client.host.conn.run(oidc_child_path + " " + args + " " + "--get-group-members --name=group1")
    data = json.loads(out.stdout)
    assert data[0]["posixUsername"] == "user1"
    assert data[0]["posixObjectType"] == "user"

"""
SSSD IdP provider Test Cases

:requirement: IDP
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.keycloak import Keycloak
from sssd_test_framework.topology import KnownTopology


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__user(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
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

    client.sssd.dom("test")["use_fully_qualified_names"] = use_fully_qualified_names
    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["fallback_homedir"] = "/home/%f" if use_fully_qualified_names == "true" else "/home/%u"

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    out = client.host.conn.run(f"getent passwd user1{domain}")
    assert out.stdout.startswith(f"user1{domain}:*:")
    assert out.stdout.endswith(f":/home/user1{domain}:/bin/bash")


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__group(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
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

    client.sssd.dom("test")["use_fully_qualified_names"] = use_fully_qualified_names

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    out = client.host.conn.run(f"getent group group1{domain}")
    assert out.stdout.startswith(f"group1{domain}:*:")
    assert out.stdout.endswith(":")


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__user_groups(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
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

    client.sssd.dom("test")["use_fully_qualified_names"] = use_fully_qualified_names

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    out = client.host.conn.run(f"groups user1{domain}")
    assert out.stdout == f"user1{domain} : user1{domain} group1{domain}"


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__group_members(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
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

    client.sssd.dom("test")["use_fully_qualified_names"] = use_fully_qualified_names

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    out = client.host.conn.run(f"getent group group1{domain}")
    assert out.stdout.startswith(f"group1{domain}:*:")
    assert out.stdout.endswith(f":user1{domain}")


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__group_ignore_group_members(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Create group with user as member
        3. Add option 'ignore_group_members = true'
    :steps:
        1. Lookup group with 'getent group'
    :expectedresults:
        1. No members shown
    :customerscenario: False
    """

    user = keycloak.user("user1").add(password="Secret123")
    keycloak.group("group1").add().add_member(user)

    client.sssd.domain["ignore_group_members"] = "true"
    client.sssd.domain["use_fully_qualified_names"] = use_fully_qualified_names

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    out = client.host.conn.run(f"getent group group1{domain}")
    assert out.stdout.startswith(f"group1{domain}:*:")
    assert out.stdout.endswith(":")

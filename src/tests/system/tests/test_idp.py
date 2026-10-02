"""
SSSD IdP provider Test Cases

:requirement: IDP

The IdP provider connects to an OAuth 2.0 and REST based identity provider (IdP).  It
allows for user and group lookups as well as authentication.   This test suite covers
both user/group data lookups as well as authentication.

Due to the nature of Identity Providers generally being remote services, we can only
provide Keycloak as a self provisioned service at this time.  Testing other services
like EntraID requires a pre-provisioned environment that you setup config options for
in the SSSD Test Framework's multihost config file (mhc.yaml).

If you want to run the IdP authentication tests against a specific Identity Provider
(i.e. EntraID), you must modify the mhc.yaml file to add a configuration dictionary
to the client host. To do this add a config section named idp using the following
format:

...code-block...
  - hostname: client.test
    role: client
    artifacts:
    - /etc/sssd/*
    - /var/log/sssd/*
    - /var/lib/sss/db/*
    config:
      idp:
        entra_id:
          tenant_id: "<EntraID_Org_Id>"
          client_id: "<EntraID_Client_Id>"
          client_secret: "<EntraID_Client_Secret>"
          domain_name: "<EntraID_Org_Domain_Name>"
          user1_username: "<test_user_1_username>@<EntraID_Org_Domain_Name>"
          user1_password: "<test_user_1_password>"
        keycloak:
          tenant_id: "master"
          client_id: "myclient"
          client_secret: "ClientSecret123"
          domain_name: "keycloak.test"
          user1_username: "testuser1@keycloak.test"
          user1_password: "Secret123"

For the fields needed, you must include:
- **idp**: Top level config dictionary key name.  This is a dictionary of dictionaries
  where the keys in the first dictionary inside "idp" reflect the names of the
  Identity Providers being configured.
  - **<IdP_Type>**: This is the next level where each entry represents different IdPs.
    - **tenant_id**: This is the Organizational|Realm|Domain ID as provided by the IdP.
    - **client_id**: This is the ID for the client provided by the IdP.
    - **client_secret**: If needed, this is the secret/password for the client that you
      define in the IdP.
    - **domain_name**: This is the name of the domain/organization as provided by the
      IdP.
    - **user1_username**: Default username for testing.  You must pre-create for IdPs
      other than Keycloak.
    - **user1_password**: Default user password for testing.  You must have this set
      in the IdP for the user defined in user1_username.

It is important to indent everything appropriately to ensure the proper structure for the
dictionary when it is imported. The tests will then make use of the data via a config get like:

...code-block...
    idp = client.host.config.get("idp", [])
    username = idp[type]["user1_username"]
    password = idp[type]["user1_password"]

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


@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.topology(KnownTopology.Keycloak)
@pytest.mark.builtwith(client="idp-provider")
def test_idp__id_before_group(client: Client, keycloak: Keycloak, use_fully_qualified_names: str):
    """
    :title: Call id before getent group
    :setup:
        1. Create two user
        2. Create group with both users as members
    :steps:
        1. Lookup one user with 'id'
        2. Lookup group with 'getent group'
    :expectedresults:
        1. User is member of added group and the auto-private group
        2. Both users are members of the group
    :customerscenario: False
    """

    user1 = keycloak.user("user1").add(password="Secret123")
    user2 = keycloak.user("user2").add(password="Secret123")
    group1 = keycloak.group("group1").add().add_members([user1, user2])

    client.sssd.dom("test")["use_fully_qualified_names"] = use_fully_qualified_names

    domain = f"@{client.sssd.default_domain}" if use_fully_qualified_names == "true" else ""

    client.sssd.start(check_config=False)

    user_out = client.tools.id(user1.name + domain)
    assert user_out is not None, f"User {user1.name} was not found using getent!"
    assert (
        user_out.user.name == user1.name + domain
    ), f"Username {user_out.user.name} is incorrect, {user1.name}{domain} expected!"
    assert user_out.memberof(
        group1.name + domain
    ), f"User {user_out.user.name} is not a member of group {group1.name}{domain}!"
    assert user_out.memberof(
        user1.name + domain
    ), f"User {user_out.user.name} is not a member of group {user1.name}{domain}!"

    group_out = client.tools.getent.group(f"{group1.name}{domain}")
    assert group_out is not None, f"Group {group1.name}{domain} was not found using getent!"
    assert (
        group_out.name == group1.name + domain
    ), f"Groupname {group_out.name} is incorrect, {group1.name}{domain} expected!"
    assert (
        len(group_out.members) == 2
    ), f"Group {group_out.name} has unexpected number of members [{len(group_out.members)}]!"
    assert (
        user1.name + domain in group_out.members
    ), f"Member {user1.name}{domain} of group {group_out.name} not found!"
    assert (
        user2.name + domain in group_out.members
    ), f"Member {user2.name}{domain} of group {group_out.name} not found!"


@pytest.mark.importance("high")
@pytest.mark.builtwith(client="idp-provider")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.parametrize("type", ["keycloak", "entra_id"])
@pytest.mark.topology(KnownTopology.IdpClient)
def test_idp__login_succeeds(
    client: Client, keycloak: Keycloak, method: str, use_fully_qualified_names: str, type: str
):
    """
    :title: Authentication succeeds with Generic IdP device flow
    :setup:
        1. First check for needed IdP options in multihost config
        2. Configure SSSD for IdP Provider, set relevant options, and start SSSD
        3. Create user in Keycloak if type is keycloak.  EntraID test user is
           expected to already have been created.
    :steps:
        1. Authenticate via SSH or SU using IdP device authorization grant flow
    :expectedresults:
        1. Authentication succeeds after browser-based OAuth flow
    :customerscenario: False
    """
    # Check for valid IdP config first.  Skip if anything missing
    client.idp.config_check(client, type=type)

    # Configure SSSD for IdP Provider
    client.idp.setup_config(client, keycloak, type, use_fully_qualified_names)

    idp = client.host.config.get("idp", [])
    username = idp[type]["user1_username"]
    password = idp[type]["user1_password"]

    # Add user if type is keycloak
    if type == "keycloak":
        keycloak.user(username.split("@")[0]).add(password=password)

    # Authenticate via SSH or SU with IdP user
    assert client.auth.parametrize(method).password_idp(
        username, password, idp_provider=type, use_fully_qualified_names=use_fully_qualified_names
    ), f"{method.upper()} IdP authentication failed!"


@pytest.mark.importance("high")
@pytest.mark.builtwith(client="idp-provider")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("use_fully_qualified_names", ["true", "false"])
@pytest.mark.parametrize("type", ["keycloak", "entra_id"])
@pytest.mark.topology(KnownTopology.IdpClient)
def test_idp__login_rejected_for_invalid_password(
    client: Client, keycloak: Keycloak, method: str, use_fully_qualified_names: str, type: str
):
    """
    :title: Authentication fails with Generic IdP device flow when password is invalid
    :setup:
        1. Create user in Keycloak
        2. Configure SSSD with idp_provider
        3. Configure NSS options for shell and homedir
        4. Start SSSD
    :steps:
        1. Attempt to authenticate via SSH or SU using IdP device flow with invalid password
    :expectedresults:
        1. Authentication fails
    :customerscenario: False
    """
    # Check for valid IdP config first.  Skip if anything missing
    client.idp.config_check(client, type=type)

    # Configure SSSD for IdP Provider
    client.idp.setup_config(client, keycloak, type, use_fully_qualified_names)

    idp = client.host.config.get("idp", [])
    username = idp[type]["user1_username"]
    password = idp[type]["user1_password"]
    invalid_password = "WrongPassword"

    # Add user if type is keycloak
    if type == "keycloak":
        keycloak.user(username.split("@")[0]).add(password=password)

    # Attempt to authenticate via SSH or SU with IdP user with invalid password
    assert not client.auth.parametrize(method).password_idp(
        username,
        invalid_password,
        idp_provider=type,
    ), f"{method.upper()} IdP authentication should have failed with invalid password!"

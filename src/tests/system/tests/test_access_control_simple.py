"""
SSSD Authentication Test Cases

:requirement: access control
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.importance("critical")
def test_access_control_simple__permits_user_login(client: Client, provider: GenericProvider):
    """
    :title: Simple access filter permits user login
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Configure SSSD with ‘access_provider = simple’, ‘simple_allow_users = user1’
        3. Start SSSD
    :steps:
        1. Try to login as ‘user1’
        2. Try to login as ‘user2’
    :expectedresults:
        1. ‘user1’ can login
        2. ‘user2’ can't login
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.user("user2").add()

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_users"] = "user1"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.importance("critical")
def test_access_control_simple__deny_user_login(client: Client, provider: GenericProvider):
    """
    :title: Simple access filter denies user login
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Configure SSSD with ‘access_provider = simple’, ‘simple_deny_users = user1’
        3. Start SSSD
    :steps:
        1. Try to login as ‘user1’
        2. Try to login as ‘user2’
    :expectedresults:
        1. ‘user1’ can't login
        2. ‘user2’ can login
    :customerscenario: False
    """
    provider.user("user1").add()
    provider.user("user2").add()

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_deny_users"] = "user1"

    client.sssd.start()

    assert not client.auth.ssh.password("user1", "Secret123"), "User should NOT be able to log in!"
    assert client.auth.ssh.password("user2", "Secret123"), "User should be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.importance("critical")
def test_access_control_simple__permits_user_login_based_on_group(client: Client, provider: GenericProvider):
    """
    :title: Simple access filter permits and denies access evaluating groups
    :setup:
        1. Create users ‘user1’, ‘user2’, ‘user3’
        2. Create group ‘group1’ with members ‘user1, user3’
        3. Create group ‘group2’ with member ‘user2, user3’
        4. Configure SSSD with ‘access_provider = simple’,
        5. Configure SSSD with ‘simple_allow_groups = group1’ and ‘simple_deny_groups = group2’
        6. Start SSSD
    :steps:
        1. Try to login with ‘user1’
        2. Try to login with ‘user2’
        3. Try to login with ‘user3’
    :expectedresults:
        1. ‘user1’ can login
        2. ‘user2’ can't login
        3. ‘user3’ can't login
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()
    u3 = provider.user("user3").add()

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "group1"
    client.sssd.domain["simple_deny_groups"] = "group2"

    provider.group("group1").add().add_members([u1, u3])
    provider.group("group2").add().add_members([u2, u3])

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User should NOT be able to log in!"
    assert not client.auth.ssh.password("user3", "Secret123"), "User should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.importance("critical")
def test_access_control_simple__deny_group_supersedes_allow_group(client: Client, provider: GenericProvider):
    """
    :title: Validate if superseding denies works.
    :setup:
        1. Create user `user1`
        2. Create groups `allowed_group` and `denied_group` both with member `user1`
        3. Configure SSSD with:
            `access_provider = simple`
            `simple_allow_groups = allowed_group`
            `simple_deny_groups = denied_group`
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1`
    :expectedresults:
        1. `user1` should NOT be able to log in.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()

    provider.group("allowed_group").add().add_member(u1)
    provider.group("denied_group").add().add_member(u1)

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "allowed_group"
    client.sssd.domain["simple_deny_groups"] = "denied_group"

    client.sssd.start()

    assert not client.auth.ssh.password("user1", "Secret123"), "User1 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyDC)
@pytest.mark.preferred_topology(KnownTopology.IPA)
@pytest.mark.importance("critical")
def test_access_control_simple__allow_and_deny_nested_group(client: Client, provider: GenericProvider):
    """
    :title: Validate if nested group works.
    :setup:
        1. Create users `user1`, `user2`
        2. Create groups
            `nested_group` and add `group1` as a member; add `user1` as member of `group1`
            `deny_nested_group` and add `group2` as a member; add `user2` as member of `group2`
        3. Configure SSSD with:
            `access_provider = simple`
            `simple_allow_groups = nested_group`
            `simple_deny_groups = deny_nested_group`
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1`
        2. Attempt login with `user2`
    :expectedresults:
        1. `user1` should be able to log in.
        2. `user2` should NOT be able to log in.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()

    g1 = provider.group("group").add().add_member(u1)
    provider.group("nested_group").add().add_member(g1)

    g2 = provider.group("deny_group").add().add_member(u2)
    provider.group("deny_nested_group").add().add_member(g2)

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "nested_group"
    client.sssd.domain["simple_deny_groups"] = "deny_nested_group"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should NOT be able to log in!"

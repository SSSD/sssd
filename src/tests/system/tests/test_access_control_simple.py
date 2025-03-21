"""
SSSD Authentication Test Cases

:requirement: access control
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
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
        1. User1 can login
        2. User2 cannot login
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
        1. User1 cannot login
        2. User2 can login
    :customerscenario: False
    """
    provider.user("user1").add()
    provider.user("user2").add()

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_deny_users"] = "user1"

    client.sssd.start()

    assert not client.auth.ssh.password("user1", "Secret123"), "User should be able to log in!"
    assert client.auth.ssh.password("user2", "Secret123"), "User should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
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
        1. User1 can login
        2. User2 cannot login
        3. User3 cannot login
    :customerscenario: False
    """

    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()
    user3 = provider.user("user3").add()

    group1 = provider.group("group1").add()
    group2 = provider.group("group2").add()

    group1.add_members([user1, user3])
    group2.add_members([user2, user3])

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "group1"
    client.sssd.domain["simple_deny_groups"] = "group2"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User should NOT be able to log in!"
    assert not client.auth.ssh.password("user3", "Secret123"), "User should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
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

    user1 = provider.user("user1").add()

    allowed_group = provider.group("allowed_group").add()
    denied_group = provider.group("denied_group").add()

    allowed_group.add_member(user1)
    denied_group.add_member(user1)

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "allowed_group"
    client.sssd.domain["simple_deny_groups"] = "denied_group"

    client.sssd.start()

    assert not client.auth.ssh.password("user1", "Secret123"), "User1 should NOT be able to log in!"

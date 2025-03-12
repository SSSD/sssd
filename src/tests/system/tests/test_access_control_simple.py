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
def test_access_control__simple_filter_permits_user_login(client: Client, provider: GenericProvider):
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
    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_users"] = "user1"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User can not login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_deny_user_login(client: Client, provider: GenericProvider):
    """
    :title: Simple access filter permits user login
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
    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_deny_users"] = "user1"

    client.sssd.start()

    assert not client.auth.ssh.password("user1", "Secret123"), "User cannot login!"
    assert client.auth.ssh.password("user2", "Secret123"), "User can login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_control__simple_filter_permits_user_login_based_on_group(client: Client, provider: GenericProvider):
    """
    :title: Simple access filter permits user login
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
    user1 = provider.user("user1").add(password="Secret123")
    user2 = provider.user("user2").add(password="Secret123")
    user3 = provider.user("user3").add(password="Secret123")

    group1 = provider.group("group1").add()
    group2 = provider.group("group2").add()

    group1.add_member(user1)
    group1.add_member(user3)
    group2.add_member(user2)
    group2.add_member(user3)

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_groups"] = "group1"
    client.sssd.domain["simple_deny_groups"] = "group2"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User can login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User cannot login!"
    assert not client.auth.ssh.password("user3", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_sssd_simple_allow_and_deny_users_and_groups(client: Client, provider: GenericProvider):
    """
    :title: Validate `simple_allow_users`, `simple_deny_users`, `simple_allow_groups`, and `simple_deny_groups`
    :description: This test checks whether SSSD correctly applies both allow and deny lists
                for individual users and groups.
    :setup:
        1. Create users:
           - `user1` (explicitly allowed)
           - `user2` (explicitly allowed)
           - `user3` (explicitly denied)
           - `user4` (explicitly denied)
           - `user5` (not in any list but part of an allowed group)
           - `user6` (not in any list but part of a denied group)
        2. Create groups:
           - `allowed_group` (includes `user5`)
           - `denied_group` (includes `user6`)
        3. Configure SSSD with:
           - `access_provider = simple`
           - `simple_allow_users = user1, user2`
           - `simple_deny_users = user3, user4`
           - `simple_allow_groups = allowed_group`
           - `simple_deny_groups = denied_group`
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1` (explicitly allowed)
        2. Attempt login with `user2` (explicitly allowed)
        3. Attempt login with `user3` (explicitly denied)
        4. Attempt login with `user4` (explicitly denied)
        5. Attempt login with `user5` (allowed via group membership)
        6. Attempt login with `user6` (denied via group membership)
    :expectedresults:
        1. `user1` should be able to log in.
        2. `user2` should be able to log in.
        3. `user3` should NOT be able to log in.
        4. `user4` should NOT be able to log in.
        5. `user5` should be able to log in (due to allowed group membership).
        6. `user6` should NOT be able to log in (due to denied group membership).
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")
    provider.user("user3").add(password="Secret123")
    provider.user("user4").add(password="Secret123")
    provider.user("user5").add(password="Secret123")
    provider.user("user6").add(password="Secret123")

    allowed_group = provider.group("allowed_group").add()
    denied_group = provider.group("denied_group").add()

    allowed_group.add_member(provider.user("user5"))
    denied_group.add_member(provider.user("user6"))

    client.sssd.domain["access_provider"] = "simple"
    client.sssd.domain["simple_allow_users"] = "user1, user2"
    client.sssd.domain["simple_deny_users"] = "user3, user4"
    client.sssd.domain["simple_allow_groups"] = "allowed_group"
    client.sssd.domain["simple_deny_groups"] = "denied_group"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to log in!"
    assert client.auth.ssh.password("user2", "Secret123"), "User2 should be able to log in!"
    assert not client.auth.ssh.password("user3", "Secret123"), "User3 should NOT be able to log in!"
    assert not client.auth.ssh.password("user4", "Secret123"), "User4 should NOT be able to log in!"
    assert client.auth.ssh.password("user5", "Secret123"), "User5 should be able to log in!"
    assert not client.auth.ssh.password("user6", "Secret123"), "User6 should NOT be able to log in!"

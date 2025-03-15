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
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_access_control__simple_filter_permits_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
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

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_access_control__simple_filter_deny_user_login(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
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

    client.sssd.start(service_user=sssd_service_user)

    assert not client.auth.parametrize(method).password("user1", "Secret123"), "User cannot login!"
    assert client.auth.parametrize(method).password("user2", "Secret123"), "User can login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_access_control__simple_filter_permits_user_login_based_on_group(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
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

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User can login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"
    assert not client.auth.parametrize(method).password("user3", "Secret123"), "User cannot login!"

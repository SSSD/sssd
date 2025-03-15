"""
SSSD Authentication Test Cases

:requirement: access control access_filter
"""

from __future__ import annotations

import pytest

# Remove this import and the function later
import pudb
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__single_ldap_attribute_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP attribute filter permits specific user login
    :description: Verifies that SSSD allows login only for users matching an specific LDAP attribute.
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Configure SSSD with ‘access_provider = ldap|ad’ and ‘*_access_filter = uid|samAccountName = user1’
        3. Start SSSD
    :steps:
        1. Attempt login with `user1`.
        2. Attempt login with `user2`.
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    ad_filter = "samAccountName=user1"
    ldap_filter = "uid=user1"

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = ad_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = ldap_filter

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User login!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User cannot login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__group_attributes_permits_user_login(client: Client, provider: GenericProvider, method: str):
    """
    :title: LDAP attribute permits user login
    :description:   Tests whether SSSD allows login based on LDAP group membership.
                    LDAP has options to be tested as rfc23007bis and rfc2307.
                    The former uses memberOf and the latter member. AD uses memberof, so LDAP will cover member.
    :setup:
        1. Create users `user1` and `user2`, and create group `group1`.
        2. Add `user1` to `group1`, leaving `user2` outside the group.
        3. Configure SSSD with `access_provider = ldap|ad` and apply `*_access_filter` to allow only group members.
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1` (a group member).
        2. Attempt login with `user2` (not in the group).
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123")
    provider.user("user2").add(password="Secret123")

    group1 = provider.group("group1").add()

    group1.add_member(provider.user("user1"))

    ad_filter = "(&(memberof=cn=group1,ou=groups,dc=master,dc=ldap,dc=test))"
    ldap_filter = "(&(member=uid=user1,ou=groups,dc=master,dc=ldap,dc=test))"

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = ad_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = ldap_filter

    client.sssd.start()

    # pudb.set_trace()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User2 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_wildcard_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP wildcard filter permits user login
    :description: Tests whether SSSD correctly processes wildcard-based LDAP filters for login.
    :setup:
        1. Create `user1` with a valid `mail` attribute (`user1@domain.com`).
        2. Create `user2` without an email attribute.
        3. Configure SSSD with `access_provider = ldap|ad` and `*_access_filter = mail=*domain.com`.
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1` (matching the wildcard filter).
        2. Attempt login with `user2` (lacking the attribute).
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123", mail="user1@domain.com")
    provider.user("user2").add(password="Secret123")

    ad_filter = "(mail=*domain.com)"
    ldap_filter = "(mail=*domain.com)"

    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = ad_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = ldap_filter

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User2 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_and_or_not_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP query with AND, OR, NOT operators permits user login
    :description: Verifies that SSSD correctly processes LDAP queries using `AND (&)`, `OR (|)`, and `NOT (!)`.
    :setup:
        1. Create user `user1` (username: Joe, email: user1@domain.com)
        2. Create user `user2` (username: Daniela, email: user2@domain.com)
        3. Create user `user3` (username: Jack, email: user3@example.com)
        4. Configure SSSD with `access_provider = ldap|ad` and `*_access_filter` that:
            - Allows users with `@domain.com` email OR username `Joe`
            - Denies users named `Jack`
        5. Start SSSD
    :steps:
        1. Attempt login with `user1`
        2. Attempt login with `user2`
        3. Attempt login with `user3`
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
        3. `user3` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123", mail="user1@domain.com", cn="Joe")
    provider.user("user2").add(password="Secret123", mail="user2@domain.com", cn="Daniela")
    provider.user("user3").add(password="Secret123", mail="user3@example.com", cn="Jack")

    # This filter allows BOTH (AND) conditions
    # users with @domain.com emails OR username is Joe
    # username is NOT 'Jack'
    ldap_filter = "(&(|(mail=*domain.com)(cn=Joe))(!(cn=Jack)))"
    ad_filter = "(&(|(mail=*domain.com)(cn=Joe))(!(cn=Jack)))"

    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = ad_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = ldap_filter

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User2 should NOT be able to log in!"
    assert not client.auth.parametrize(method).password("user3", "Secret123"), "User3 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
@pytest.mark.parametrize(
    "filter",
    [
        ("(mail=*domain.com)"),
        ("(INVALID_ATTRIBUTE=value)"),
    ],
)
def test_access_filter__invalid_ldap_query_denies_user_login(
    client: Client, provider: GenericProvider, method: str, filter: str
):
    """
    :title: Invalid LDAP access filter query denies user login
    :description: Tests whether SSSD denies authentication when an invalid LDAP filter is used.
    :setup:
        1. Create user `user1` with a valid `mail` attribute (`user1@domain.com`).
        2. Create user `user2` with an invalid attribute (`INVALID_ATTRIBUTE=value`).
        3. Configure SSSD with `access_provider = ldap|ad` and set an invalid access filter.
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1`
        2. Attempt login with `user2`
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access due to the invalid filter.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123", mail="user1@domain.com")
    provider.user("user2").add(password="Secret123", INVALID_ATTRIBUTE="value")

    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = filter

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User2 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh"])
@pytest.mark.importance("critical")
def test_access_filter__ldap_attributes_approximately_greater_and_less_than_permits_user_login(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: LDAP attribute filters using `~=`, `>`, `<` permit user login
    :description: Tests LDAP access control using approximate (`~=`), greater (`>`), and less (`<`) comparison operators.
    :setup:
        1. Create `user1` with `age = 30`
        2. Create `user2` with `age = 25`
        3. Configure SSSD with `access_provider = ldap|ad` and `*_access_filter` to allow only users with:
            - `age >= 30`
            - `age ~= 29` (approximate match)
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1` (age 30)
        2. Attempt login with `user2` (age 25)
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(password="Secret123", age=30)
    provider.user("user2").add(password="Secret123", age=25)

    # This filter allows users whose age is >= 30 (~= operator may match approximations)
    ldap_filter = "(&(|(age>=30)(age~=29)))"
    ad_filter = ldap_filter

    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = ad_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = ldap_filter

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.parametrize(method).password("user2", "Secret123"), "User2 should NOT be able to log in!"

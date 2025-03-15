"""
SSSD Authentication Test Cases

:requirement: access control access_filter
"""

from __future__ import annotations

import pytest

# Remove this import and the function later
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.ipa import IPA


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_filter__single_ldap_attribute_permits_user_login(client: Client, provider: GenericProvider):
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

    # Remove the UID if it won't be used by IPA provider
    provider.user("user1").add(uid=10001)
    provider.user("user2").add()

    # Logic to determine the access provider and filter based on the provider
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "samAccountName=user1"
    # I don't know how to set the filter for IPA
    # It seems uid is an integer in IPA, and it doesn't work as expected
    elif isinstance(provider, IPA):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "uid=10001"
    elif isinstance(provider, LDAP):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "uid=user1"
    else:
        raise RuntimeError("Provider not supported")

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should not be able to login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_filter__group_attributes_permits_user_login(client: Client, provider: GenericProvider):
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

    provider.user("user1").add()
    provider.user("user2").add()

    group1 = provider.group("group1").add()

    group1.add_member(provider.user("user1"))

    # None of the filters below work :/
    if isinstance(provider, AD) or isinstance(provider, Samba):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(memberof=cn=group1)"
    elif isinstance(provider, IPA):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(member=cn=group1)"
    elif isinstance(provider, LDAP):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(member=cn=group1)"
    else:
        raise RuntimeError("Provider not supported")

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should not be able to login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_wildcard_permits_user_login(client: Client, provider: GenericProvider):
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

    # Revisit this logic once https://github.com/SSSD/sssd-test-framework/pull/161 is merged
    if isinstance(provider, LDAP):
        provider.user("user1").add(mail="user1@domain.com")
    else:
        provider.user("user1").add(email="user1@domain.com")

    provider.user("user2").add()

    # None of the filters below work :/
    if isinstance(provider, AD):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(mail=*domain.com)"
    elif isinstance(provider, IPA):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(mail=*domain.com)"
    elif isinstance(provider, LDAP):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(mail=*domain.com)"
    else:
        raise RuntimeError("Provider not supported")

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_and_or_not_permits_user_login(client: Client, provider: GenericProvider):
    """
    :title: LDAP query with AND, OR, NOT operators permits user login
    :description: Verifies that SSSD correctly processes LDAP queries using `AND (&)`, `OR (|)`, and `NOT (!)`.
    :setup:
        1. Create user `user1` (email: user1@domain.com, uid: 10001)
        2. Create user `user2` (email: user2@domain.com, uid: 10002)
        3. Create user `user3` (email: user3@example.com, uid: 10003)
        4. Configure SSSD with `access_provider = ldap|ad` and `*_access_filter` that:
            - Allows users with `@domain.com` email OR uid `10001`
            - Denies users with uid `10003`
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

    # Revisit this logic once https://github.com/SSSD/sssd-test-framework/pull/161 is merged
    if isinstance(provider, LDAP):
        provider.user("user1").add(mail="user1@domain.com", uid=10001)
        provider.user("user2").add(mail="user2@domain.com", uid=10002)
        provider.user("user3").add(mail="user3@example.com", uid=10003)
    else:
        provider.user("user1").add(email="user1@domain.com", uid=10001)
        provider.user("user2").add(email="user2@domain.com", uid=10002)
        provider.user("user3").add(email="user3@example.com", uid=10003)

    if isinstance(provider, AD):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(&(|(mail=*domain.com)(uid=10001))(!(uid=10003)))"
    elif isinstance(provider, IPA):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(|(mail=*domain.com)(uid=10001))(!(uid=10003)))"
    elif isinstance(provider, LDAP):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(|(mail=*domain.com)(uid=10001))(!(uid=10003)))"
    else:
        raise RuntimeError("Provider not supported")

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should NOT be able to log in!"
    assert not client.auth.ssh.password("user3", "Secret123"), "User3 should NOT be able to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.importance("critical")
def test_access_filter__ldap_attributes_approximately_greater_and_less_than_permits_user_login(
    client: Client, provider: GenericProvider
):
    """
    :title: LDAP attribute filters using `~=`, `>`, `<` permit user login
    :description: Tests LDAP access control using approximate (`~=`), greater (`>`),
                    and less (`<`) comparison operators.
    :setup:
        1. Create `user1` with `uid = 10030`
        2. Create `user2` with `uid = 10025`
        3. Configure SSSD with `access_provider = ldap|ad` and `*_access_filter` to allow only users with:
            - `uid >= 10030`
            - `uid ~= 10029` (approximate match)
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1`
        2. Attempt login with `user2`
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(uid=10030)
    provider.user("user2").add(uid=10025)

    if isinstance(provider, AD):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(&(|(uid>=10030)(uid~=10029)))"
    elif isinstance(provider, IPA):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(|(uid>=10030)(uid~=10029)))"
    elif isinstance(provider, LDAP):
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(&(|(uid>=10030)(uid~=10029)))"
    else:
        raise RuntimeError("Provider not supported")

    assert client.auth.ssh.password("user1", "Secret123"), "User1 should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "User2 should NOT be able to log in!"

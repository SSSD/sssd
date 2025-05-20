"""
SSSD LDAP Filter Test

:requirement: access control access_filter

LDAP Filters are not intenteded to work with IPA provider
(there are other mechanisms in IPA to handle it way better than ldap filter).
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_access_filter__single_ldap_attribute_permits_user_login(client: Client, provider: AD | LDAP | Samba):
    """
    :title: LDAP attribute filter permits specific user login
    :description: Verifies that SSSD allows login only for users matching an specific LDAP attribute.
    :setup:
        1. Create users ‘user1’ and ‘user2’
        2. Configure SSSD with:
            AD/Samba: ‘access_provider = ad’ and set ‘ad_access_filter’ filter
            LDAP: ‘access_provider = ldap’ and set ‘ldap_access_filter’ filter
            Set the filter to allow only `user1` to login.
        3. Start SSSD
    :steps:
        1. Attempt login with `user1`.
        2. Attempt login with `user2`.
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.user("user2").add()

    if isinstance(provider, (AD, Samba)):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = "(samAccountName=user1)"
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = "(uid=user1)"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "`user1` should be able to login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "`user2` should NOT be able to login!"


@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.importance("critical")
def test_access_filter__group_attributes_permits_user_login(client: Client, provider: GenericADProvider):
    """
    :title: LDAP attribute permits user login
    :description: Tests whether SSSD allows login based on LDAP group membership.
    :setup:
        1. Create users `user1` and `user2`.
        2. Create groups `group1` and `group2`.
        3. Add `user1` to `group1`, and `user2` to `group2`.
        4. Configure SSSD with:
            AD/Samba: ‘access_provider = ad’ and set ‘ad_access_filter’ filter
            LDAP: ‘access_provider = ldap’ and set ‘ldap_access_filter’ filter
        5. Set the filter to allow users in `group1` to login.
        6. Start SSSD.
    :steps:
        1. Attempt login with `user1`.
        2. Attempt login with `user2`.
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """
    u1 = provider.user("user1").add()
    provider.user("user2").add()

    provider.group("group1").add().add_member(u1)

    client.sssd.domain["access_provider"] = "ad"
    client.sssd.domain["ad_access_filter"] = f"(memberOf=CN=group1,CN=Users,{provider.naming_context})"

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "`user1` should be able to login!"
    assert not client.auth.ssh.password("user2", "Secret123"), "`user2` should NOT be able to login"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_wildcard_permits_user_login(client: Client, provider: AD | LDAP | Samba):
    """
    :title: LDAP wildcard filter permits user login
    :description: Tests whether SSSD correctly processes wildcard-based LDAP filters for login.
    :setup:
        1. Create `user1` with a valid `mail` attribute (`user1@domain.com`).
        2. Create `user2` without an email attribute.
        3. Configure SSSD with:
            AD/Samba: ‘access_provider = ad’ and set ‘ad_access_filter’ filter
            LDAP: ‘access_provider = ldap’ and set ‘ldap_access_filter’ filter
            filter to allow users with `mail` attribute matching `*domain.com`.
        4. Start SSSD.
    :steps:
        1. Attempt login with `user1` (matching the wildcard filter).
        2. Attempt login with `user2` (lacking the attribute).
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(email="user1@allowedLogin.com")
    provider.user("user2").add(email="user2@deniedLogin.com")

    access_filter = "(mail=*allowedLogin.com)"
    client.sssd.domain["ad_access_filter"] = access_filter

    if isinstance(provider, (AD, Samba)):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = access_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = access_filter

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "`user1` should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "`user2` should NOT be able to log in!"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_access_filter__ldap_query_with_and_or_not_permits_user_login(client: Client, provider: AD | LDAP | Samba):
    """
    :title: LDAP query with AND, OR, NOT operators permits user login
    :description: Verifies that SSSD correctly processes LDAP queries using `AND (&)`, `OR (|)`, and `NOT (!)`.
    :setup:
        1. Create user `user1` (email: user1@allowedLogin.com)
        2. Create user `user2` (email: user2@domain.com)
        3. Create user `user3` (email: user3@deniedLogin.com)
        4. Configure SSSD with:
            AD/Samba: ‘access_provider = ad’ and set ‘ad_access_filter’ filter
            LDAP: ‘access_provider = ldap’ and set ‘ldap_access_filter’ filter
            Filter to allow users with `@allowedLogin.com` or `@domain.com` email.
            Filter to deny users with email `@deniedLogin.com`.
        5. Start SSSD
    :steps:
        1. Attempt login with `user1`
        2. Attempt login with `user2`
        3. Attempt login with `user3`
    :expectedresults:
        1. `user1` is successfully authenticated.
        2. `user2` is successfully authenticated.
        3. `user3` is denied access.
    :customerscenario: False
    """

    provider.user("user1").add(email="user1@allowedLogin.com")
    provider.user("user2").add(email="user2@domain.com")
    provider.user("user3").add(email="user3@deniedLogin.com")

    access_filter = "(&(|(mail=*domain.com)(mail=*allowedLogin.com))(!(mail=*deniedLogin.com)))"
    client.sssd.domain["ldap_access_filter"] = access_filter

    if isinstance(provider, (AD, Samba)):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = access_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = access_filter

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "`user1` should be able to log in!"
    assert client.auth.ssh.password("user2", "Secret123"), "`user2` should be able to log in!"
    assert not client.auth.ssh.password("user3", "Secret123"), "`user3` should NOT be able to log in!"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.importance("critical")
def test_access_filter__ldap_attributes_approximately_greater_and_less_than_permits_user_login(
    client: Client, provider: AD | LDAP | Samba
):
    """
    :title: LDAP attribute filters using `~=`, `>`, `<` permit user login
    :description: Tests LDAP access control using approximate (`~=`), greater (`>`),
                    and less (`<`) comparison operators.
    :setup:
        1. Create `user1` with `uid = 10030`
        2. Create `user2` with `uid = 10025`
        3. Configure SSSD with:
            AD/Samba: ‘access_provider = ad’ and set ‘ad_access_filter’ filter
            LDAP: ‘access_provider = ldap’ and set ‘ldap_access_filter’ filter
            Filter to `uid >= 10030` or `uid ~= 10029` (approximate match)
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

    access_filter = "(|(uidNumber>=10030)(uidNumber~=10029))"

    if isinstance(provider, (AD, Samba)):
        client.sssd.domain["access_provider"] = "ad"
        client.sssd.domain["ad_access_filter"] = access_filter
    else:
        client.sssd.domain["access_provider"] = "ldap"
        client.sssd.domain["ldap_access_filter"] = access_filter

    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "`user1` should be able to log in!"
    assert not client.auth.ssh.password("user2", "Secret123"), "`user2` should NOT be able to log in!"

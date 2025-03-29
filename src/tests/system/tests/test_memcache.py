"""
SSSD In-Memory Cache (memcache) Test Cases.

:requirement: IDM-SSSD-REQ: Client side performance improvements

:note: Stopping SSSD is the easiest way to check the memcache, but it doesn't mean it is supposed to work
exactly like when SSSD is running. It was not designed to work, but it is a collateral effect.
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("lookup_type", ["users", "groups", "users_and_groups"])
@pytest.mark.parametrize("memcache", [True, False], ids=["with_memcache", "without_memcache"])
def test_memcache__user_group_initigroup_cache_alternately_disabled(
    client: Client, provider: GenericProvider, lookup_type: str, memcache: bool
):
    """
    :title: Validate memory cache behavior for users and groups with different cache settings
    :setup:
        1. Create user `user1`.
        2. Create group `group1`.
        3. Configure SSSD to disable selected cache settings based on `lookup_type`.
    :steps:
        1. Start SSSD.
        2. Perform lookup operation for `user1` and `group1`.
        3. Stop SSSD.
        4. Perform lookup operation again for `user1` and `group1`.
    :expectedresults:
        1. SSSD starts successfully.
        2. `user1` and `group1` are found.
        3. SSSD stops successfully.
        4. If memcache is enabled, `user1` and `group1` are found.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    g1 = provider.group("group1").add()

    cache_setting = {
        "users": ["memcache_size_passwd"],
        "groups": ["memcache_size_group"],
        "users_and_groups": ["memcache_size_passwd", "memcache_size_group", "memcache_size_initgroups"],
    }

    if not memcache:
        for cache in cache_setting[lookup_type]:
            client.sssd.nss[cache] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd(u1.name) is not None, f"`{u1.name}` should be found while SSSD is running."
    assert client.tools.getent.group(g1.name) is not None, f"`{g1.name}` should be found while SSSD is running."

    client.sssd.stop()

    if lookup_type in ("users", "users_and_groups") and not memcache:
        assert client.tools.getent.passwd(u1.name) is None, f"`{u1.name}` should NOT be found after stopping SSSD."
    else:
        assert (
            client.tools.getent.passwd("{u1.name}") is not None
        ), f"`{u1.name}` should still be found after stopping SSSD."

    if lookup_type in ("groups", "users_and_groups") and not memcache:
        assert client.tools.getent.group(g1.name) is None, f"`{g1.name}` should NOT be found after stopping SSSD."
    else:
        assert (
            client.tools.getent.group(g1.name) is not None
        ), f"`{g1.name}` should still be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("lookup_type", ["users", "groups", "users_and_groups"])
@pytest.mark.parametrize("invalidate_cache", ["before", "after"], ids=["disable_cache_before", "disable_cache_after"])
def test_memcache__user_group_before_and_after_cache_disabled(
    client: Client, provider: GenericProvider, lookup_type: str, invalidate_cache: str
):
    """
    :title: Validate memory cache behavior for users and groups with different cache settings
    :setup:
        1. Create test users `user1`.
        2. Create test groups `group1`.
        3. Configure SSSD with default cache settings.
    :steps:
        1. Start SSSD.
        2. Perform lookup operation for `user1` and `group1`.
        3. Invalidate `user1` and/or group cache (depending on `lookup_type` and `invalidate_cache` timing).
        4. Stop SSSD.
        5. Perform lookup operation again for us`user1`er1 and `group1`.
    :expectedresults:
        1. SSSD starts successfully.
        2. `user1` and `group1` are found while SSSD is running.
        3. Cache is invalidated according to test parameter.
        4. SSSD stops successfully.
        5. `user1` and/or `group1` are not found after stopping SSSD.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    g1 = provider.group("group1").add()

    client.sssd.start()

    assert client.tools.getent.passwd(u1.name) is not None, f"`{u1.name}` should be found while SSSD is running."
    assert client.tools.getent.group(g1.name) is not None, f"`{g1.name}` should be found while SSSD is running."

    if invalidate_cache == "before":
        if lookup_type in ("users", "users_and_groups"):
            client.sssctl.cache_expire(users=True)
        if lookup_type in ("groups", "users_and_groups"):
            client.sssctl.cache_expire(groups=True)

    client.sssd.stop()

    if invalidate_cache == "after":
        if lookup_type in ("users", "users_and_groups"):
            client.sssctl.cache_expire(users=True)
        if lookup_type in ("groups", "users_and_groups"):
            client.sssctl.cache_expire(groups=True)

    assert client.tools.getent.passwd(u1.name) is None, f"`{u1.name}` should NOT be found after stopping SSSD."
    assert client.tools.getent.group(g1.name) is None, f"`{g1.name}` should NOT be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__cache_timeout_zero_disables_memcache(client: Client, provider: GenericProvider):
    """
    :title: memcache_timeout set to 0 disables cache entirely
    :setup:
        1. Create user `user1` and group `group1`.
        2. Set `memcache_timeout = 0` in SSSD config.
        3. Start SSSD.
    :steps:
        1. Perform id lookup for `user1`.
        2. Perform getent group lookup for `group1`.
        3. Stop SSSD.
        4. Attempt to perform id lookup for `user1`.
        5. Attempt to perform getent group lookup for `group1`.
    :expectedresults:
        1. `user1` is found while SSSD is running.
        2. `group1` is found while SSSD is running.
        3. SSSD stops successfully.
        4. `user1` is not found after SSSD is stopped.
        5. `group1` is not found after SSSD is stopped.
    :customerscenario: True"
    """

    u1 = provider.user("user1").add()
    g1 = provider.group("group1").add()

    client.sssd.nss["memcache_timeout"] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd(u1.name) is not None, f"`{u1.name}` should be found"
    assert client.tools.getent.group(g1.name) is not None, f"`{g1.name}` should be found"

    client.sssd.stop()

    assert client.tools.getent.passwd(g1.name) is None, f"`{u1.name}` should NOT be found after SSSD is stopped"
    assert client.tools.getent.group(g1.name) is None, f"`{g1.name}` should NOT be found after SSSD is stopped"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__initgroup_cache_disabled_and_user_group_resolution(client: Client, provider: GenericProvider):
    """
    :title: Disabling only initgroups cache doesn't prevent user/group membership resolution after SSSD is stopped
    :setup:
        1. Create user `user1`.
        2. Create groups `group1` and `group2`, and add `user1` to both.
        3. Set `memcache_size_initgroups = 0` in SSSD configuration.
        4. Start SSSD.
    :steps:
        1. Run `id user1` and validate group membership.
        2. Stop SSSD.
        3. Run `id user1` again.
    :expectedresults:
        1. `user1` is found and member of both groups.
        2. SSSD stops successfully.
        3. After stopping SSSD, group/user membership is resolved.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    g1 = provider.group("group1").add().add_member(u1)
    g2 = provider.group("group2").add().add_member(u1)

    client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.start()

    result = client.tools.id(u1.name)
    assert result is not None, f"`{u1.name}` should still be found before SSSD is stopped."
    assert result.memberof([g1.name, g1.name]), "Group membership should be resolved before SSSD is stopped."

    client.sssd.start()

    result = client.tools.id(u1.name)
    assert result is not None, f"`{u1.name}` should still be found after SSSD is stopped."
    assert result.memberof([g1.name, g2.name]), "Group membership should be resolved after SSSD is stopped."


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("case_sensitive", [True, False], ids=["case_sensitive", "case_insensitive"])
def test_memcache__case_sensitivity_affects_cache_lookup(client: Client, provider: IPA | LDAP, case_sensitive: bool):
    """
    :title: Cache lookup respects or ignores case based on `case_sensitive` setting
    :setup:
        1. Create user `user1`.
        2. Set `case_sensitive` in SSSD configuration.
        3. Start SSSD.
    :steps:
        1. Lookup user1 with mixed casing to populate memory cache.
        2. Stop SSSD.
        3. Lookup again with the same and other casings.
            `case_sensitive = true`: Lookup works only for matching case
            `case_sensitive = false`: Lookup works only for last case
    :expectedresults:
        1. User is found while SSSD is running.
        2. SSSD stops successfully.
        3. Lookup works only:
            When `case_sensitive = true` only for matching case
            When `case_sensitive = false` only with the last lookup
    :customerscenario: False
    :documentationReference:
        IPA: IdM automatically converts the name to lowercase when saving it.
        AD/Samba: sssd.conf(5) man page -> case_sensitive
    """

    u1 = provider.user("user1").add()

    client.sssd.domain["case_sensitive"] = "true" if case_sensitive else "false"

    client.sssd.start()

    if case_sensitive:
        assert client.tools.getent.passwd("USER1") is None, "USER1 was NOT supposed to be found"
    else:
        assert client.tools.getent.passwd("USER1") is not None, "USER1 was supposed to be found"

    assert client.tools.getent.passwd(u1.name) is not None, f"{u1.name} was supposed to be found"

    client.sssd.stop()

    assert client.tools.getent.passwd(u1.name) is not None, f"{u1.name} was supposed to be found in cache"
    # Only last lookup name is stored in cache
    assert client.tools.getent.passwd("USER1") is None, f"{u1.name} was NOT supposed to be found in cache"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("use_fqdn", [True, False], ids=["with_fqdn", "without_fqdn"])
def test_memcache__lookup_users_by_fully_qualified_names(client: Client, provider: GenericProvider, use_fqdn: bool):
    """
    :title: Cache lookup works based on `use_fully_qualified_names` setting
    :setup:
        1. Create user `user1`.
        2. Set `use_fully_qualified_names` in SSSD configuration.
        3. Start SSSD.
    :steps:
        1. Lookup user1 using the correct format (fqdn or not).
        2. Stop SSSD.
        3. Attempt lookups in both forms.
    :expectedresults:
        1. User is found while SSSD is running.
        2. SSSD stops successfully.
        3. Only the correct format (fqdn or not) is cached and retrievable.
    :customerscenario: False
    """
    u1 = provider.user("user1").add()

    client.sssd.domain["use_fully_qualified_names"] = "true" if use_fqdn else "false"

    client.sssd.start()

    if use_fqdn:
        assert (
            client.tools.getent.passwd(u1.name) is None
        ), f"`{u1.name}` should NOT be found when use_fully_qualified_names is {use_fqdn}"
        assert (
            client.tools.id(f"{u1.name}@test") is not None
        ), f"`{u1.name}@test` should be found when use_fully_qualified_names is {use_fqdn}"
    else:
        assert (
            client.tools.getent.passwd(u1.name) is not None
        ), f"`{u1.name}` should be found when use_fully_qualified_names is {use_fqdn}"
        assert (
            client.tools.id(f"{u1.name}@test") is not None
        ), f"{u1.name}@test` should be found when use_fully_qualified_names is {use_fqdn}"

    client.sssd.stop()

    if use_fqdn:
        assert (
            client.tools.id(f"{u1.name}@test") is not None
        ), f"`{u1.name}@test` should be found when use_fully_qualified_names is {use_fqdn}"
        assert (
            client.tools.getent.passwd(u1.name) is None
        ), f"`{u1.name}` should NOT be found when use_fully_qualified_names is {use_fqdn}"
    else:
        assert (
            client.tools.id(f"{u1.name}@test") is None
        ), f"`{u1.name}@test` should be found when use_fully_qualified_names is {use_fqdn}"
        assert (
            client.tools.getent.passwd(u1.name) is not None
        ), f"`{u1.name}` should be found when use_fully_qualified_names is {use_fqdn}"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__truncate_cache_file_does_not_crash(client: Client, provider: GenericProvider):
    """
    :title: Accessing truncated in-memory cache file does not cause failure
    :setup:
        1. Create user `user1`.
        2. Start SSSD.
    :steps:
        1. Lookup `user1` to populate memory cache.
        2. Truncate the cache file.
        3. Lookup `user1` again.
    :expectedresults:
        1. `user1` is found before truncating.
        2. Truncation succeeds.
        3. `user1` is still resolved and system does not crash.
    :customerscenario: True
    """

    u1 = provider.user("user1").add()

    client.sssd.start()

    result = client.tools.id(u1.name)
    assert result is not None, f"`{u1.name}` should be found before truncating cache."

    client.fs.truncate("/var/lib/sss/mc/passwd")

    result = client.tools.id(u1.name)
    assert result is not None, f"`{u1.name}` should still be found after cache truncation."
    assert result.user.name == u1.name, f"Expected username `{u1.name}` after truncation."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("by_gid", [False, True], ids=["by_group_name", "by_group_id"])
def test_memcache__lookup_user_membership_with_cache(client: Client, provider: GenericProvider, by_gid: bool):
    """
    :title: Lookup user and test membership by group name or gid using memory cache
    :setup:
        1. Create `user1` and `user2`.
        2. Create groups
            `group1` with gid=1001
            `group2` with gid=1002
        3. Add `user1` to `group1` and `group2`
        4. Add `user2` to `group2`
        5. Start SSSD
    :steps:
        1. Lookup users and verify memberships.
        2. Stop SSSD.
        3. Lookup users and verify memberships again.
    :expectedresults:
        1. Users are found and have correct group memberships.
        2. SSSD stops successfully.
        3. Users are still found with correct group memberships.
    :customerscenario: False
    """

    u1 = provider.user("user1").add(uid=110001, gid=1110001)
    u2 = provider.user("user2").add(uid=110002, gid=1110002)

    g1 = provider.group("group1").add(gid=1001).add_member(u1)
    g2 = provider.group("group2").add(gid=1002).add_members([u1, u2])

    # Using specific uid and gid require ldap_id_mapping false
    if isinstance(provider, (AD, Samba)) and by_gid:
        client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    r1 = client.tools.id(u1.name)
    assert r1 is not None, f"`{u1.name}` should be found"

    r2 = client.tools.id(u2.name)
    assert r2 is not None, f"`{u2.name}` should be found"

    if by_gid:
        assert r1.memberof([1001, 1002]), f"`{u1.name}` is not member of the expected groups"
        assert r2.memberof(1002), f"`{u2.name}` is not member of the expected groups"
    else:
        assert r1.memberof([g1.name, g2.name]), f"`{u1.name}` is not member of the expected groups"
        assert r2.memberof(g2.name), f"`{u2.name}` is not member of the expected groups"

    client.sssd.stop()

    r1 = client.tools.id(u1.name)
    assert r1 is not None, f"`{u1.name}` should be found"

    r2 = client.tools.id(u2.name)
    assert r2 is not None, f"`{u2.name}` should be found"

    if by_gid:
        assert r1.memberof([1001, 1002]), f"`{u1.name}` is not member of the expected groups"
        assert r2.memberof(1002), f"`{u2.name}` is not member of the expected groups"
    else:
        assert r1.memberof([g1.name, g2.name]), f"`{u1.name}` is not member of the expected groups"
        assert r2.memberof(g2.name), f"`{u2.name}` is not member of the expected groups"

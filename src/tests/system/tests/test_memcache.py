"""
SSSD In-Memory Cache (memcache) Test Cases.

:requirement: memcache

:note: Stopping SSSD is the easiest way to check the memcache, but it doesn't mean it is supposed to work
exactly like when SSSD is running.
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__users_and_groups_caches_enabled(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for users and groups with all caches enabled
    :setup:
        1. Create user `user1` and group `group1`.
        2. Start SSSD
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Stop SSSD and perform lookup again for `user1` and `group1`.
    :expectedresults:
        1. `user1` and `group1` are found.
        2. `user1` and `group1` are still found.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should still be found after stopping SSSD."
    assert client.tools.getent.group("group1") is not None, "`group1` should still be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__users_and_groups_caches_disabled(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for users and groups with all caches disabled
    :setup:
        1. Create user `user1` and group `group1`.
        2. Disable all caches in SSSD configuration.
        3. Start SSSD
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Stop SSSD and perform lookup again for `user1` and `group1`.
    :expectedresults:
        1. `user1` and `group1` are found.
        2. `user1` and `group1` are NOT found.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.nss["memcache_size_passwd"] = "0"
    client.sssd.nss["memcache_size_group"] = "0"
    client.sssd.nss["memcache_size_initgroups"] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is None, "`user1` should NOT be found after stopping SSSD."
    assert client.tools.getent.group("group1") is None, "`group1` should NOT be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__users_cache_disabled(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for users with disabled cache.
    :setup:
        1. Create user `user1` and group `group1`.
        2. Configure SSSD to disable `memcache_size_passwd`.
        3. Start SSSD
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Stop SSSD and perform lookup again for `user1` and `group1`.
    :expectedresults:
        1. `user1` and `group1` are found.
        2. `user1` is NOT found.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.nss["memcache_size_passwd"] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is None, "`user1` should NOT be found after stopping SSSD."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__groups_cache_disabled(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for groups with disabled cache
    :setup:
        1. Create user `user1` and group `group1`.
        2. Configure SSSD to disable `memcache_size_group`.
        3. Start SSSD
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Stop SSSD and perform lookup again for `user1` and `group1`.
    :expectedresults:
        1. `user1` and `group1` are found.
        2. `group1` is NOT found.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.nss["memcache_size_group"] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found after stopping SSSD."
    assert client.tools.getent.group("group1") is None, "`group1` should NOT be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__users_and_groups_cache_expired_before_stoppind_sssd(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for users and groups expiring cache BEFORE stopping SSSD
    :setup:
        1. Create test users `user1` and group `group1`.
        3. Start SSSD.
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Expire users and groups cache, stop SSSD, lookup again.
    :expectedresults:
        1. `user1` and `group1` are found while SSSD is running.
        2. `user1` and/or `group1` are not found after stopping SSSD.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssctl.cache_expire(users=True)
    client.sssctl.cache_expire(groups=True)

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is None, "`user1` should NOT be found after stopping SSSD."
    assert client.tools.getent.group("group1") is None, "`group1` should NOT be found after stopping SSSD."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__users_and_groups_cache_expired_after_stoppind_sssd(client: Client, provider: GenericProvider):
    """
    :title: Validate memory cache behavior for users and groups expiring cache AFTER stopping SSSD
    :setup:
        1. Create test users `user1` and group `group1`.
        2. Configure SSSD with default cache settings.
        3. Start SSSD.
    :steps:
        1. Perform lookup operation for `user1` and `group1`.
        2. Stop SSSD, expire users and groups cache, lookup again.
    :expectedresults:
        1. `user1` and `group1` are found while SSSD is running.
        2. `user1` and/or `group1` are not found after stopping SSSD.
    :customerscenario: False
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found while SSSD is running."
    assert client.tools.getent.group("group1") is not None, "`group1` should be found while SSSD is running."

    client.sssd.stop()

    client.sssctl.cache_expire(users=True)
    client.sssctl.cache_expire(groups=True)

    assert client.tools.getent.passwd("user1") is None, "`user1` should NOT be found after stopping SSSD."
    assert client.tools.getent.group("group1") is None, "`group1` should NOT be found after stopping SSSD."


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
        1. Perform lookup for `user1` and `group1`
        2. Stop SSSD and perform lookup for `user1` and `group1`
    :expectedresults:
        1. `user1` and `group1` are found while SSSD is running.
        2. `user1` and `group1` are NOT found while SSSD is stopped.
    :customerscenario: True"
    """

    provider.user("user1").add()
    provider.group("group1").add()

    client.sssd.nss["memcache_timeout"] = "0"

    client.sssd.start()

    assert client.tools.getent.passwd("user1") is not None, "`user1` should be found"
    assert client.tools.getent.group("group1") is not None, "`group1` should be found"

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is None, "`user1` should NOT be found after SSSD is stopped"
    assert client.tools.getent.group("group1") is None, "`group1` should NOT be found after SSSD is stopped"


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
        1. Perform `id user1` and validate group membership.
        2. Stop SSSD and perform `id user1` again.
    :expectedresults:
        1. `user1` is found and member of both groups.
        2. After stopping SSSD, group/user membership is not resolved.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()

    provider.group("group1").add().add_member(u1)
    provider.group("group2").add().add_member(u1)

    client.sssd.nss["memcache_size_initgroups"] = "0"

    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "`user1` should be found before SSSD is stopped."
    assert result.memberof(["group1", "group2"]), "Group membership should be resolved before SSSD is stopped."

    assert client.tools.getent.group("group1") is not None, "`group1` should be found after SSSD is stopped"

    assert client.tools.getent.group("group2") is not None, "`group2` should be found after SSSD is stopped"

    client.sssd.stop()

    result = client.tools.id("user1")
    assert result is not None, "`user1` should still be found after SSSD is stopped."
    assert (
        result.memberof(["group1", "group2"]) is not None
    ), "Group membership should still be resolved after SSSD is stopped."

    assert client.tools.getent.group("group1") is not None, "`group1` should still be found after SSSD is stopped"

    assert client.tools.getent.group("group2") is not None, "`group2` should still be found after SSSD is stopped"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("case_sensitive", [True, False], ids=["case_sensitive", "case_insensitive"])
def test_memcache__case_sensitivity_affects_cache_lookup(client: Client, provider: IPA | LDAP, case_sensitive: bool):
    """
    :title: Cache lookup respects or ignores case based on `case_sensitive`
    :setup:
        1. Create user `user1`.
        2. Set `case_sensitive` in SSSD configuration.
        3. Start SSSD.
    :steps:
        1. Lookup user1 with mixed casing to populate memory cache.
        2. Stop SSSD and lookup again with the same and other casings.
            `case_sensitive = true`: Lookup works only for matching case
            `case_sensitive = false`: Lookup works only for last case
    :expectedresults:
        1. User is found while SSSD is running.
        2. Lookup works only:
            When `case_sensitive = true` only for matching case
            When `case_sensitive = false` only with the last lookup
    :customerscenario: False
    :documentationReference:
        IPA: IdM automatically converts the name to lowercase when saving it.
        AD/Samba: sssd.conf(5) man page -> case_sensitive
    """

    provider.user("user1").add()

    client.sssd.domain["case_sensitive"] = "true" if case_sensitive else "false"

    client.sssd.start()

    # [Andre] I don't think it is worth to create a new test to avoid this if, but I am open to feedback
    # I'll remove this comment after the review/feedback
    if case_sensitive:
        assert client.tools.getent.passwd("USER1") is None, "`USER1` was NOT supposed to be found"
    else:
        assert client.tools.getent.passwd("USER1") is not None, "`USER1` was supposed to be found"

    assert client.tools.getent.passwd("user1") is not None, "`user1` was supposed to be found"

    client.sssd.stop()

    assert client.tools.getent.passwd("user1") is not None, "`user1` was supposed to be found in cache"

    # Only last lookup name is stored in cache
    assert client.tools.getent.passwd("USER1") is None, "`user1` was NOT supposed to be found in cache"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__lookup_users_with_fully_qualified_name(client: Client, provider: GenericProvider):
    """
    :title: Cache lookup works based on `use_fully_qualified_names`
    :setup:
        1. Create user `user1`.
        2. Set `use_fully_qualified_names` in SSSD configuration.
        3. Start SSSD.
    :steps:
        1. Lookup `user1` using the correct format (fqdn).
        2. Stop SSSD and attempt to lookup with getent and id.
    :expectedresults:
        1. User is found while SSSD is running.
        2. Only the correct format (fqdn) is cached and retrievable.
    :customerscenario: False
    """
    provider.user("user1").add()

    client.sssd.domain["use_fully_qualified_names"] = "true"

    client.sssd.start()

    assert (
        client.tools.getent.passwd("user1") is None
    ), "`user1` should NOT be found when use_fully_qualified_names is enabled"
    assert (
        client.tools.id("user1@test") is not None
    ), "`user1@test` should be found when use_fully_qualified_names is enabled"

    client.sssd.stop()

    assert (
        client.tools.id("user1@test") is not None
    ), "`user1@test` should be found when use_fully_qualified_names is enabled"
    assert (
        client.tools.getent.passwd("user1") is None
    ), "`user1` should NOT be found when use_fully_qualified_names is enabled"


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

    provider.user("user1").add()

    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "`user1` should be found before truncating cache."

    client.fs.truncate("/var/lib/sss/mc/passwd")

    result = client.tools.id("user1")
    assert result is not None, "`user1` should still be found after cache truncation."
    assert result.user.name == "user1", "Expected username `user1` after truncation."


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__lookup_user_membership_by_group_id_with_cache_enabled(client: Client, provider: GenericProvider):
    """
    :title: Lookup user and test membership by group name or gid using memory cache
    :setup:
        1. Create `user1` and `user2` with uids and gids.
        2. Create groups `group1` and `group2` with gids
        3. Add `user1` to `group1` and `group2`
        4. Add `user2` to `group2`
        5. Start SSSD
    :steps:
        1. Lookup users and verify memberships.
        2. Stop SSSD and lookup users and verify memberships again.
    :expectedresults:
        1. Users are found and have correct group memberships.
        2. Users are still found with correct group memberships.
    :customerscenario: False
    """

    u1 = provider.user("user1").add(uid=1234, gid=123456)
    u2 = provider.user("user2").add(uid=5678, gid=567890)

    provider.group("group1").add(gid=9876).add_member(u1)
    provider.group("group2").add(gid=5432).add_members([u1, u2])

    # Using specific uid and gid require ldap_id_mapping false
    client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    r1 = client.tools.id("user1")
    assert r1 is not None, "`user1` should be found"

    r2 = client.tools.id("user2")
    assert r2 is not None, "`user2` should be found"

    assert r1.memberof([9876, 5432]), "`user1` is not member of the expected groups"
    assert r2.memberof(5432), "`user2` is not member of the expected groups"

    client.sssd.stop()

    r1 = client.tools.id("user1")
    assert r1 is not None, "`user1` should be found"

    r2 = client.tools.id("user2")
    assert r2 is not None, "`user2` should be found"

    assert r1.memberof([9876, 5432]), "`user1` is not member of the expected groups"
    assert r2.memberof(5432), "`user2` is not member of the expected groups"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_memcache__lookup_user_membership_by_group_name_with_cache_enabled(client: Client, provider: GenericProvider):
    """
    :title: Lookup user and test membership by group name using memory cache
    :setup:
        1. Create `user1` and `user2`
        2. Create groups `group1` and `group2`
        3. Add `user1` to `group1` and `group2`
        4. Add `user2` to `group2`
        5. Start SSSD
    :steps:
        1. Lookup users and verify memberships.
        2. Stop SSSD and lookup users and verify memberships again.
    :expectedresults:
        1. Users are found and have correct group memberships.
        2. Users are still found with correct group memberships.
    :customerscenario: False
    """

    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()

    provider.group("group1").add().add_member(u1)
    provider.group("group2").add().add_members([u1, u2])

    client.sssd.start()

    r1 = client.tools.id("user1")
    assert r1 is not None, "`user1` should be found"

    r2 = client.tools.id("user2")
    assert r2 is not None, "`user2` should be found"

    assert r1.memberof(["group1", "group2"]), "`user2` is not member of the expected groups"
    assert r2.memberof("group2"), "`user2` is not member of the expected groups"

    client.sssd.stop()

    r1 = client.tools.id("user1")
    assert r1 is not None, "`user1` should be found"

    r2 = client.tools.id("user2")
    assert r2 is not None, "`user2` should be found"

    assert r1.memberof(["group1", "group2"]), "`user1` is not member of the expected groups"
    assert r2.memberof("group2"), "`user2` is not member of the expected groups"

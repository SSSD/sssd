"""
SSSD In-Memory Cache (memcache) Test Cases.

:requirement: IDM-SSSD-REQ: Client side performance improvements
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name uses memory cache when SSSD is stopped
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that results have correct names
        3. Stop SSSD
        4. Find 'user1', 'user2' and 'user3' with id(name)
        5. Check that results have correct names
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. SSSD is stopped
        4. Users are found
        5. Users have correct names
    :customerscenario: False
    """

    def check(users):
        for user in users:
            result = client.tools.id(user)
            assert result is not None, f"User {user} was not found using id"
            assert result.user.name == user, f"Username {result.user.name} is incorrect, {user} expected"

    users = ["user1", "user2", "user3"]
    for user in users:
        provider.user(user).add()

    client.sssd.start()

    check(users)
    client.sssd.stop()
    check(users)


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_groups(client: Client, provider: GenericProvider):
    """
    :title: Lookup group by groupname uses memory cache when SSSD is stopped
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Check that groups have correct names
        3. Stop SSSD
        4. Find 'group1', 'group2' and 'group3' with getent.group(name)
        5. Check that groups have correct names
    :expectedresults:
        1. Groups are found
        2. Groups have correct names
        3. SSSD is stopped
        4. Groups are found
        5. Groups have correct names
    :customerscenario: False
    """

    def check(groups):
        for group in groups:
            result = client.tools.getent.group(group)
            assert result is not None, f"Group {group} was not found using getent"
            assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected"

    groups = ["group1", "group2", "group3"]
    for group in groups:
        provider.group(group).add()

    client.sssd.start()

    check(groups)
    client.sssd.stop()
    check(groups)


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__user_cache_is_disabled_and_lookup_groups(client: Client, provider: GenericProvider):
    """
    :title: Lookup group by groupname uses memory cache when SSSD is stopped and 'memcache_size_passwd' = 0
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. In SSSD nss change 'memcache_size_passwd' to '0'
        3. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Check that groups have correct names
        3. Stop SSSD
        4. Find 'group1', 'group2' and 'group3' with getent.group(name)
        5. Check that groups have correct names
    :expectedresults:
        1. Groups are found
        2. Groups have correct names
        3. SSSD is stopped
        4. Groups are found
        5. Groups have correct names
    :customerscenario: False
    """

    def check(groups):
        for group in groups:
            result = client.tools.getent.group(group)
            assert result is not None, f"Group {group} was not found using getent"
            assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected"

    groups = ["group1", "group2", "group3"]
    for group in groups:
        provider.group(group).add()

    client.sssd.nss["memcache_size_passwd"] = "0"
    client.sssd.start()

    check(groups)
    client.sssd.stop()
    check(groups)


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__user_cache_is_disabled_and_lookup_users(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name when SSSD is stopped and 'memcache_size_passwd' = 0
            uses memory cache therefore user is not found
    :setup:
        1. Add users to SSSD
        2. Set users uids and gids
        3. In SSSD nss change 'memcache_size_passwd' to '0'
        4. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users have correct names
        3. Stop SSSD
        4. Find users with id(name)
        5. Find users with id(uid)
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. SSSD is stopped
        4. Users are not found
        5. Users are not found
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.nss["memcache_size_passwd"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for user, id in ids:
        result = client.tools.id(user)
        assert result is not None, f"User {user} was not found using id"
        assert result.user.name == user, f"Username {result.user.name} is incorrect, {user} expected"
        assert result.user.id == id, f"User id {result.user.id} is incorrect, {id} expected"

    client.sssd.stop()

    for user, id in ids:
        assert client.tools.id(user) is None, f"User {user} was found which is not expected"
        assert client.tools.id(id) is None, f"User with id {id} was found which is not expected"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__initgroup_cache_is_disabled_and_lookup_groups(client: Client, provider: GenericProvider):
    """
    :title: Lookup group by groupname when SSSD is stopped and 'memcache_size_initgroups' = 0 uses memory cache
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. In SSSD nss change 'memcache_size_initgroups' to '0'
        3. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Check that groups have correct names
        3. Stop SSSD
        4. Find 'group1', 'group2' and 'group3' with getent.group(name)
        5. Check that groups have correct names
    :expectedresults:
        1. Groups are found
        2. Groups have correct names
        3. SSSD is stopped
        4. Groups are found
        5. Groups have correct names
    :customerscenario: False
    """

    def check(groups):
        for group in groups:
            result = client.tools.getent.group(group)
            assert result is not None, f"Group {group} was not found using getent"
            assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected"

    groups = ["group1", "group2", "group3"]
    for group in groups:
        provider.group(group).add()

    client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.start()

    check(groups)
    client.sssd.stop()
    check(groups)


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__initgroup_cache_is_disabled_and_lookup_users(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name and id when SSSD is stopped and 'memcache_size_initgroups' = 0 uses memory cache
    :setup:
        1. Add users to SSSD
        2. Set users uids and ids
        3. In SSSD nss change 'memcache_size_initgroups' to '0'
        4. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users have correct names and uids
        3. Stop SSSD
        4. Find 'user1', 'user2' and 'user3' with id(name)
        5. Check that users have correct names and uids
        6. Find 'user1', 'user2' and 'user3' with id(uid)
        7. Check that users have correct names and uids
    :expectedresults:
        1. Users are found
        2. Users have correct names and uids
        3. SSSD is stopped
        4. Users are found
        5. Users have correct names and uids
        6. Users are found
        7. Users have correct names and uids
    :customerscenario: False
    """

    def check(ids):
        for name, id in ids:
            result = client.tools.id(name)
            assert result is not None, f"User {name} was not found using id"
            assert result.user.name == name, f"Username {result.user.name} is incorrect, {user} expected"
            assert result.user.id == id, f"User id {result.user.id} is incorrect, {id} expected"

            result = client.tools.id(id)
            assert result is not None, f"User with id {id} was not found using id"
            assert result.user.name == name, f"Username {result.user.name} is incorrect, {user} expected"
            assert result.user.id == id, f"User id {result.user.id} is incorrect, {id} expected"

    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    check(ids)
    client.sssd.stop()
    check(ids)


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__group_cache_disabled_and_lookup_groups(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name and id when SSSD is stopped and 'memcache_size_group' = 0 uses memory cache,
            but lookup groups is not possible
    :setup:
        1. Add users to SSSD
        2. Set users uids and gids
        3. Add groups to SSSD
        4. Set groups gids
        5. Add users to groups
        6. In SSSD nss change 'memcache_size_group' to '0'
        7. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users have correct names
        3. Find 'group1' and 'group2' by getent.group(gid)
        4. Check that groups have correct gids and members
        5. Stop SSSD
        6. Find 'user1', 'user2' and 'user3' with id(name)
        7. Check that users have correct names
        8. Find 'group1' and 'group2' by getent.group(name)
        9. Find 'group1' and 'group2' by getent.group(gid)
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. Groups are found
        4. Groups have correct gids and members
        5. SSSD is stopped
        6. Users are found
        7. Users have correct names
        8. Groups are not found
        9. Groups are not found
    :customerscenario: False
    """

    def check(users):
        for user in users:
            rUser = client.tools.id(user)
            assert rUser is not None, f"User {rUser} was not found using id"
            assert rUser.user.name == user, f"Username {rUser.user.name} is incorrect, {user} expected"

    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    provider.group("group1").add(gid=1111).add_member(u1)
    provider.group("group2").add(gid=2222).add_members([u1, u2, u3])

    client.sssd.nss["memcache_size_group"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    users = ["user1", "user2", "user3"]
    check(users)

    for group, members in [(1111, ["user1"]), (2222, ["user1", "user2", "user3"])]:
        result = client.tools.getent.group(group)
        assert result is not None, f"Group {group} was not found using getent"
        assert result.gid == group, f"Group gid {result.gid} is incorrect, {group} expected"
        assert result.members == members, f"Group {group} members did not match the expected ones"

    client.sssd.stop()

    check(users)

    assert client.tools.id("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.id("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.id(1111) is None, "Group with gid 1111 was found which is not expected"
    assert client.tools.id(2222) is None, "Group with gid 2222 was found which is not expected"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__all_caches_disabled_and_all_lookups_fails(client: Client, provider: GenericProvider):
    """
    :title: Lookup user and group when SSSD is stopped and whole cache disabled
            uses memory cache and therefore it is not possible
    :setup:
        1. Add users to SSSD
        2. Set users uids
        3. Add groups to SSSD
        4. Set groups gids
        5. Add users to groups
        6. In SSSD nss change 'memcache_size_passwd' to '0'
        7. In SSSD nss change 'memcache_size_group' to '0'
        8. In SSSD nss change 'memcache_size_initgroups' to '0'
        9. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users have correct names
        3. Find 'group1' and 'group2' by getent.group(name)
        4. Check that groups have correct names and members
        5. Stop SSSD
        6. Find 'user1', 'user2' and 'user3' with id(name)
        7. Find 'user1', 'user2' and 'user3' with id(uid)
        8. Find 'group1' and 'group2' by getent.group(name)
        9. Find 'group1' and 'group2' by getent.group(gid)
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. Groups are found
        4. Groups have correct names and members
        5. SSSD is stopped
        6. Users are not found
        7. Users are not found
        8. Groups are not found
        9. Groups are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    provider.group("group1").add(gid=1111).add_member(u1)
    provider.group("group2").add(gid=2222).add_members([u1, u2, u3])

    client.sssd.nss["memcache_size_passwd"] = "0"
    client.sssd.nss["memcache_size_group"] = "0"
    client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for user in ["user1", "user2", "user3"]:
        result = client.tools.id(user)
        assert result is not None, f"User {user} was not found using id"
        assert result.user.name == user, f"Username {result.user.name} is incorrect, {user} expected"

    for group, members in [("group1", ["user1"]), ("group2", ["user1", "user2", "user3"])]:
        gresult = client.tools.getent.group(group)
        assert gresult is not None, f"Group {group} was not found using id"
        assert gresult.name == group, f"Groupname {gresult.name} is incorrect, {group} expected"
        assert gresult.members == members, f"Group {group} members did not match the expected ones"

    client.sssd.stop()

    for user in ["user1", "user2", "user3"]:
        assert client.tools.id(user) is None, f"User {user} was found which is not expected"

    for id in [10001, 10002, 10003]:
        assert client.tools.id(id) is None, f"User with id {id} was found which is not expected"

    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(1111) is None, "Group with gid 1111 was found which is not expected"
    assert client.tools.getent.group(2222) is None, "Group with gid 2222 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_check_group_memberships(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name and test membership by name use memory cache when SSSD is stopped
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Add 'group1' and 'group2' to SSSD
        3. Add users to groups
        4. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users are members of correct groups
        3. Stop SSSD
        4. Find 'user1', 'user2' and 'user3' with id(name)
        5. Check that users are members of correct groups
    :expectedresults:
        1. Users are found
        2. Users are members of correct groups
        3. SSSD is stopped
        4. Users are found
        5. Users are members of correct groups
    :customerscenario: False
    """

    def check():
        result = client.tools.id("user1")
        assert result is not None, "User user1 was not found using id"
        assert result.memberof(["group1", "group2"]), "User user1 is member of incorrect groups"

        result = client.tools.id("user2")
        assert result is not None, "User user2 was not found using id"
        assert result.memberof(["group2"]), "User user2 is member of incorrect groups"

        result = client.tools.id("user3")
        assert result is not None, "User user3 was not found using id"
        assert result.memberof(["group2"]), "User user3 is member of incorrect groups"

    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()
    u3 = provider.user("user3").add()

    provider.group("group1").add().add_member(u1)
    provider.group("group2").add().add_members([u1, u2, u3])

    client.sssd.start()

    check()
    client.sssd.stop()
    check()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_and_check_membership_by_gid(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by name and test membership by gid use memory cache when SSSD is stopped
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Add 'group1', 'group2' and 'group3' to SSSD
        3. Set group gids
        4. Add users to groups
        5. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users are members of correct groups
        3. Stop SSSD
        4. Find 'user1', 'user2' and 'user3' with id(name)
        5. Check that users are members of correct groups
    :expectedresults:
        1. Users are found
        2. Users are members of correct groups
        3. SSSD is stopped
        4. Users are found
        5. Users are members of correct groups
    :customerscenario: False
    """

    def check():
        result = client.tools.id("user1")
        assert result is not None, "User user1 was not found using id"
        assert result.memberof([1001, 1002]), "User user1 is member of incorrect groups"

        result = client.tools.id("user2")
        assert result is not None, "User user2 was not found using id"
        assert result.memberof([1002]), "User user2 is member of incorrect groups"

        result = client.tools.id("user3")
        assert result is not None, "User user3 was not found using id"
        assert result.memberof([1002]), "User user3 is member of incorrect groups"

    u1 = provider.user("user1").add(uid=11001, gid=19001)
    u2 = provider.user("user2").add(uid=11002, gid=19002)
    u3 = provider.user("user3").add(uid=11003, gid=19003)

    provider.group("group1").add(gid=1001).add_member(u1)
    provider.group("group2").add(gid=1002).add_members([u1, u2, u3])
    provider.group("group3").add(gid=1003)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    check()
    client.sssd.stop()
    check()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_uids_and_check_membership_by_gid(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by id and test membership by gid use memory cache when SSSD is stopped
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids and gids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add users to groups
        6. Start SSSD
    :steps:
        1. Find users by id(uid)
        2. Check that users are members of correct groups
        3. Stop SSSD
        4. Find users by id(uid)
        5. Check that users are members of correct groups
    :expectedresults:
        1. Users are found
        2. Users are members of correct groups
        3. SSSD is stopped
        4. Users are found
        5. Users are members of correct groups
    :customerscenario: False
    """

    def check():
        result = client.tools.id(2001)
        assert result is not None, "User with id 2001 was not found using id"
        assert result.memberof([101, 1001, 1002]), "User with id 2001 is member of incorrect groups"

        result = client.tools.id(2002)
        assert result is not None, "User with id 2002 was not found using id"
        assert result.memberof([102, 1002]), "User with id 2002 is member of incorrect groups"

        result = client.tools.id(2003)
        assert result is not None, "User with id 2003 was not found using id"
        assert result.memberof([103, 1002]), "User with id 2003 is member of incorrect groups"

    u1 = provider.user("user1").add(uid=2001, gid=101)
    u2 = provider.user("user2").add(uid=2002, gid=102)
    u3 = provider.user("user3").add(uid=2003, gid=103)

    provider.group("group1").add(gid=1001).add_member(u1)
    provider.group("group2").add(gid=1002).add_members([u1, u2, u3])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    check()
    client.sssd.stop()
    check()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_by_fully_qualified_names(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by full name when 'use_fully_qualified_names' is 'true'
            uses memory cache when sssd is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. In SSSD domain change 'use_fully_qualified_names' to 'true'
        3. Start SSSD
    :steps:
        1. Find 'user1' and 'user2' with id(name)
        2. Find 'user1' and 'user2' with id(name@domain)
        3. Check that users have correct full names
        4. Stop SSSD
        5. Find 'user1' and 'user2' with id(name)
        6. Find 'user1' and 'user2' with id(name@domain)
        7. Check that users have correct full names
    :expectedresults:
        1. Users are not found
        2. Users are found
        3. Users have correct full names
        4. SSSD is stopped
        5. Users are not found
        6. Users are found
        7. Users have correct full names
    :customerscenario: False
    """

    def check():
        assert client.tools.id("user1") is None, "User user1 should not be found without fully qualified name"
        assert client.tools.id("user2") is None, "User user2 should not be found without fully qualified name"

        result = client.tools.id("user1@test")
        assert result is not None, "User user1@test was not found using id"
        assert result.user.name == "user1@test", f"User {result.user.name} has incorrect name, user1@test expected"

        result = client.tools.id("user2@test")
        assert result is not None, "User user2@test was not found using id"
        assert result.user.name == "user2@test", f"User {result.user.name} has incorrect name, user2@test expected"

    provider.user("user1").add()
    provider.user("user2").add()

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.start()

    check()
    client.sssd.stop()
    check()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_when_case_insensitive_is_false(client: Client, provider: GenericProvider):
    """
    :title: Lookup user by case insensitive name when 'case_sensitive' is 'false'
            uses memory cache when SSSD is stopped
    :setup:
        1. Add 'user1' to SSSD
        2. Set user gid and uid
        3. Add groups to SSSD
        4. Set group gid
        5. Add member to the groups
        6. In SSSD domain change 'case_sensitive' to 'false'
        7. Start SSSD
    :steps:
        1. Find users with getent.initgroups(name), where name is in random lower and upper case format
        2. Check that usernames are correct
        3. Check that user is member of correct groups
        4. Stop SSSD
        5. Find user with getent.initgroups(name), where name is last name used when resolving user
        6. Check that username is correct
        7. Check that user is member of correct groups
        8. Find users with getent.initgroups(name), where names are previously used names
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. User is member of correct groups
        4. SSSD is stopped
        5. User is found
        6. User has correct name
        7. User is member of correct groups
        8. Users are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=10001, gid=2001)
    provider.group("group1").add(gid=10010).add_member(u1)
    provider.group("group2").add(gid=10011).add_member(u1)
    provider.group("group3").add(gid=10012).add_member(u1)

    client.sssd.domain["case_sensitive"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name in ["uSer1", "useR1", "USER1", "user1", "uSER1"]:
        result = client.tools.getent.initgroups(name)
        assert result.name == name, f"Username {result.name} is not correct, {name} expected"
        assert result.memberof([10010, 10011, 10012]), f"User {result.name} is member of wrong groups"

    client.sssd.stop()

    result = client.tools.getent.initgroups("uSER1")
    assert result.name == "uSER1", f"Username {result.name} is not correct, uSER1 expected"
    assert result.memberof([10010, 10011, 10012]), f"User {result.name} is member of wrong groups"

    # Only last version of name is stored in cache
    # That is why initgroups call returns no secondary groups
    assert client.tools.getent.initgroups("uSer1").groups == [], "User uSer1 should not be found in cache"
    assert client.tools.getent.initgroups("useR1").groups == [], "User useR1 should not be found in cache"
    assert client.tools.getent.initgroups("USER1").groups == [], "User USER1 should not be found in cache"
    assert client.tools.getent.initgroups("user1").groups == [], "User user1 should not be found in cache"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_when_fully_qualified_name_is_true_and_case_ins_is_false(
    client: Client, provider: GenericProvider
):
    """
    :title: Lookup user by case insensitive fully qualified name when 'case_sensitive' is 'false'
            and 'use_fully_qualified_names' is 'true' uses memory cache when SSSD is stopped
    :setup:
        1. Add user to SSSD
        2. Add groups to SSSD
        3. Set groups gids
        4. Add members to the groups
        5. In SSSD domain change 'use_fully_qualified_names' to 'true'
        6. In SSSD domain change 'case_sensitive' to 'false'
        7. Start SSSD
    :steps:
        1. Find user with names without domain
        2. Find user with getent.initgroups(name@domain), where name is in random lower and upper case format
        3. Check that user is members of correct groups
        4. Stop SSSD
        5. Find user with getent.initgroups(name@domain), where same name as in 2.
        6. Check that user is member of correct groups
        7. Find users with names, that should not be found
    :expectedresults:
        1. User is not found
        2. User is found
        3. User is member of correct groups
        4. SSSD is stopped
        5. User is found
        6. User is member of correct groups
        7. Users are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(gid=19001, uid=11001)

    provider.group("group1").add(gid=20001).add_member(u1)
    provider.group("group2").add(gid=20002).add_member(u1)
    provider.group("group3").add(gid=20003).add_member(u1)

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.domain["case_sensitive"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.tools.getent.initgroups("uSer1").groups == [], "User uSer1 should be found only with fq name"
    assert client.tools.getent.initgroups("user1").groups == [], "User user1 should be found only with fq name"

    result = client.tools.getent.initgroups("uSer1@test")
    assert result.memberof([20001, 20002, 20003]), "User uSer1@test is member of incorrect groups"

    client.sssd.stop()

    result = client.tools.getent.initgroups("uSer1@test")
    assert result.memberof([20001, 20002, 20003]), "User uSer1@test is member of incorrect groups"

    assert client.tools.getent.initgroups("user1@test").groups == [], "User user1@test should not be found in cache"
    assert client.tools.getent.initgroups("user1").groups == [], "User user1 should be found only with fq name"
    assert client.tools.getent.initgroups("uSer1").groups == [], "User uSer1 should be found only with fq name"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidation_of_gids_after_initgroups(client: Client, provider: GenericProvider):
    """
    :title: Invalidate groups after initgroups call when SSSD is stopped
    :setup:
        1. Add 'user1' to SSSD
        2. Set user uid and gid
        3. Add groups to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Check that "user1" has correct attributes
        2. Check that groups have correct attributes
        3. Check that "user1" has correct initgroups
        4. Stop SSSD
        5. Check that "group2" has correct attributes
        6. Check that "user1" has correct initgroups
        7. All "user1" initgroups should be invalidated and not found
    :expectedresults:
        1. User has correct attributes
        2. Groups have correct attributes
        3. User has correct initgroups
        4. SSSD is stopped
        5. Group has correct attributes
        6. User has correct attributes
        7. Groups are not found
    :customerscenario: False
    """

    def check_user_passwd():
        for user in ("user1", 10001):
            result = client.tools.getent.passwd(user)
            assert result is not None, f"User {user} was not found using getent"
            assert result.uid == 10001, f"User id {result.uid} is incorrect, expected 10001"
            assert result.name == "user1", f"Username {result.name} is incorrect, expected user1"

    def check_initgroups():
        result = client.tools.getent.initgroups("user1")
        assert result.name == "user1", f"Username {result.name} is incorrect, user1 expected"
        assert result.memberof([12345]), "User user1 is member of incorrect groups"

    def check_group(name, gid):
        for group in (name, gid):
            gresult = client.tools.getent.group(group)
            assert gresult is not None, f"Group {group} was not found using getent"
            assert gresult.name == name, f"Groupname {gresult.name} is incorrect, {name} expected"
            assert gresult.gid == gid, f"Group gid {gresult.gid} is incorrect, {gid} expected"

    u1 = provider.user("user1").add(uid=10001, gid=19001)

    provider.group("group1").add(gid=12345).add_member(u1)
    provider.group("group1_").add(gid=123450).add_member(u1)
    provider.group("group2").add(gid=22222)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    check_user_passwd()

    check_group("group1", 12345)
    check_group("group2", 22222)

    check_initgroups()

    client.sssd.stop()

    check_user_passwd()
    check_group("group2", 22222)

    check_initgroups()

    assert client.tools.getent.group(12345) is None, "Group with gid 12345 was found which is not expected"
    assert client.tools.getent.group(123450) is None, "Group with gid 123450 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group("group1_") is None, "Group group1_ was found which is not expected"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_initgroups_without_change_in_membership(client: Client, provider: GenericProvider):
    """
    :title: Invalidated cache, after refresh and stopped SSSD, has everything loaded in memory
    :setup:
        1. Add 'user1' to SSSD
        2. Set user gid and uid
        3. Add 'group1' to SSSD
        4. Set group gid
        5. Add members to the group
        6. Start SSSD
    :steps:
        1. Find user with id(name) and id(uid)
        2. Check that user is member of correct groups
        3. Find group with getent.group(name) and getent.group(gid)
        4. Check that the group have correct name and gid
        5. Invalidate whole cache
        6. Find user with id(name) and id(uid)
        7. Check that user is member of correct groups
        8. Find group with getent.group(name) and getent.group(gid)
        9. Check that the group have correct name and gid
        10. Stop SSSD
        11. Find user with id(name) and id(uid)
        12. Check that user is member of correct groups
        13. Find group with getent.group(name) and getent.group(gid)
        14. Check that the group have correct name and gid
    :expectedresults:
        1. User is found
        2. User is member of correct groups
        3. Group is found
        4. Group has correct name and gid
        5. Cache is invalidated
        6. User is found
        7. User is member of correct groups
        8. Group is found
        9. Group has correct name and gid
        10. SSSD is stopped
        11. User is found
        12. User is member of correct groups
        13. Group is found
        14. Group has correct name and gid
    :customerscenario: False
    """

    def check():
        result = client.tools.id("user1")
        assert result is not None, "User user1 was not found using id"
        assert result.memberof([111, 12345]), "User user1 is member of incorrect groups"

        result = client.tools.id(10001)
        assert result is not None, "User with id 10001 was not found using id"
        assert result.memberof([111, 12345]), "User with id 10001 is member of incorrect groups"

        gresult = client.tools.getent.group("group1")
        assert gresult is not None, "Group group1 was not found using getent"
        assert gresult.gid == 12345, f"Group gid {gresult.gid} is incorrect, 12345 expected"

        gresult = client.tools.getent.group(12345)
        assert gresult is not None, "Group with gid 12345 was not found using getent"
        assert gresult.name == "group1", f"Groupname {gresult.name} is incorrect, group1 expected"

        gresult = client.tools.getent.group("group2")
        assert gresult is not None, "Group group2 was not found using getent"
        assert gresult.gid == 222222, f"Group gid {gresult.gid} is incorrect, 222222 expected"

        gresult = client.tools.getent.group(222222)
        assert gresult is not None, "Group with gid 222222 was not found using getent"
        assert gresult.name == "group2", f"Groupname {gresult.name} is incorrect, group2 expected"

        result = client.tools.getent.initgroups("user1")
        assert result.memberof([12345, 123450]), "User user1 is member of incorrect groups"

    u1 = provider.user("user1").add(uid=10001, gid=111)
    provider.group("group1").add(gid=12345).add_member(u1)
    provider.group("group1_").add(gid=123450).add_member(u1)
    provider.group("group2").add(gid=222222)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    check()
    client.sssctl.cache_expire(everything=True)
    check()
    client.sssd.stop()
    check()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_user_cache_before_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate user cache before SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users gids and uids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find user with id(name)
        2. Check that user has correct id
        3. Check that user is member of correct groups
        4. Invalidate cache for 'user1'
        5. Stop SSSD
        6. Find user by id(name) and id(uid)
        7. Find the user's groups by getent.group(name) and getent.group(uid)
    :expectedresults:
        1. User is found
        2. User has correct id
        3. User is member of correct groups
        4. Cache is invalidated
        5. SSSD is stopped
        6. User is not found
        7. Group is not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"
    assert result.memberof([110011, 101010, 202020]), "User user1 is member of incorrect groups"

    client.sssctl.cache_expire(user="user1")
    client.sssd.stop()

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_user_cache_after_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate user cache after SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users gids and uids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find user with id(name)
        2. Check that user has correct id
        3. Check that user is member of correct groups
        4. Stop SSSD
        5. Invalidate cache for 'user1'
        6. Find user by id(name) and id(uid)
        7. Find the user's groups by getent.group(name) and getent.group(uid)
    :expectedresults:
        1. User is found
        2. User has correct id
        3. User is member of correct groups
        4. SSSD is stopped
        5. Cache is invalidated
        6. User is not found
        7. Group is not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"
    assert result.memberof([110011, 101010, 202020]), "User user1 is member of incorrect groups"

    client.sssd.stop()
    client.sssctl.cache_expire(user="user1")

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_users_cache_before_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate users cache before SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users gids and uids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find users with id(name)
        2. Check that users have correct ids
        3. Check that users are members of correct groups
        4. Invalidate cache for all users
        5. Stop SSSD
        6. Find users by id(name) and id(uid)
        7. Find the groups of users by getent.group(name) and getent.group(uid)
    :expectedresults:
        1. Users are found
        2. Users have correct ids
        3. Users are members of correct groups
        4. Cache is invalidated
        5. SSSD is stopped
        6. Users are not found
        7. Groups are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"
    assert result.memberof([110011, 101010, 202020]), "User user1 is member of incorrect groups"

    result = client.tools.id("user2")
    assert result is not None, "User user2 was not found using id"
    assert result.user.id == 220022, f"User id {result.user.id} is incorrect, 220022 expected"
    assert result.memberof([222222, 202020]), "User user2 is member of incorrect groups"

    client.sssctl.cache_expire(users=True)
    client.sssd.stop()

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"
    assert client.tools.id("user2") is None, "User user2 was found which is not expected"
    assert client.tools.id(220022) is None, "User with id 220022 was found which is not expected"
    assert client.tools.getent.group(222222) is None, "Group with gid 222222 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_users_cache_after_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate users cache after SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users gids and uids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find users with id(name)
        2. Check that users have correct ids
        3. Check that users are members of correct groups
        4. Stop SSSD
        5. Invalidate cache for all users
        6. Find users by id(name) and id(uid)
        7. Find the groups of users by getent.group(name) and getent.group(uid)
    :expectedresults:
        1. Users are found
        2. Users have correct ids
        3. Users are members of correct groups
        4. SSSD is stopped
        5. Cache is invalidated
        6. Users are not found
        7. Groups are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"
    assert result.memberof([110011, 101010, 202020]), "User user1 is member of incorrect groups"

    result = client.tools.id("user2")
    assert result is not None, "User user2 was not found using id"
    assert result.user.id == 220022, f"User id {result.user.id} is incorrect, 220022 expected"
    assert result.memberof([222222, 202020]), "User user2 is member of incorrect groups"

    client.sssd.stop()
    client.sssctl.cache_expire(users=True)

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"
    assert client.tools.id("user2") is None, "User user2 was found which is not expected"
    assert client.tools.id(220022) is None, "User with id 220022 was found which is not expected"
    assert client.tools.getent.group(222222) is None, "Group with gid 222222 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_group_cache_before_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate group cache before SSSD is stopped
    :setup:
        1. Add 'group1' to SSSD
        2. Set group gid
        3. Start SSSD
    :steps:
        1. Find the 'group1' getent.group(name)
        2. Check that group has correct id
        3. Check that group has correct name
        4. Invalidate cache for 'group1'
        5. Stop SSSD
        6. Find the 'group1' getent.group(name) and getent.group(uid)
    :expectedresults:
        1. Group is found
        2. Group has correct id
        3. Group has correct name
        4. Cache is invalidated
        5. SSSD is stopped
        6. Group is not found
    :customerscenario: False
    """
    provider.group("group1").add(gid=101010)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.group("group1")
    assert result is not None, "Group group1 was not found using getent"
    assert result.name == "group1", f"Groupname {result.name} is incorrect, group1 expected"
    assert result.gid == 101010, f"Group gid {result.gid} is incorrect, 101010 expected"

    client.sssctl.cache_expire(group="group1")
    client.sssd.stop()

    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_group_cache_after_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate group cache after SSSD is stopped
    :setup:
        1. Add 'group1' to SSSD
        2. Set group gid
        3. Start SSSD
    :steps:
        1. Find the 'group1' getent.group(name)
        2. Check that group has correct id
        3. Check that group has correct name
        4. Stop SSSD
        5. Invalidate cache for 'group1'
        6. Find the 'group1' getent.group(name) and getent.group(uid)
    :expectedresults:
        1. Group is found
        2. Group has correct id
        3. Group has correct name
        4. SSSD is stopped
        5. Cache is invalidated
        6. Group is not found
    :customerscenario: False
    """
    provider.group("group1").add(gid=101010)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.group("group1")
    assert result is not None, "Group group1 was not found using getent"
    assert result.name == "group1", f"Groupname {result.name} is incorrect, group1 expected"
    assert result.gid == 101010, f"Group gid {result.gid} is incorrect, 101010 expected"

    client.sssd.stop()
    client.sssctl.cache_expire(group="group1")

    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_groups_cache_before_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate groups cache before SSSD is stopped
    :setup:
        1. Add 'group1' and 'group2' to SSSD
        2. Set groups gids
        3. Start SSSD
    :steps:
        1. Find groups with getent.group(name)
        2. Check that groups have correct gids
        3. Invalidate cache for all groups
        4. Stop SSSD
        5. Find 'group1' and 'group2' with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. Groups are found
        2. Groups have correct gids
        3. Cache is invalidated
        4. SSSD is stopped
        5. Groups are not found
    :customerscenario: False
    """
    provider.group("group1").add(gid=101010)
    provider.group("group2").add(gid=202020)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.group("group1")
    assert result is not None, "Group group1 was not found using getent"
    assert result.gid == 101010, f"Group gid {result.gid} is incorrect, 101010 expected"

    result = client.tools.getent.group("group2")
    assert result is not None, "Group group2 was not found using getent"
    assert result.gid == 202020, f"Group gid {result.gid} is incorrect, 202020 expected"

    client.sssctl.cache_expire(groups=True)
    client.sssd.stop()

    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("high")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_groups_cache_after_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate groups cache after SSSD is stopped
    :setup:
        1. Add 'group1' and 'group2' to SSSD
        2. Set groups gids
        3. Start SSSD
    :steps:
        1. Find groups with getent.group(name)
        2. Check that groups have correct gids
        3. Stop SSSD
        4. Invalidate cache for all groups
        5. Find 'group1' and 'group2' with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. Groups are found
        2. Groups have correct gids
        3. SSSD is stopped
        4. Cache is invalidated
        5. Groups are not found
    :customerscenario: False
    """
    provider.group("group1").add(gid=101010)
    provider.group("group2").add(gid=202020)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.group("group1")
    assert result is not None, "Group group1 was not found using getent"
    assert result.gid == 101010, f"Group gid {result.gid} is incorrect, 101010 expected"

    result = client.tools.getent.group("group2")
    assert result is not None, "Group group2 was not found using getent"
    assert result.gid == 202020, f"Group gid {result.gid} is incorrect, 202020 expected"

    client.sssd.stop()
    client.sssctl.cache_expire(groups=True)

    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_everything_before_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate all parts of cache before SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users uids and gids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find users with id(name)
        2. Check that users have correct uids
        3. Find groups with getent.group(name)
        4. Check that groups have correct gids
        5. Invalidate all parts of cache
        6. Stop SSSD
        7. Find 'user1' and 'user2' with id(name) and id(uid)
        8. Find 'group1' and 'group2' with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. Users are found
        2. Users have correct uids
        3. Groups are found
        4. Groups have correct gids
        5. Cache is invalidated
        6. SSSD is stopped
        7. Users are not found
        8. Groups are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"

    result = client.tools.id("user2")
    assert result is not None, "User user2 was not found using id"
    assert result.user.id == 220022, f"User id {result.user.id} is incorrect, 220022 expected"

    gresult = client.tools.getent.group("group1")
    assert gresult is not None, "Group group1 was not found using getent"
    assert gresult.gid == 101010, f"Group gid {gresult.gid} is incorrect, 101010 expected"

    gresult = client.tools.getent.group("group2")
    assert gresult is not None, "Group group2 was not found using getent"
    assert gresult.gid == 202020, f"Group gid {gresult.gid} is incorrect, 202020 expected"

    client.sssctl.cache_expire(everything=True)
    client.sssd.stop()

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.id("user2") is None, "User user2 was found which is not expected"
    assert client.tools.id(220022) is None, "User with id 220022 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__invalidate_everything_after_stop(client: Client, provider: GenericProvider):
    """
    :title: Invalidate all parts of cache after SSSD is stopped
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users uids and gids
        3. Add 'group1' and 'group2' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. Start SSSD
    :steps:
        1. Find users with id(name)
        2. Check that users have correct uids
        3. Find groups with getent.group(name)
        4. Check that groups have correct gids
        5. Stop SSSD
        6. Invalidate all parts of cache
        7. Find 'user1' and 'user2' with id(name) and id(uid)
        8. Find 'group1' and 'group2' with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. Users are found
        2. Users have correct uids
        3. Groups are found
        4. Groups have correct gids
        5. SSSD is stopped
        6. Cache is invalidated
        7. Users are not found
        8. Groups are not found
    :customerscenario: False
    """
    u1 = provider.user("user1").add(uid=123456, gid=110011)
    u2 = provider.user("user2").add(uid=220022, gid=222222)

    provider.group("group1").add(gid=101010).add_member(u1)
    provider.group("group2").add(gid=202020).add_members([u1, u2])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"

    result = client.tools.id("user2")
    assert result is not None, "User user2 was not found using id"
    assert result.user.id == 220022, f"User id {result.user.id} is incorrect, 220022 expected"

    gresult = client.tools.getent.group("group1")
    assert gresult is not None, "Group group1 was not found using getent"
    assert gresult.gid == 101010, f"Group gid {gresult.gid} is incorrect, 101010 expected"

    gresult = client.tools.getent.group("group2")
    assert gresult is not None, "Group group2 was not found using getent"
    assert gresult.gid == 202020, f"Group gid {gresult.gid} is incorrect, 202020 expected"

    client.sssd.stop()
    client.sssctl.cache_expire(everything=True)

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.id("user2") is None, "User user2 was found which is not expected"
    assert client.tools.id(220022) is None, "User with id 220022 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(110011) is None, "Group with gid 110011 was found which is not expected"
    assert client.tools.getent.group("group2") is None, "Group group2 was found which is not expected"
    assert client.tools.getent.group(202020) is None, "Group with gid 202020 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__memcache_timeout_zero(client: Client, provider: GenericProvider):
    """
    :title: Cache is not created at all when 'memcache_timeout' set to '0'
    :setup:
        1. Add 'user1' to SSSD
        2. Set user uid
        3. Add 'group1' to SSSD
        4. Set group gid
        5. In SSSD nss change 'memcache_timeout' set to '0'
        6. Start SSSD
    :steps:
        1. Check that cache is not created
        2. Find user with id(name)
        3. Check that user has correct uid
        4. Find group with getent.group(name)
        5. Check that group has correct gid
        6. Stop SSSD
        7. Find user with id(name) and id(uid)
        8. Find group with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. Cache is not created
        2. User is found
        3. User has correct uid
        4. Group is found
        5. Group has correct gid
        6. Stop SSSD
        7. User is not found
        8. Group is not found
    :customerscenario: False
    """
    provider.user("user1").add(uid=123456, gid=19001)
    provider.group("group1").add(gid=10001)

    client.sssd.nss["memcache_timeout"] = "0"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    r = client.host.conn.exec(["ls", "/var/lib/sss/mc"])
    assert r.stdout == "", "Cache directory is not empty"
    assert r.stderr == "", "Ls command failed"

    result = client.tools.id("user1")
    assert result is not None, "User user1 was not found using user1"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"

    gresult = client.tools.getent.group("group1")
    assert gresult is not None, "Group group1 is not found using getent"
    assert gresult.gid == 10001, f"Group gid {gresult.gid} is incorrect, 10001 expected"

    client.sssd.stop()

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(10001) is None, "Group with gid 10001 was found which is not expected"


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__removed_cache_without_invalidation(client: Client, provider: GenericProvider):
    """
    :title: SSSD is stopped, cache removed then users and groups cannot be lookedup
    :setup:
        1. Add 'user1' to SSSD
        2. Set user uid and gid
        3. Add 'group1' to SSSD
        4. Set group gid
        5. Start SSSD
    :steps:
        1. Find user with id(name)
        2. Check that user has correct uid
        3. Find group with getent.group(name)
        4. Check that group has correct gid
        5. Stop SSSD
        6. Remove cache files
        7. Find user with id(name) and id(uid)
        8. Find group with getent.group(name) and getent.group(gid)
    :expectedresults:
        1. User is found
        2. User has correct uid
        3. Group is found
        4. Group has correct gid
        5. SSSD is stopped
        6. Cache files are removed
        7. User is not found
        8. Group is not found
    :customerscenario: True
    """
    provider.user("user1").add(uid=123456, gid=19001)
    provider.group("group1").add(gid=10001)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("user1")
    assert result is not None, "User user1 is not found using id"
    assert result.user.id == 123456, f"User id {result.user.id} is incorrect, 123456 expected"

    gresult = client.tools.getent.group("group1")
    assert gresult is not None, "Group group1 is not found using getent"
    assert gresult.gid == 10001, f"Group gid {gresult.gid} is incorrect, 10001 expected"

    client.sssd.stop()

    r = client.host.conn.exec(["ls", "/var/lib/sss/mc"])
    for file in r.stdout.split():
        check = client.host.conn.exec(["rm", f"/var/lib/sss/mc/{file}"])
        assert check.rc == 0, "Cache file was not removed successfully"

    assert client.tools.id("user1") is None, "User user1 was found which is not expected"
    assert client.tools.id(123456) is None, "User with id 123456 was found which is not expected"
    assert client.tools.getent.group("group1") is None, "Group group1 was found which is not expected"
    assert client.tools.getent.group(10001) is None, "Group with gid 10001 was found which is not expected"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.ticket(bz=2226021)
def test_memcache__truncate_in_memory_cache_no_sigbus(client: Client, ldap: LDAP):
    """
    :title: Accessing truncated in-memory cache file does not cause SIGBUS
    :setup:
        1. Add 'user-1' to SSSD
        2. Start SSSD
    :steps:
        1. Find 'user-1' so it is stored in in-memory cache
        2. Truncate /var/lib/sss/mc/passwd
        3. Check that 'user-1' can be correctly resolved
    :expectedresults:
        1. User is found
        2. Size of /var/lib/sss/mc/passwd is 0
        3. User can be found again and there is no crash
    :customerscenario: True
    """
    ldap.user("user-1").add()

    client.sssd.start()

    result = client.tools.id("user-1")
    assert result is not None, "User was not found"
    assert result.user.name == "user-1"

    client.fs.truncate("/var/lib/sss/mc/passwd")

    result = client.tools.id("user-1")
    assert result is not None, "User was not found"
    assert result.user.name == "user-1"

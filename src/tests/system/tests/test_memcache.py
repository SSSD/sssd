"""
SSSD In-Memory Cache (memcache) Test Cases.

:requirement: IDM-SSSD-REQ: Client side performance improvements
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericGroup, GenericProvider, GenericUser
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


# The following functions are created to help parametrize the memcache tests.
def add_objects(provider: GenericProvider) -> dict[str, list[GenericUser | GenericGroup]]:
    """
    Create objects.

    The word objects is used because it may add 'users' or 'groups'. It returns a dict of lists of objects,
    so they can be used to retrieve uidNumber and gidNumbers.

    :param provider: GenericProvider object.
    :type provider: GenericProvider
    :return: Dict of objects.
    :rtype: dict[str, list[GenericUser | GenericGroup]]
    """
    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()
    user3 = provider.user("user3").add()

    group1 = provider.group("group1").add().add_members([user1, user2, user3])
    group2 = provider.group("group2").add().add_members([user2, user3])
    group3 = provider.group("group3").add().add_members([user3])

    return {"users": [user1, user2, user3], "groups": [group1, group2, group3]}


def assert_objects(
    client: Client, objects: dict[str, list[GenericUser | GenericGroup]], cache: str, by_id: bool = False
) -> None:
    """
    Check the existence of objects, either users, groups, or initgroups.

    This is a helper function to parameterize the memcache test. The assertions for each
    cache type are different. Looking up 'users, will use 'id', groups will use 'getent group',
    and initgroups will use 'getent initgroups'.

    If 'id' bool is True, the lookup perform will by uid or gid.

    The assertion compares the command output against the 'GenericUser|GenericGroup|GenericInitGroups' objects
    created at setup. Constructing a new list from the objects to easily compare the results.

    :param client: Client object.
    :type client: Client
    :param objects: Dict of object lists.
    :type objects: dict[str, list[GenericUser | GenericGroup]]
    :param cache: Cache type, 'user', 'group' or 'initgroups'
    :type cache: str
    :param by_id: Lookup object by id, default is False
    :type by_id: bool
    """
    if cache == "users":
        for user in objects.get("users", []):
            if by_id:
                _result_user = user.get(["uidNumber"]).get("uidNumber")
                assert (
                    isinstance(_result_user, list) and len(_result_user) >= 1
                ), "uidNumber is not a list or is empty!"
                result_user = client.tools.id(_result_user[-1])
            else:
                result_user = client.tools.id(user.name)
            assert result_user is not None, f"User '{user.name}' was not found!"

    if cache == "groups":
        for group in objects.get("groups", []):
            if by_id:
                _result_group = group.get(["gidNumber"]).get("gidNumber")
                assert (
                    isinstance(_result_group, list) and len(_result_group) >= 1
                ), "gidNumber is not a list or is empty!"
                result_group = client.tools.getent.group(_result_group[-1])
            else:
                result_group = client.tools.getent.group(group.name)
            assert result_group is not None, f"Group {group.name} was not found!"

    if cache == "initgroups":
        for initgroup in objects.get("users", []):
            result_initgroup = client.tools.getent.initgroups(str(initgroup.name))
            assert result_initgroup is not None, f"User '{initgroup.name}' was not found in initgroups!"


def assert_objects_not_found(client: Client, objects: dict[str, list[GenericUser | GenericGroup]], cache: str) -> None:
    """
    Check for non-existence of objects.

    This helper function is used to parameterize the memcache test.
    The assertion for each cache type is different.

    :param client: Client object.
    :type client: Client
    :param objects: Dict of objects.
    :type objects: dict[str, list[GenericUser | GenericGroup]]
    :param cache: Cache type, 'user', 'group' or 'initgroups'
    :type cache: str
    """
    if cache == "users":
        for user in objects.get("users", []):
            result_user = client.tools.id(user.name)
            assert result_user is None, f"User '{user.name}' was found!"

    if cache == "groups":
        for group in objects.get("groups", []):
            result_group = client.tools.getent.group(group.name)
            assert result_group is None, f"Group {group.name} was found!"

    if cache == "initgroups":
        for initgroup in objects.get("users", []):
            _group = objects.get("groups", [])[-1].name
            result_initgroup = client.tools.getent.initgroups(initgroup.name)
            assert not result_initgroup.memberof(_group), f"User '{initgroup.name}' was found in initgroups!"


def assert_group_membership(
    client: Client, objects: dict[str, list[GenericUser | GenericGroup]], cache: str, by_id: bool = False
) -> None:
    """
    Checks group membership.

    Helper function to help parameterize the memcache test. The assertion for each cache type is different.
    All the users and groups are created during setup. 'user_map' is the expected group membership.

    Each cache type the user membership is checked differently. For 'users' cache, it will use 'id' and check the
    memberof attribute. For 'groups' cache, it will use 'getent group' and check the members attribute. For
    'initgroups' cache, it will use 'getent initgroups' and check the memberof attribute with group ids. Importantly,
    for 'initgroups' the results are ids; using the user_map, a lookup is performed to get the correct GIDs.

    :param client: Client object.
    :type client: Client
    :param objects: Dict of objects.
    :type objects: dict[str, list[GenericUser | GenericGroup]]
    :param cache: Cache type, 'user', 'group' or 'initgroups'
    :type cache: str
    :param by_id: Lookup object by id, default is False
    :type by_id: bool
    """
    user_map = {"user1": ["group1"], "user2": ["group1", "group2"], "user3": ["group1", "group2", "group3"]}

    if cache == "users":
        for user in objects.get("users", []):
            expected_groups = user_map.get(user.name, [])
            if by_id:
                _result_user = user.get(["uidNumber"]).get("uidNumber")
                assert (
                    isinstance(_result_user, list) and len(_result_user) >= 1
                ), "uidNumber is not a list or is empty!"
                result_user = client.tools.id(str(_result_user[-1]))
            else:
                result_user = client.tools.id(user.name)

            assert result_user is not None, f"User '{user.name}' was not found!"
            expected_names = set(expected_groups)
            actual_names = {g.name for g in result_user.groups if g.name is not None}
            assert actual_names == expected_names, (
                f"User '{user.name}' group names from id {sorted(actual_names)!r} "
                f"!= expected {sorted(expected_names)!r}"
            )

    if cache == "groups":
        for group in objects.get("groups", []):
            expected_members = [user for user, groups in user_map.items() if group.name in groups]
            if by_id:
                _result_group = group.get(["gidNumber"]).get("gidNumber")
                assert (
                    isinstance(_result_group, list) and len(_result_group) >= 1
                ), "gidNumber is not a list or is empty!"
                result_group = client.tools.getent.group(str(_result_group[-1]))
            else:
                result_group = client.tools.getent.group(group.name)

            assert result_group is not None, f"Group {group.name} was not found!"
            assert result_group.members == expected_members, f"Group '{group.name}' has incorrect members!"

    if cache == "initgroups":
        for user in objects.get("users", []):
            expected_groups = user_map.get(user.name, [])
            expected_ids = []

            for ids in expected_groups:
                for group in objects.get("groups", []):
                    if group.name == ids:
                        _result_gid = group.get(["gidNumber"]).get("gidNumber")
                        assert (
                            isinstance(_result_gid, list) and len(_result_gid) > 0
                        ), "gidNumber list should not be empty!"
                        expected_ids.append(int(_result_gid[-1]))
            result_initgroup = client.tools.getent.initgroups(user.name)

            assert result_initgroup is not None, f"User '{user.name}' was not found in initgroups!"
            assert set(result_initgroup.groups) == set(expected_ids), f"User '{user.name}' groups are wrong!"


def invalidate_cache_stop_sssd(client: Client, order: str, cache: str) -> None:
    """
    Helpful function to parameterize when the cache is invalidated,
    which is either before or after stopping SSSD.

    :param client: Client object.
    :type client: Client
    :param order: Before or after SSSD stopping.
    :type order: str
    :param cache: Cache type, 'user', 'group', leave blank for all.
    :type cache: str
    """
    if order == "before":
        if cache == "users":
            client.sssctl.cache_expire(users=True)
        elif cache == "groups" or cache == "initgroups":
            client.sssctl.cache_expire(users=False, groups=True)
        else:
            client.sssctl.cache_expire(everything=True)
        client.sssd.stop()

    if order == "after":
        client.sssd.stop()
        if cache == "users":
            client.sssctl.cache_expire(users=True, groups=False)
        elif cache == "groups" or cache == "initgroups":
            client.sssctl.cache_expire(users=False, groups=True)
        else:
            client.sssctl.cache_expire(everything=True)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    [
        "users",
        "groups",
        "initgroups",
    ],
)
def test_memcache__lookup_objects_by_name(client: Client, provider: GenericProvider, cache: str):
    """
    :title: Lookup objects, by name and remains in memcache after SSSD is stopped.
      Objects will either be users, groups or initgroups.
    :setup:
      1. Create objects to be cached
      2. Start SSSD
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Look up objects
      2. Check group membership
    :expectedresults:
      1. Objects are found
      2. Group membership is correct
    :customerscenario: False
    """
    objects = add_objects(provider)
    client.sssd.start()
    assert_objects(client, objects, cache)
    client.sssd.stop()

    assert_objects(client, objects, cache)
    assert_group_membership(client, objects, cache)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    [
        "users",
        "groups",
        "initgroups",
    ],
)
def test_memcache__lookup_objects_by_id(client: Client, provider: GenericProvider, cache: str):
    """
    :title: Lookup objects, by id and remains in memcache after SSSD is stopped.
    :setup:
      1. Create objects to be cached
      2. Start SSSD
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Look up objects by uid or gid
      2. Check group membership
    :expectedresults:
      1. Objects are found
      2. Group membership is correct
    :customerscenario: False
    """
    objects = add_objects(provider)
    client.sssd.start()
    assert_objects(client, objects, cache, by_id=True)
    client.sssd.stop()

    assert_objects(client, objects, cache, by_id=True)
    assert_group_membership(client, objects, cache, by_id=True)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_by_fully_qualified_name(client: Client, provider: GenericProvider):
    """
    :title: Lookup users by fully qualified names after SSSD is stopped.
    :setup:
      1. Create users to be cached
      2. Configure and start SSSD
      3. Cache users by looking them up
      4. Stop SSSD
    :steps:
      1. Look up users by fully qualified names
    :expectedresults:
      1. Users are found
    :customerscenario: False
    """
    objects = add_objects(provider)
    users = objects.get("users", [])
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()
    for user in users:
        result_id = client.tools.id(f"{user.name}@{client.sssd.default_domain}")
        assert result_id is not None, f"User '{user.name}@{client.sssd.default_domain}' was not found!"
    client.sssd.stop()

    for user in users:
        result_id = client.tools.id(f"{user.name}@{client.sssd.default_domain}")
        assert result_id is not None, f"User '{user.name}@{client.sssd.default_domain}' was not found!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_users_by_name_with_case_sensitive_true(client: Client, provider: GenericProvider):
    """
    :title: Lookup users by name with case sensitivity set to true after SSSD is stopped.
    :setup:
      1. Create users to be cached
      2. Configure and start SSSD
      3. Cache users by looking them up
      4. Stop SSSD
    :steps:
      1. Look up users in uppercase
    :expectedresults:
      1. Users are found
    :customerscenario: False
    """
    objects = add_objects(provider)
    users = objects.get("users", [])
    client.sssd.domain["case_sensitive"] = "True"
    client.sssd.start()
    for user in users:
        result_id = client.tools.id(user.name)
        assert result_id is not None, f"User '{user.name}' was not found!"
    client.sssd.stop()

    for user in users:
        result_id = client.tools.id(user.name.upper())
        assert result_id is None, f"User '{user.name.upper()}' not found!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    ["users", "groups", "initgroups"],
)
def test_memcache__lookup_objects_with_the_same_cache_type_disabled(
    client: Client, provider: GenericProvider, cache: str
):
    """
    :title: Lookup objects, by name with the same cache type disabled.
    :setup:
      1. Create objects to be cached
      2. Start SSSD with the memcache disabled for the specific type
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Look up objects
    :expectedresults:
      1. Objects are not found
    :customerscenario: False
    """
    objects = add_objects(provider)
    if cache == "users":
        client.sssd.nss["memcache_size_passwd"] = "0"
    elif cache == "groups":
        client.sssd.nss["memcache_size_group"] = "0"
    else:
        client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.start()
    assert_objects(client, objects, cache)
    client.sssd.stop()

    assert_objects_not_found(client, objects, cache)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    ["users", "groups", "initgroups"],
)
def test_memcache__lookup_objects_with_all_cache_types_disabled(client: Client, provider: GenericProvider, cache: str):
    """
    :title: Lookup objects, by name with all cache types disabled.
    :setup:
      1. Create objects to be cached
      2. Start SSSD with the memcache disabled
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Look up objects
    :expectedresults:
      1. Objects are not found
    :customerscenario: False
    """
    objects = add_objects(provider)
    client.sssd.nss["memcache_size_passwd"] = "0"
    client.sssd.nss["memcache_size_group"] = "0"
    client.sssd.nss["memcache_size_initgroups"] = "0"
    client.sssd.start()
    assert_objects(client, objects, cache)
    client.sssd.stop()

    assert_objects_not_found(client, objects, cache)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    ["users", "groups", "initgroups"],
)
def test_memcache__lookup_objects_with_all_other_cache_types_disabled(
    client: Client, provider: GenericProvider, cache: str
):
    """
    :title: Lookup objects, by name with other cache types disabled.
    :setup:
      1. Create objects to be cached
      2. Start SSSD with the memcache disabled for other object types
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Look up objects
    :expectedresults:
      1. Objects are found
    :customerscenario: False
    """
    objects = add_objects(provider)
    if cache == "users":
        client.sssd.nss["memcache_size_group"] = "0"
        client.sssd.nss["memcache_size_initgroups"] = "0"
    elif cache == "groups":
        client.sssd.nss["memcache_size_passwd"] = "0"
        client.sssd.nss["memcache_size_initgroups"] = "0"
    else:
        client.sssd.nss["memcache_size_passwd"] = "0"
        client.sssd.nss["memcache_size_group"] = "0"
    client.sssd.start()
    assert_objects(client, objects, cache)
    client.sssd.stop()

    assert_objects(client, objects, cache)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_memcache__lookup_objects_with_memcache_disabled(client: Client, provider: GenericProvider):
    """
    :title: Lookup objects, with memcache disabled entirely, memcache_timeout=0
    :setup:
      1. Create objects to be cached
      2. Start SSSD with the memcache disabled
      3. Cache objects by looking them up
      4. Stop SSSD
    :steps:
      1. Check memcache cache folder
      2. Look up objects
    :expectedresults:
      1. No files are created
      2. Objects are not found
    :customerscenario: False
    """
    objects = add_objects(provider)
    client.sssd.nss["memcache_timeout"] = "0"
    client.sssd.start()
    assert_objects(client, objects, "users")
    assert_objects(client, objects, "groups")
    assert_objects(client, objects, "initgroups")
    client.sssd.stop()

    file_list = client.host.conn.run("ls /var/lib/sss/mc/").stdout_lines
    assert len(file_list) == 0, "Cache files should not be present when memcache is disabled!"

    assert_objects_not_found(client, objects, "users")
    assert_objects_not_found(client, objects, "groups")
    assert_objects_not_found(client, objects, "initgroups")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "cache",
    ["users", "groups", "initgroups"],
)
@pytest.mark.parametrize(
    "order",
    ["before", "after"],
    ids=["before stopping sssd", "after stopping sssd"],
)
def test_memcache__invalidating_caches_before_or_after_stopping_sssd(
    client: Client, provider: GenericProvider, cache: str, order: str
):
    """
    :title: Lookup objects and changing when the cache is invalidated, before or after stopping sssd
    :setup:
      1. Create objects to be cached
      2. Start SSSD
      3. Cache objects by looking them up
      4. Invalidate the cache objects
    :steps:
      1. Look up objects
    :expectedresults:
      1. Objects are not found
    :customerscenario: False
    """
    objects = add_objects(provider)
    client.sssd.start()
    assert_objects(client, objects, cache)
    invalidate_cache_stop_sssd(client, order, cache)

    assert_objects_not_found(client, objects, cache)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.ticket(bz=2226021)
def test_memcache__truncate_in_memory_cache_no_sigbus(client: Client, provider: GenericProvider):
    """
    :title: Accessing truncated in-memory cache file does not cause SIGBUS
    :setup:
        1. Add objects to be cached
        2. Start SSSD
        3. Cache users by looking them up
        4. Truncate /var/lib/sss/mc/passwd
    :steps:
        1. Lookup users
    :expectedresults:
        1. Users are found
    :customerscenario: True
    """
    objects = add_objects(provider)
    client.sssd.start()
    assert_objects(client, objects, "users")
    client.fs.truncate("/var/lib/sss/mc/passwd")

    assert_objects(client, objects, "users")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.ticket(gh=4595)
def test_memcache__handles_colliding_hashes(client: Client, provider: GenericProvider):
    """
    :title: Lookup objects with colliding hashes are handled correctly
        The string for the colliding hash needs to be longer than the other
        object data stored in mcache. Like 'getent passwd user1 | wc -c' => 45
        Note, pysss_murmur is used to generate the hash.
    :setup:
        1. Upload script to generate colliding hash
        2. Create the first user, cache the user by looking up the user
        3. Run the script to get the hash
        4. Create the second user using the hash as the username
        5. Cache users by looking them up and after stop sssd
    :steps:
        1. Lookup users
    :expectedresults:
        1. Users are found
    :customerscenario: True
    """
    script = client.fs.mktmp("""
#!/usr/bin/env python3
import random
import string
import struct
import pysss_murmur

class MemoryCache:
    SIZE_OF_UINT32_T = 4

    def __init__(self) -> None:
        self.user = "user1"
        self.cache_path = "/var/lib/sss/mc/passwd"
        with open(self.cache_path, "rb") as f:
            f.seek(16)
            self.seed = struct.unpack("i", f.read(4))[0]
            f.read(8)
            hash_length = struct.unpack("i", f.read(4))[0]
            self.hash_size = hash_length // 4

    def generate_colliding_username(self, min_length=80):
        target = pysss_murmur.murmurhash3(self.user + "\\0", len(self.user) + 1, self.seed) % self.hash_size
        while True:
            candidate = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(min_length))
            h = pysss_murmur.murmurhash3(candidate + "\\0", len(candidate) + 1, self.seed) % self.hash_size
            if h == target:
                return candidate

if __name__ == "__main__":
    mc = MemoryCache()
    colliding = mc.generate_colliding_username(80)
    print(colliding)
""")

    normal_user = "user1"
    provider.user("user1").add()
    client.sssd.start()
    client.tools.id(normal_user)

    colliding_user = client.host.conn.run(f"python {script}").stdout.strip()
    provider.user(colliding_user).add()

    for user in [normal_user, colliding_user]:
        result_user = client.tools.id(user)
        assert result_user is not None, f"User '{user}' was not found!"
    client.sssd.stop()

    for user in [normal_user, colliding_user]:
        result_user = client.tools.id(user)
        assert result_user is not None, f"User '{user}' was not found!"

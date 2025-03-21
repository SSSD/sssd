import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize(
    "lookup_type",
    [
        ("users"),
        ("groups"),
        ("all"),
    ],
)
@pytest.mark.parametrize(
    "memcache",
    [
        True,
        False,
    ],
)
def test_memcache__user_group_initigroup_cache_alternately_disabled(
    client: Client, provider: GenericProvider, lookup_type: str, memcache: str
):
    """
    :title: Validate memory cache behavior for users and groups with different cache settings
    :setup:
        1. Create test users `user1`, `user2`, `user3`.
        2. Create test groups `group1`, `group2`, `group3`.
        3. Configure SSSD to disable `{cache_setting}`.
        4. Start SSSD.
    :steps:
        1. Perform lookup operation for all users or groups while SSSD is running.
        2. Verify that the expected users or groups are found.
        3. Stop SSSD.
        4. Attempt to perform the lookup operation again.
        5. Verify that users or groups are NOT found after stopping SSSD.
    :expectedresults:
        1. Lookups should succeed when SSSD is running.
        2. The expected users or groups should be retrieved correctly.
        3. SSSD stops successfully.
        4. Lookups should fail after stopping SSSD.
        5. Users or groups should NOT be found after stopping SSSD.
    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    groups = ["group1", "group2", "group3"]
    cache_setting = {
        "users": ["memcache_size_passwd"],
        "groups": ["memcache_size_group"],
        "all": ["memcache_size_passwd", "memcache_size_group", "memcache_size_initgroups"],
    }

    for user in users:
        provider.user(user).add()

    for group in groups:
        provider.group(group).add()

    if memcache is False:
        for cache in cache_setting[lookup_type]:
            client.sssd.nss[cache] = "0"

    def checkBeforeStop():
        for user in users:
            assert client.tools.getent.passwd(user) is not None, f"{user} should be found."
        for group in groups:
            assert client.tools.getent.group(group) is not None, f"{group} should be found."

    def checkAfterStop():
        if memcache is True:
            for user in users:
                assert client.tools.getent.passwd(user) is not None, f"{user} should be found."
            for group in groups:
                assert client.tools.getent.group(group) is not None, f"{group} should be found."
        else:
            for user in users:
                if lookup_type in ("users", "all"):
                    assert client.tools.getent.passwd(user) is None, f"{user} should NOT be found."
                else:
                    assert client.tools.getent.passwd(user) is not None, f"{user} should be found."
            for group in groups:
                if lookup_type in ("groups", "all"):
                    assert client.tools.getent.group(group) is None, f"{group} should NOT be found."
                else:
                    assert client.tools.getent.group(group) is not None, f"{group} should be found."

    client.sssd.start()
    checkBeforeStop()

    client.sssd.stop()
    checkAfterStop()


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize(
    "lookup_type",
    [
        ("users"),
        ("groups"),
        ("all"),
    ],
)
@pytest.mark.parametrize(
    "invalidate_cache",
    [
        ("before"),
        ("after"),
    ],
)
def test_memcache__user_group_before_and_after_cache_disabled(
    client: Client, provider: GenericProvider, lookup_type: str, invalidate_cache: str
):
    """
    :title: Validate memory cache behavior for users and groups with different cache settings
    :setup:
        1. Create test users `user1`, `user2`, `user3`.
        2. Create test groups `group1`, `group2`, `group3`.
        3. Configure SSSD to disable `{cache_setting}`.
        4. Start SSSD.
    :steps:
        1. Perform lookup operation for all users or groups while SSSD is running.
        2. Verify that the expected users or groups are found.
        3. Stop SSSD.
        4. Attempt to perform the lookup operation again.
        5. Verify that users or groups are NOT found after stopping SSSD.
    :expectedresults:
        1. Lookups should succeed when SSSD is running.
        2. The expected users or groups should be retrieved correctly.
        3. SSSD stops successfully.
        4. Lookups should fail after stopping SSSD.
        5. Users or groups should NOT be found after stopping SSSD.
    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    groups = ["group1", "group2", "group3"]

    for user in users:
        provider.user(user).add()

    for group in groups:
        provider.group(group).add()

    def check(afterStart=True):
        if afterStart is True:
            for user in users:
                assert client.tools.getent.passwd(user) is not None, f"{user} should be found."
            for group in groups:
                assert client.tools.getent.group(group) is not None, f"{group} should be found."
        else:
            for user in users:
                assert client.tools.getent.passwd(user) is None, f"{user} should NOT be found."
            for group in groups:
                assert client.tools.getent.group(group) is None, f"{group} should NOT be found."

    def invalidate_cache_entries():
        if lookup_type in ("users", "all"):
            client.sssctl.cache_expire(users=True)
        if lookup_type in ("groups", "all"):
            client.sssctl.cache_expire(groups=True)

    client.sssd.start()
    check(True)

    if invalidate_cache == "before":
        invalidate_cache_entries()

    client.sssd.stop()

    if invalidate_cache == "after":
        invalidate_cache_entries()
    check(False)

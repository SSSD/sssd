"""
SSSD Cache Tests.

Tests pertaining SSSD caches, the following types are tested and some will be in other python files.

* Local cache (LDB)
* Negative cache (ncache)
* In-memory cache (memcache): test_memcache.py

:requirement: Cache
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_cache__is_refreshed_as_configured(client: Client, provider: GenericProvider):
    """
    :title: Ensuring LDB cache refreshes at configured intervals
    :setup:
        1. Create user
        2. Create group
        3. Create netgroup
        4. Configure SSSD and set 'entry_cache_timeout to 1' and 'refresh_expired_interval to 2'
        5. Restart SSSD
        6. Lookup user, group and netgroup
    :steps:
        1. Search for objects lastUpdate and dataExpireTimestamp in ldb database
        2. Wait 5 seconds and repeat search
    :expectedresults:
        1. The 'dataExpireTimestamp' value equals the 'lastUpdate + entry_cache_timeout' value
        2. Objects 'lastUpdate' timestamp value has been refreshed
    :customerscenario: False
    """
    user = provider.user("test_user").add()
    provider.group("test_group").add().add_member(user)
    provider.netgroup("test_netgroup").add().add_member(user=user)

    domain = client.sssd.default_domain
    entry_cache_timeout = 1
    refresh_expired_interval = 2

    client.sssd.domain["entry_cache_timeout"] = str(entry_cache_timeout)
    client.sssd.domain["refresh_expired_interval"] = str(refresh_expired_interval)

    client.sssd.restart()
    client.tools.getent.passwd(f"test_user@{domain}")
    client.tools.getent.group(f"test_group@{domain}")
    client.tools.getent.netgroup(f"test_netgroup@{domain}")

    ldb_cache = f"/var/lib/sss/db/cache_{domain}.ldb"
    ldb_suffix = f"cn={domain},cn=sysdb"

    last_update: list[int] = []
    expire_time: list[int] = []

    for i in [f"test_user@{domain}", f"test_group@{domain}", "test_netgroup"]:
        result = client.ldb.search(ldb_cache, ldb_suffix, filter=f"name={i}")
        for k, v in result.items():
            for y in v.items():
                if y[0] == "lastUpdate":
                    last_update = last_update + [(int(y[1][0]))]
                if y[0] == "dataExpireTimestamp":
                    expire_time = expire_time + [(int(y[1][0]))]

    for m, n in enumerate(last_update):
        assert (
            last_update[m] + entry_cache_timeout == expire_time[m]
        ), f"{expire_time[m]} != {last_update[m]} + {entry_cache_timeout}"

    time.sleep(5)

    for s, t in enumerate([f"test_user@{domain}", f"test_group@{domain}", "test_netgroup"]):
        result = client.ldb.search(ldb_cache, ldb_suffix, filter=f"name={t}")
        for k, v in result.items():
            for y in v.items():
                if y[0] == "lastUpdate":
                    assert last_update[s] <= (int(y[1][0])), f"{s} lastUpdate value is greater than expected!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_cache__search_for_user_in_ldb_databases(client: Client, provider: GenericProvider):
    """
    :title: Search for user in the following ldb databases, cache_*.ldb and timestamp_*.ldb
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Lookup user
        2. Check cache
        3. Lookup user in cache ldb database
        4. Lookup user in timestamp ldb database
    :expectedresults:
        1. User is found
        2. Cache file exists
        3. User found
        4. User found
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.start()
    client.tools.getent.passwd("user1")
    cache = "/var/lib/sss/db/cache_test.ldb"
    timestamps = "/var/lib/sss/db/timestamps_test.ldb"
    assert client.fs.exists(timestamps), f"Timestamp file '{timestamps}' does not exist"

    ldb1 = client.ldb.search(cache, "name=user1@test,cn=users,cn=test,cn=sysdb")
    ldb2 = client.ldb.search(timestamps, "name=user1@test,cn=users,cn=test,cn=sysdb")
    assert ldb1 != {}, f"ldbsearch failed to find user1 in {cache}"
    assert ldb2 != {}, f"ldbsearch failed to find user1 in {timestamps}"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_cache__search_for_user_using_fully_qualified_name_in_ldb_databases(client: Client, provider: GenericProvider):
    """
    :title: Search for user using fully qualified name in the following ldb databases, cache_*.ldb and timestamp_*.ldb
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup user in cache ldb database
        3. Lookup user in timestamp ldb database
    :expectedresults:
        1. User found
        2. User found
        3. User found
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()
    client.tools.getent.passwd("user1@test")

    cache = "/var/lib/sss/db/cache_test.ldb"
    timestamps = "/var/lib/sss/db/timestamps_test.ldb"
    user_basedn = "name=user1@test,cn=users,cn=test,cn=sysdb"
    ldb1 = client.ldb.search(cache, user_basedn)
    ldb2 = client.ldb.search(timestamps, user_basedn)

    assert ldb1 != {}, f"ldbsearch failed to find user1@test in {cache}"
    assert ldb2 != {}, f"ldbsearch failed to find user1@test in {timestamps}"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_cache__check_ldb_database_for_latest_user_changes_when_modified_and_deleted(
    client: Client, provider: GenericProvider
):
    """
    :title: Check ldb database for latest user changes when modified and deleted
    :setup:
        1. Add users 'user-modify' and 'user-delete'
        2. Start SSSD
        3. Lookup users
    :steps:
        1. Login as users
        2. Modify 'user-modify' shell and delete 'user-delete' and clear cache
        3. Login as users
        4. Lookup user 'user-delete'
        5. Lookup user 'user-modify'
    :expectedresults:
        1. Users logged in
        2. User 'user-modify' is modified and user 'user-delete' is deleted
        3. User 'user-modify' logged in
        4. User 'user-delete' is not found
        5. User 'user-modify' is found and shell was updated
    :customerscenario: False
    """
    provider.user("user-modify").add(shell="/bin/bash")
    provider.user("user-delete").add(shell="/bin/bash")
    client.sssd.start()
    client.tools.getent.passwd("user-modify")
    client.tools.getent.passwd("user-delete")

    assert client.auth.ssh.password("user-modify", "Secret123"), "Login failed!"
    assert client.auth.ssh.password("user-delete", "Secret123"), "Login failed!"

    provider.user("user-delete").delete()
    provider.user("user-modify").modify(shell="/bin/sh")

    client.sssctl.cache_expire(everything=True)

    assert client.auth.ssh.password("user-modify", "Secret123"), "Login failed!"
    assert not client.auth.ssh.password("user-delete", "Secret123"), "Login successful!"

    result = client.tools.getent.passwd("user-modify")
    assert result is not None, "User not found!"
    assert result.shell == "/bin/sh", "User shell did not update!"

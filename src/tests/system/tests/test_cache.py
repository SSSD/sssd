"""
SSSD Cache Tests.

Tests pertaining SSSD caches, the following types are tested and some will be in other python files.

* Local cache (LDB)
* Negative cache (ncache)
* In-memory cache (memcache): test_memcache.py

Note: There is not added benefit to test against all topologies, the cache tests are tested against LDAP.

:requirement: Cache
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__entries_are_refreshed_as_configured(client: Client, provider: LDAP):
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
                    last_update = last_update + [int(y[1][0])]
                if y[0] == "dataExpireTimestamp":
                    expire_time = expire_time + [int(y[1][0])]

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


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__writes_to_both_database_files(client: Client, provider: LDAP):
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

    ldb1 = client.ldb.search(cache, f"name=user1@{client.sssd.default_domain},cn=users,cn=test,cn=sysdb")
    ldb2 = client.ldb.search(timestamps, f"name=user1@{client.sssd.default_domain},cn=users,cn=test,cn=sysdb")

    assert ldb1, f"ldbsearch failed to find user1 in {cache}!"
    assert ldb2, f"ldbsearch failed to find user1 in {timestamps}!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__writes_to_both_database_files_when_using_fully_qualified_names(client: Client, provider: LDAP):
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
    client.tools.getent.passwd(f"user1@{client.sssd.default_domain}")

    cache = "/var/lib/sss/db/cache_test.ldb"
    timestamps = "/var/lib/sss/db/timestamps_test.ldb"
    user_dn = f"name=user1@{client.sssd.default_domain},cn=users,cn=test,cn=sysdb"
    ldb1 = client.ldb.search(cache, user_dn)
    ldb2 = client.ldb.search(timestamps, user_dn)

    assert ldb1, f"ldbsearch failed to find user1 in {cache}!"
    assert ldb2, f"ldbsearch failed to find user1 in {timestamps}!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__user_entries_contains_latest_changes_when_modified_and_deleted(client: Client, provider: LDAP):
    """
    :title: Checks user changes are reflected when modified and deleted
    :setup:
        1. Add users 'user1' and 'user2'
        2. Start SSSD
        3. Lookup users
    :steps:
        1. Login as users
        2. Modify 'user1' shell and delete 'user2' and clear cache
        3. Login as users
        4. Lookup user 'user2'
        5. Lookup user 'user1'
    :expectedresults:
        1. Users logged in
        2. User 'user1' is modified and user 'user2' is deleted
        3. User 'user1' logged in
        4. User 'user2' is not found
        5. User 'user1' is found and shell was updated
    :customerscenario: False
    """
    provider.user("user1").add(shell="/bin/bash")
    provider.user("user2").add(shell="/bin/bash")
    client.sssd.start()
    client.tools.getent.passwd("user1")
    client.tools.getent.passwd("user2")

    assert client.auth.ssh.password("user1", "Secret123"), "Login failed!"
    assert client.auth.ssh.password("user2", "Secret123"), "Login failed!"

    provider.user("user2").delete()
    provider.user("user1").modify(shell="/bin/sh")

    client.sssctl.cache_expire(everything=True)

    assert client.auth.ssh.password("user1", "Secret123"), "Login failed!"
    assert not client.auth.ssh.password("user2", "Secret123"), "Login successful!"

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"
    assert result.shell == "/bin/sh", "User shell did not update!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__group_entries_contains_latest_changes_when_modified_and_deleted(
    client: Client,
    provider: LDAP,
):
    """
    :title: Check latest group changes are reflected when modified and deleted
    :setup:
        1. Create groups 'group1' and group2'
        2. Start SSSD
        3. Lookup groups
    :steps:
        1. Create and add 'user1' to 'group1' and delete 'group2' and clear cache
        2. Lookup group 'group1'
        3. Lookup group 'group2'
    :expectedresults:
        1. User 'user1' is created and added to group 'group1'  and group 'group2' is deleted
        2. Group 'group1' is found and contains 'user1'
        3. Group 'group2' is not found
    :customerscenario: False
    """
    group1 = provider.group("group1").add()
    group2 = provider.group("group2").add()
    client.sssd.start()

    assert client.tools.getent.group("group1"), "Group group1 not found!"
    assert client.tools.getent.group("group2"), "Group group2 not found!"

    group1.add_member(provider.user("user1").add())
    group2.delete()

    client.sssctl.cache_expire(everything=True)

    assert client.tools.getent.group("group1"), "Group group1 not found!"
    assert "user1" in str(client.tools.getent.group("group1")), "Group group1 is missing a user!"
    assert not client.tools.getent.group("group2"), "Group group2 found!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.parametrize("obj", ["user", "group"])
@pytest.mark.parametrize("dbs", ["cache", "timestamps"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__invalidate_entries_in_domain_and_timestamps_caches(
    client: Client,
    provider: LDAP,
    obj: str,
    dbs: str,
):
    """
    :title: Invalidates object entries in the domain and timestamps caches using dataExpireTimestamp attribute
    :setup:
        1. Create user and group
        2. Add user as a member to group
        3. Start SSSD and lookup user, group
    :steps:
        1. Search for object attribute dataExpireTimestamp in domain and timestamps ldb caches
        2. Clear the SSSD cache for the object
        3. Search for the object attribute dataExpireTimestamp in domain and timestamps ldb caches
    :expectedresults:
        1. Attribute is found
        2. Cache is cleared for the object
        3. Attribute is found and the value is '[1]' meaning it is cleared
    :customerscenario: False
    """
    # Unable to parametrize provider method when adding objects, so all object types are created
    user = provider.user("user").add()
    provider.group("group").add().add_member(user)
    client.sssd.start()

    assert client.tools.getent.passwd("user")
    assert client.tools.getent.group("group")

    path = f"/var/lib/sss/db/{dbs}_{client.sssd.default_domain}.ldb"
    suffix = f"cn={obj}s,cn={client.sssd.default_domain},cn=sysdb"
    ldb_filter = f"dn=name={obj}@{client.sssd.default_domain},{suffix}"

    result = client.ldb.search(path, suffix, filter=ldb_filter)
    assert result != {}, f"ldbsearch {ldb_filter} did not return any results!"
    for _, v in result.items():
        result_expire_time = v.get("dataExpireTimestamp")
        assert result_expire_time is not None
        expire_time = int(result_expire_time.pop())
        assert expire_time > 1, f"Expire time for {dbs} does not have a valid value!"

    client.host.conn.exec(["sss_cache", f"-{obj[0]}", obj])

    result = client.ldb.search(path, suffix, filter=ldb_filter)
    assert result != {}, f"ldbsearch {ldb_filter} did not find any results in {path}"
    for _, v in result.items():
        result_expire_time = v.get("dataExpireTimestamp")
        assert result_expire_time is not None
        expire_time = int(result_expire_time.pop())
        assert expire_time == 1, f"Expire time for {dbs} has not been cleared!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__extra_attributes_are_stored(client: Client, provider: LDAP):
    """
    :title: Extra attributes are cached
    :setup:
        1. Create user "user1"
        2. Edit SSSD configuration and set "ldap_user_extra_attrs =
            description:gecos, userID:uidNumber, shell:loginShell, groupID:gidNumber" and
            "ldap_id_mapping = false"
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup user in cache
    :expectedresults:
        1. User is found
        2. User is found and cache contains correct attributes and values
    :customerscenario: True
    """
    provider.user("user1").add(gid=111111, uid=100110, gecos="gecos user1", shell="/bin/sh", home="/home/user1")
    client.sssd.domain["ldap_user_extra_attrs"] = (
        "description:gecos, userID:uidNumber, shell:loginShell, groupID:gidNumber"
    )
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )

    user_dict = search["name=user1@test,cn=users,cn=test,cn=sysdb"]
    assert user_dict["description"] == ["gecos user1"], "attribute 'description' was not correct"
    assert user_dict["shell"] == ["/bin/sh"], "attribute 'shell' was not correct"
    assert user_dict["userID"] == ["100110"], "attribute 'userID' was not correct"
    assert user_dict["groupID"] == ["111111"], "attribute 'groupID' was not correct"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__extra_attributes_with_empty_values_are_ignored(client: Client, provider: LDAP):
    """
    :title: When extra attribute of user is added but not assigned, it is neither cached nor displayed
    :setup:
        1. Create user "user1"
        2. Configure SSSD with "ldap_user_extra_attr = number:telephonenumber"
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup user in cache
    :expectedresults:
        1. User is found
        2. User is found and does not have the extra numbers attribute
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.domain["ldap_user_extra_attrs"] = "number:telephonenumber"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User is not found!"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )
    assert search != {}, "User not found!"

    search = client.ldb.search(f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", "number=*")
    assert search == {}


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_cache__both_ldap_user_email_and_extra_attribute_email_are_stored(client: Client, ldap: LDAP):
    """
    :title: Setting ldap_user_email and email using extra attributes are cached
    :setup:
        1. Create user "user1" with gecos and mail attributes`
        2. Configure SSSD with "ldap_user_extra_attrs = email:mail, description:gecos" and
            "ldap_user_email = mail"
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Lookup user in cache
    :expectedresults:
        1. User is found
        2. User is found with description, mail and email attributes
    :customerscenario: False
    """
    ldap.user("user1").add(gecos="gecos1", mail="user1@example.test")

    client.sssd.domain["ldap_user_email"] = "mail"
    client.sssd.domain["ldap_user_extra_attrs"] = "email:mail, description:gecos"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User is not found"
    assert result.name == "user1", "User has wrong name"

    search = client.ldb.search(
        f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb", f"cn=users,cn={client.sssd.default_domain},cn=sysdb"
    )

    user_dict = search["name=user1@test,cn=users,cn=test,cn=sysdb"]
    assert user_dict["description"] == ["gecos1"], "attribute 'description' was not correct"
    assert user_dict["mail"] == ["user1@example.test"], "attribute 'mail' was not correct"
    assert user_dict["email"] == ["user1@example.test"], "attribute 'email' was not correct"

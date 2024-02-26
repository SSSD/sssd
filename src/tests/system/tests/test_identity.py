"""
SSSD Client identity Lookups

:requirement: IDM-SSSD-REQ: Client side performance improvements
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider, GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_identity__lookup_with_id(client: Client, provider: GenericProvider, sssd_service_user: str):
    """
    :title: Resolve user by name and uid, group membershif by username and group with id
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids and gids
        3. Add 'group1' to SSSD
        5. Add members to group
        3. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users have correct names and ids
        3. Check that users are members of correct group using memberof(group)
        4. Check that users are members of correct groups using memberof(gid)
        5. Find 'user1', 'user2' and 'user3' with id(uid)
        4. Check that users have correct names and ids

    :expectedresults:
        1. Users are found with id(name)
        2. Users are found with id(uid)
        3. Users have correct names
        4. Users have correct ids
    :customerscenario: False
    """
    users = [("user1", 10001, 1001, "group1"), ("user2", 10002, 1001, "group1"), ("user3", 10003, 1001, "group1")]
    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    provider.group("group1").add(gid=1001).add_members([u1, u2, u3])

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid, gid, group in users:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected"
        assert result.memberof(gid), f"User {name} is member of wrong groups"
        assert result.memberof(group), f"User {name} is member of wrong groups"

    for name, uid, gid, group in users:
        result = client.tools.id(uid)
        assert result is not None, f"User with uid {uid} was not found using id"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected"    


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Resolve group name, gid and user with getent
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Add 'group1', 'group2' and 'group3' to SSSD
        3. Set groups gids
        4. Add members to groups
        5. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Check that groups have correct names
        3. Check that groups have correct gids
        4. Find 'group1', 'group2' and 'group3' with getent.group(gid)
        5. Check that groups have correct names
        6. Check that groups have correct gids
        7. Find 'user1', 'user2' and 'user3' with getent.passwd(name)
        8. Check that users have correct names
        9. Check that users have correct ids
        10. Find 'user1', 'user2' and 'user3' with getent.passwd(uid)
        11. Check that users have correct names
        12. Check that users have correct ids
        13. Find users with getent.initgroups(name)
        14. Check that user has correct name
        15. Check that user has correct initgroups
    :expectedresults:
        1. Groups are found
        2. Groups have correct names and gids
        3. Users are found
        4. Users have correct names and ids
        3. Users have correct initgroups
    :customerscenario: False
    """
    users = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    groups = [("group1", 10001), ("group2", 10002), ("group3", 10003)]

    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    for group, id in groups:
        provider.group(group).add(gid=id).add_members([u1, u2, u3])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, id in groups:
        result = client.tools.getent.group(name)
        assert result is not None, f"Group {name} was not found using getent"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {gid} expected"

    for name, id in groups:
        result = client.tools.getent.group(id)
        assert result is not None, f"Group with gid {id} was not found using getent"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {id} expected"

    for user, id in users:
        result = client.tools.getent.passwd(user)
        assert result is not None, f"User {user} was not found using getent"
        assert result.name == user, f"Username {result.name} is incorrect, {user} expected"
        assert result.uid == id, f"User id {result.uid} is incorrect, {id} expected"

        result = client.tools.getent.passwd(id)
        assert result is not None, f"User with uid {id} was not found using getent"
        assert result.name == user, f"Username {result.user} is incorrect, {user} expected"
        assert result.uid == id, f"User id {result.uid} is incorrect, {id} expected"

    for name, id in users:
        result = client.tools.getent.initgroups(name)
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected"
        assert result.memberof([10001, 10002, 10003]), f"User {name} is member of wrong groups"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_with_fully_qualified_name(client: Client, provider: GenericProvider):
    """
    :title: Resolve user when 'use_fully_qualified_names' is 'true'
    :setup:
        1. Add 'user1' and 'user2' to SSSD
        2. Set users uids and gids
        3. In SSSD domain change 'use_fully_qualified_names' to 'true'
        4. Start SSSD
    :steps:
        1. Find 'user1' and 'user2' with id(name)
        2. Find 'user1' and 'user2' with id(name@domain)
        3. Check that users have correct full names
        4. Check that users have correct ids
    :expectedresults:
        1. Users are not found
        2. Users are found
        3. Users have correct full names
        4. Users have correct ids
    :customerscenario: False
    """
    provider.user("user1").add(uid=10001, gid=19001)
    provider.user("user2").add(uid=10002, gid=19002)

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.tools.id("user1") is None, "User user1 should be found only with fq name"
    assert client.tools.id("user2") is None, "User user2 should be found only with fq name"

    result = client.tools.id("user1@test")
    assert result is not None, "User user1@test was not found using id"
    assert result.user.name == "user1@test", f"Username {result.user.name} is incorrect, user1@test expected"
    assert result.user.id == 10001, f"User id {result.user.id} is incorrect, 10001 expected"

    result = client.tools.id("user2@test")
    assert result is not None, "User user2@test was not found using id"
    assert result.user.name == "user2@test", f"Username {result.user.name} is incorrect, user2@test expected"
    assert result.user.id == 10002, f"User id {result.user.id} is incorrect, 10002 expected"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_when_case_insensitive(client: Client, provider: GenericProvider):
    """
    :title: Search user with case insensitive name when 'case_sensitive' is 'false'
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids
        3. In SSSD domain change 'case_sensitive' to 'false'
        4. Start SSSD
    :steps:
        1. Find users with id(name), where name is in random lower and upper case format
        2. Check that usernames are correctly set
        3. Check that users have correct ids
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. Users have correct ids
    :customerscenario: False
    """
    provider.user("user1").add(uid=10001, gid=19001)
    provider.user("user2").add(uid=10002, gid=19002)
    provider.user("user3").add(uid=10003, gid=19003)

    client.sssd.domain["case_sensitive"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid in [
        ("uSer1", 10001),
        ("user1", 10001),
        ("uSER1", 10001),
        ("USEr2", 10002),
        ("uSEr2", 10002),
        ("usER2", 10002),
        ("USer3", 10003),
        ("uSer3", 10003),
        ("USER3", 10003),
    ]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.user.name == name.lower(), f"Username {result.user.name} is incorrect, {name.lower()} expected"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_fully_qualified_name_and_case_insensitive(client: Client, provider: GenericProvider):
    """
    :title: Search user with fq case insensitive name when
            'case_sensitive' is 'false' and 'use_fully_qualified_names' is 'true'
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users gids and uids
        3. Add 'group1', 'group2' and 'group3' to SSSD
        4. Set groups gids
        5. Add members to the groups
        6. In SSSD domain change 'use_fully_qualified_names' to 'true'
        7. In SSSD domain change 'case_sensitive' to 'false'
        8. Start SSSD
    :steps:
        1. Find users with id(name)
        2. Find users with id(name@domain) - name is in random lower and upper case format
        3. Check that users have correct groups
    :expectedresults:
        1. Users are not found
        2. Users are found
        3. Users are members of correct groups
    :customerscenario: False
    """
    u1 = provider.user("user1").add(gid=101, uid=10001)
    u2 = provider.user("user2").add(gid=102, uid=10002)
    u3 = provider.user("user3").add(gid=103, uid=10003)

    provider.group("group1").add(gid=1001).add_members([u1])
    provider.group("group2").add(gid=1002).add_members([u1, u2])
    provider.group("group3").add(gid=1003).add_members([u1, u2, u3])

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.domain["case_sensitive"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.tools.id("user1") is None, "User user1 should be found only with fq name"
    assert client.tools.id("user2") is None, "User user2 should be found only with fq name"
    assert client.tools.id("user3") is None, "User user3 should be found only with fq name"

    for name in ["User1@TesT", "UseR1@TesT", "UsER1@TesT"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.memberof([101, 1001, 1002, 1003]), f"User {name} is member of wrong groups"

    for name in ["uSer2@TeST", "user2@TEsT", "uSER2@tesT"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.memberof([102, 1002, 1003]), f"User {name} is member of wrong groups"

    for name in ["USer3@TeST", "uSer3@TeST", "USER3@Test"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.memberof([103, 1003]), f"User {name} is member of wrong groups"


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_identity__lookup_idmapping_of_posix_and_non_posix_user_and_group(client: Client, provider: GenericADProvider):
    """
    :title: Check ID mapping of POSIX and non POSIX users in AD type directories when ldap_id_mapping is false
    :setup:
        1. Create user with POSIX attriubtes
        2. Create group with POSIX attributes
        3. Create user with no POSIX attributes
        4. Create group with no POSIX attributes
        5. Configure SSSD with "ldap_id_mapping" = false
        6. Start SSSD
    :steps:
        1. Query POSIX group information
        2. Query POSIX user information
        3. Query Non-POSIX group information
        4. Query Non-POSIX user information
    :expectedresults:
        1. POSIX group information should be returned and
            gid matches the one supplied in creation
        2. POSIX user information should be returned and
            uid matches the one supplied in creation
        3. Non-POSIX group information should not be returned
        4. Non-POSIX user information should not be returned
    :customerscenario: False
    """

    u1 = provider.user("posix_user").add(
        uid=10001, gid=20001, password="Secret123", gecos="User for tests", shell="/bin/bash"
    )
    provider.group("posix_group").add(gid=20001).add_member(u1)

    u2 = provider.user("nonposix_user").add(password="Secret123")
    provider.group("nonposix_group").add().add_member(u2)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.id("posix_user")
    assert result is not None, "posix-user is not returned by sssd"
    assert result.group.id == 20001, "gid returned not matched the one provided"
    assert result.user.id == 10001, "uid returned not matched the one provided"

    assert client.tools.getent.group("posix_group") is not None, "posix-group is not returned by sssd"
    assert client.tools.getent.group("nonposix_group") is None, "non-posix group is returned by sssd, it should not be"
    assert client.tools.getent.passwd("nonposix_user") is None, "non-posix user is returned by sssd, it should not be"

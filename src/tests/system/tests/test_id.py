"""
SSSD Client identification

:requirement: IDM-SSSD-REQ: Client side performance improvements
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getpwnam(client: Client, provider: GenericProvider):
    """
    :title: Resolve user by name with id
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids and gids
        3. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that results have correct names
        3. Check that results have correct ids
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. Users have correct ids
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getpwuid(client: Client, provider: GenericProvider):
    """
    :title: Resolve user by uid with id
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids and gids
        3. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(uid)
        2. Check that users have correct names
        3. Check that users have correct ids
    :expectedresults:
        1. Users are found
        2. Users have correct names
        3. Users have correct ids
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(uid)
        assert result is not None, f"User with uid {uid} was not found using id"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getgrnam(client: Client, provider: GenericProvider):
    """
    :title: Resolve group by name with getent.group
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. Set groups gids
        3. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Check that groups have correct names
        3. Check that groups have correct gids
    :expectedresults:
        1. Groups are found
        2. Groups have correct names
        3. Groups have correct gids
    :customerscenario: False
    """
    ids = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in ids:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, gid in ids:
        result = client.tools.getent.group(name)
        assert result is not None, f"Group {name} was not found using getent"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected"
        assert result.gid == gid, f"Group gid {result.gid} is incorrect, {gid} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getgrgid(client: Client, provider: GenericProvider):
    """
    :title: Resolve group with by gid with getent.group
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. Set groups gids
        3. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(gid)
        2. Check that users have correct names
        3. Check that users have correct gids
    :expectedresults:
        1. Groups are found
        2. Groups have correct names
        3. Groups have correct gids
    :customerscenario: False
    """
    ids = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in ids:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, gid in ids:
        result = client.tools.getent.group(gid)
        assert result is not None, f"Group with gid {gid} was not found using getent"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected"
        assert result.gid == gid, f"Group gid {result.gid} is incorrect, {gid} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getent_passwd(client: Client, provider: GenericProvider):
    """
    :title: Resolve user with getent.passwd
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Set users uids and gids
        3. Add 'group1', 'group2' and 'group3' to SSSD
        4. Add users to groups
        5. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with getent.passwd(name)
        2. Find 'user1', 'user2' and 'user3' with getent.passwd(uid)
        3. Check that users have correct names
        4. Check that users have correct ids
    :expectedresults:
        1. Users are found
        2. Users are found
        3. Users have correct names
        4. Users have correct ids
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid in ids:
        result = client.tools.getent.passwd(name)
        assert result is not None, f"User {name} was not found using getent"
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected"
        assert result.uid == uid, f"User id {result.uid} is incorrect, {uid} expected"

        result = client.tools.getent.passwd(uid)
        assert result is not None, f"User with uid {uid} was not found using getent"
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected"
        assert result.uid == uid, f"User id {result.uid} is incorrect, {uid} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getent_group(client: Client, provider: GenericProvider):
    """
    :title: Resolve user with getent.group
    :setup:
        1. Add 'group1', 'group2' and 'group3' to SSSD
        2. Set groups gids
        3. Start SSSD
    :steps:
        1. Find 'group1', 'group2' and 'group3' with getent.group(name)
        2. Find 'group1', 'group2' and 'group3' with getent.group(gid)
        3. Check that groups have correct names
        4. Check that groups have correct gids
    :expectedresults:
        1. Groups are found
        2. Groups are found
        3. Groups have correct names
        4. Groups have correct gids
    :customerscenario: False
    """
    groups = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in groups:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for group, id in groups:
        result = client.tools.getent.group(group)
        assert result is not None, f"Group {group} was not found using getent"
        assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {id} expected"

        result = client.tools.getent.group(id)
        assert result is not None, f"Group with gid {id} was not found using getent"
        assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {id} expected"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__membership_by_group_name(client: Client, provider: GenericProvider):
    """
    :title: Check membership of user by group name with id
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Add 'group1' to SSSD
        3. Add members to group
        4. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users are members of correct group using memberof([name])
    :expectedresults:
        1. Users are found
        2. Users are members of correct group
    :customerscenario: False
    """
    users = [("user1", "group1"), ("user2", "group1"), ("user3", "group1")]
    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()
    u3 = provider.user("user3").add()

    provider.group("group1").add().add_members([u1, u2, u3])

    client.sssd.start()

    for name, groups in users:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.memberof(groups), f"User {name} is member of wrong groups"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__membership_by_group_id(client: Client, provider: GenericProvider):
    """
    :title: Check membership of user by gid with id
    :setup:
        1. Add 'user1', 'user2' and 'user3' to SSSD
        2. Add 'group1' to SSSD
        3. Add members to group
        4. Start SSSD
    :steps:
        1. Find 'user1', 'user2' and 'user3' with id(name)
        2. Check that users are members of correct groups using memberof(gid)
    :expectedresults:
        1. Users are found
        2. Users are members of correct group
    :customerscenario: False
    """
    users = [("user1", 1001), ("user2", 1001), ("user3", 1001)]
    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    provider.group("group1").add(gid=1001).add_members([u1, u2, u3])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, gids in users:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id"
        assert result.memberof(gids), f"User {name} is member of wrong groups"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__initgroups(client: Client, provider: GenericProvider):
    """
    :title: Check initgroups of user
    :setup:
        1. Add users to SSSD
        2. Add groups to SSSD
        3. Set groups gids
        4. Add members to groups
        5. Start SSSD
    :steps:
        1. Find users with getent.initgroups(name)
        2. Check that user has correct name
        3. Check that user has correct initgroups
    :expectedresults:
        1. Users are found
        2. User has correct names
        3. User has correct initgroups
    :customerscenario: False
    """
    users = ["user1", "user2", "user3"]
    u1 = provider.user("user1").add(uid=10001, gid=19001)
    u2 = provider.user("user2").add(uid=10002, gid=19002)
    u3 = provider.user("user3").add(uid=10003, gid=19003)

    provider.group("group1").add(gid=10001).add_members([u1, u2, u3])
    provider.group("group2").add(gid=10002).add_members([u1, u2, u3])
    provider.group("group3").add(gid=10003).add_members([u1, u2, u3])

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name in users:
        result = client.tools.getent.initgroups(name)
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected"
        assert result.memberof([10001, 10002, 10003]), f"User {name} is member of wrong groups"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__getpwnam_fully_qualified_names(client: Client, provider: GenericProvider):
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


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__case_insensitive(client: Client, provider: GenericProvider):
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


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_id__fq_names_case_insensitive(client: Client, provider: GenericProvider):
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

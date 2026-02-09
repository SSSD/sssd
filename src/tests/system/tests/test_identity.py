"""
Identity Tests

These tests cover all the searches, queries, and lookups performed by SSSD.

:requirement: Identity
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider, GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_identity__lookup_username_with_id_command(client: Client, provider: GenericProvider, sssd_service_user: str):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start(service_user=sssd_service_user)

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_identity__lookup_uid_with_id_command(client: Client, provider: GenericProvider, sssd_service_user: str):
    """
    :title: Resolve user by uid with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UID
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start(service_user=sssd_service_user)

    for name, uid in ids:
        result = client.tools.id(uid)
        assert result is not None, f"User with uid {uid} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_groupname_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Resolve group by name with getent
    :setup:
        1. Create the following groups 'group1', 'group2' and 'group3' specifying the GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup the groups
        2. Check the results
    :expectedresults:
        1. Groups are found
        2. Results have the correct names and GIDs
    :customerscenario: False
    """
    ids = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in ids:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, gid in ids:
        result = client.tools.getent.group(name)
        assert result is not None, f"Group {name} was not found using getent!"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected!"
        assert result.gid == gid, f"Group gid {result.gid} is incorrect, {gid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_group_gid_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Resolve group with by gid with getent
    :setup:
        1. Create the following groups 'group1', 'group2' and 'group3' specifying the GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup the groups using their GID with getent
        2. Check the results
    :expectedresults:
        1. Groups are found
        2. Groups have the correct names and GIDs
    :customerscenario: False
    """
    ids = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in ids:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, gid in ids:
        result = client.tools.getent.group(gid)
        assert result is not None, f"Group with gid {gid} was not found using getent!"
        assert result.name == name, f"Groupname {result.name} is incorrect, {name} expected!"
        assert result.gid == gid, f"Group gid {result.gid} is incorrect, {gid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_user_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Resolve user with getent
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup the users using their name
        2. Check the results
        3. Lookup the users using their uid
        4. Check the results
    :expectedresults:
        1. Users are found
        2. Users have correct names and uids
        3. Users are found
        4. Users have correct names and uids
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        provider.user(user).add(uid=id, gid=id + 500)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for name, uid in ids:
        result = client.tools.getent.passwd(name)
        assert result is not None, f"User {name} was not found using getent!"
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected!"
        assert result.uid == uid, f"User id {result.uid} is incorrect, {uid} expected!"

        result = client.tools.getent.passwd(uid)
        assert result is not None, f"User with uid {uid} was not found using getent!"
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected!"
        assert result.uid == uid, f"User id {result.uid} is incorrect, {uid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_groups_by_name_and_gid_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Resolve groups with getent
    :setup:
        1. Create the following groups 'group1', 'group2' and 'group3' specifying the GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup the groups using their name
        2. Check the results
        3. Lookup the groups using their gid
        4. Check the results
    :expectedresults:
        1. Groups are found
        2. Groups have correct names and gids
        3. Groups are found
        4. Groups have correct names and gids
    :customerscenario: False
    """
    groups = [("group1", 10001), ("group2", 10002), ("group3", 10003)]
    for group, id in groups:
        provider.group(group).add(gid=id)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    for group, id in groups:
        result = client.tools.getent.group(group)
        assert result is not None, f"Group {group} was not found using getent!"
        assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected!"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {id} expected!"

        result = client.tools.getent.group(id)
        assert result is not None, f"Group with gid {id} was not found using getent!"
        assert result.name == group, f"Groupname {result.name} is incorrect, {group} expected!"
        assert result.gid == id, f"Group gid {result.gid} is incorrect, {id} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_identity__lookup_group_membership_by_username_with_id_command(
    client: Client, provider: GenericProvider, sssd_service_user: str
):
    """
    :title: Check membership of user by group name with "id"
    :setup:
        1. Create the following users 'user1', 'user2', 'user3', and 'user4'
        2. Create 'group1' and add all users to group except for 'user4'
        3. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup users by name
        2. Check results
    :expectedresults:
        1. Users are found
        2. All users except 'user4' are members of 'group1'
    :customerscenario: False
    """
    users = [("user1", "group1"), ("user2", "group1"), ("user3", "group1")]
    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()
    u3 = provider.user("user3").add()
    u4 = provider.user("user4").add()

    provider.group("group1").add().add_members([u1, u2, u3])

    client.sssd.start(service_user=sssd_service_user)

    for name, groups in users:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.memberof(groups), f"User {name} is a member of the wrong groups!"

    result = client.tools.id(u4.name)
    assert result is not None, "User not found!"
    assert not result.memberof("group1"), f"User {u4.name} is a member of the wrong groups!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_group_membership_by_group_with_id_command(client: Client, provider: GenericProvider):
    """
    :title: Check membership of user by gid with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Create 'group1' and add all users to group
        3. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup users by name with "id"
        2. Check results
    :expectedresults:
        1. Users are found
        2. Users are members of the group checked using the GID
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
        assert result is not None, f"User {name} was not found using id!"
        assert result.memberof(gids), f"User {name} is member of wrong groups!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_initgroups_with_getent(client: Client, provider: GenericProvider):
    """
    :title: Check initgroups of user
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Create the following groups 'group1', 'group2' and 'group3' and add all users to all groups
        3. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup users using initgroups with getent
        2. Check results
    :expectedresults:
        1. Users are found
        2. Users are in the groups checked by GIDs
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
        assert result.name == name, f"Username {result.name} is incorrect, {name} expected!"
        assert result.memberof([10001, 10002, 10003]), f"User {name} is member of wrong groups!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_with_fully_qualified_name(client: Client, provider: GenericProvider):
    """
    :title: Resolve user when 'use_fully_qualified_names' is 'true'
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and "use_fully_qualified_name = true" and start SSSD
    :steps:
        1. Lookup users with their username
        2. Lookup users with their fully qualified name
        3. Check results
    :expectedresults:
        1. Users are not found
        2. Users are found
        3. Users have the correct names and UIDs
    :customerscenario: False
    """
    provider.user("user1").add(uid=10001, gid=19001)
    provider.user("user2").add(uid=10002, gid=19002)

    client.sssd.domain["use_fully_qualified_names"] = "true"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.tools.id("user1") is None, "User user1 should be found only with fq name!"
    assert client.tools.id("user2") is None, "User user2 should be found only with fq name!"

    result = client.tools.id("user1@test")
    assert result is not None, "User user1@test was not found using id!"
    assert result.user.name == "user1@test", f"Username {result.user.name} is incorrect, user1@test expected!"
    assert result.user.id == 10001, f"User id {result.user.id} is incorrect, 10001 expected!"

    result = client.tools.id("user2@test")
    assert result is not None, "User user2@test was not found using id!"
    assert result.user.name == "user2@test", f"Username {result.user.name} is incorrect, user2@test expected!"
    assert result.user.id == 10002, f"User id {result.user.id} is incorrect, 10002 expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_when_case_sensitive_is_false(client: Client, provider: GenericProvider):
    """
    :title: Search user with case-sensitivity is false
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Configure SSSD with "ldap_id_mapping = false" and "case_sensitive = false" and start SSSD
    :steps:
        1. Lookup users by their name randomizing the capitalization of letters in the name
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UID
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
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name.lower(), f"Username {result.user.name} is incorrect, {name.lower()} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_users_fully_qualified_name_and_case_sensitive_is_false(
    client: Client, provider: GenericProvider
):
    """
    :title: Search user with fully qualified name when case-sensitive is false
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs and GIDs
        2. Create the following groups 'group1', 'group2' and 'group3' specifying the GIDs
        3. Configure SSSD with "ldap_id_mapping = false", "case_sensitive = false" and
           "use_fully_qualified_name = true" and start SSSD
    :steps:
        1. Lookup users by their name with id
        2. Lookup users with their fully qualified name randomizing the capitalization of letters in the name
        3. Check that users have correct groups
    :expectedresults:
        1. Users are not found
        2. Users are found
        3. Users are in the correct groups
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

    assert client.tools.id("user1") is None, "User user1 should be found only with fully qualified name!"
    assert client.tools.id("user2") is None, "User user2 should be found only with fully qualified name!"
    assert client.tools.id("user3") is None, "User user3 should be found only with fully qualified name!"

    for name in ["User1@TesT", "UseR1@TesT", "UsER1@TesT"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.memberof([101, 1001, 1002, 1003]), f"User {name} is a member of the wrong groups!"

    for name in ["uSer2@TeST", "user2@TEsT", "uSER2@tesT"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.memberof([102, 1002, 1003]), f"User {name} is a member of the wrong groups!"
        assert not result.memberof(1001), f"User {name} is in the wrong groups!"

    for name in ["USer3@TeST", "uSer3@TeST", "USER3@Test"]:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.memberof([103, 1003]), f"User {name} is a member of the wrong groups!"
        assert not result.memberof([1001, 1002]), f"User {name} is in the wrong groups!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_identity__lookup_id_mapping_of_posix_and_non_posix_user_and_group(
    client: Client, provider: GenericADProvider
):
    """
    :title: Check ID mapping of POSIX and non-POSIX users in AD directories when id mapping is false
    :note: This is a generic provider test, AD is a workaround to create users with no posix attributes
    :setup:
        1. Create user with POSIX attributes
        2. Create group with POSIX attributes
        3. Create user with no POSIX attributes
        4. Create group with no POSIX attributes
        5. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Query POSIX user information
        2. Query Non-POSIX user information
        3. Query POSIX group information
        4. Query Non-POSIX group information
    :expectedresults:
        1. POSIX user found with the correct values
        2. User is not found
        3. POSIX group found with the correct values
        4. Group is not found
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

    user = client.tools.getent.passwd("posix_user")
    assert user is not None, "posix-user not found!"
    assert user.uid == 10001, "gid returned does not matched the one provided!"
    assert user.gid == 20001, "uid returned does not matched the one provided!"
    assert client.tools.getent.passwd("nonposix_user") is None, "nonposix-user found!"

    group = client.tools.getent.group("posix_group")
    assert group is not None, "posix-group not found!"
    assert group.gid == 20001, "gid is not the correct value!"
    assert client.tools.getent.group("nonposix_group") is None, "nonposix-group found!"


@pytest.mark.ticket(bz=1695577)
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_when_auto_private_groups_is_set_to_true(client: Client, provider: GenericProvider):
    """
    :title: Look up users when auto private groups is set to true
    :description:
        When true, the user's gid will match the uid, even when the object isn't
        a real group in the directory. If it is a real group, the user values will override
        the name and gid. In this test, only the users exist in LDAP.
    :setup:
        1. Create the following users 'user_same_gid', 'user_diff_gid' and 'user_group_gid'.
            Set the uids and gids to match the condition defined by in the username
        2. Configure SSSD with "ldap_id_mapping = false" and "auto_private_groups = true" and start SSSD
    :steps:
        1. Lookup all users and compare their uid to their gid
        2. Lookup up the user's gid
    :expectedresults:
        1. All users uid and gid match
        2. All groups are found
    :customerscenario: True
    :requirement: IDM-SSSD-REQ: SSSD can automatically create user private groups for users
    """
    provider.user("user_same_gid").add(uid=111111, gid=111111)
    provider.user("user_diff_gid").add(uid=222222, gid=333333)
    provider.user("user_no_gid").add(uid=444444)

    client.sssd.domain["auto_private_groups"] = "true"
    client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    for i in [("user_same_gid", 111111), ("user_diff_gid", 222222), ("user_no_gid", 444444)]:
        user = client.tools.getent.passwd(i[0])
        assert user is not None, f"User '{i[0]}' is not found!"
        assert user.uid == (i[1]), "uid does not match expected value!"
        assert user.uid == user.gid, "uid does not match gid!"

        group = client.tools.getent.group(i[0])
        assert group is not None, f"{i[0]} group is not found!"


@pytest.mark.ticket(bz=1695577)
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_when_auto_private_groups_is_set_to_false(client: Client, provider: GenericProvider):
    """
    :title: Look up users when auto private groups is set to false
    :description:
        When false, to be able to look up the group, the group needs to exist
        in the directory. In this test, only the 'user_group_gid' user has a valid LDAP group.
    :setup:
        1. Create a group
        2. Create the following users 'user_same_gid', 'user_diff_gid' and 'user_group_gid'.
            Set the uids and gids to match the condition defined by in the username
        3. Configure SSSD with "ldap_id_mapping = false" and "auto_private_groups = false" and start SSSD
    :steps:
        1. Lookup 'user_same_gid' and look up the user's gid
        2. Lookup 'user_diff_gid' and look up the user's gid
        3. Lookup 'user_group_gid' and look up the user's gid
    :expectedresults:
        1. The user is found with the configured values, and the group is *NOT* found
        2. The user is found with the configured values, and the group is *NOT* found
        3. The user is found with the configured values, and the group is found
    :customerscenario: True
    :requirement: IDM-SSSD-REQ: SSSD can automatically create user private groups for users
    """
    provider.group("group").add(gid=444444)
    provider.user("user_same_gid").add(uid=111111, gid=111111)
    provider.user("user_diff_gid").add(uid=222222, gid=333333)
    provider.user("user_group_gid").add(uid=444444, gid=444444)

    client.sssd.domain["auto_private_groups"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    result = client.tools.getent.passwd("user_same_gid")
    assert result is not None, "User 'user_same_gid' not found!"
    assert result.gid == 111111, "gid does not match expected value!"

    # IPA manages auto_private_groups on the server and is true by default
    if isinstance(provider, IPA):
        assert client.tools.getent.group(111111), "Group is not found!"
    else:
        assert not client.tools.getent.group(111111), "Group should not be found!"

    result = client.tools.getent.passwd("user_diff_gid")
    assert result is not None, "User 'user_diff_gid' is not found!"
    assert result.gid == 333333, "gid does not match expected value!"
    assert client.tools.getent.group(333333) is None, "group is found!"

    result = client.tools.getent.passwd("user_group_gid")
    assert result is not None, "User 'user_group_gid' is not found!"
    assert result.gid == 444444, "gid does not match expected value!"
    assert client.tools.getent.group(444444) is not None, "group is not found!"


@pytest.mark.ticket(bz=1695577)
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_identity__lookup_when_auto_private_groups_is_set_to_hybrid(client: Client, provider: GenericProvider):
    """
    :title: Look up users when auto private groups is set to hybrid
    :description:
        When set to hybrid, if the uid and gid match for the user, it will act as if a
        group exists similar to when the parameter is set to true. Like when it's set to false, if the
        group exists in LDAP, it will look at whatever is existing for its values.
    :setup:
        1. Create a group
        2. Create the following users 'user_same_gid', 'user_diff_gid', 'user_no_gid' and 'user_group_gid'.
            Set the uids and gids to match the condition defined by in the username
        3. Configure SSSD with "ldap_id_mapping = false" and "auto_private_groups = hybrid" start SSSD
    :steps:
        1. Lookup 'user_same_gid' and look up the user's gid
        2. Lookup 'user_diff_gid' and look up the user's gid
        3. Lookup 'user_no_gid' and look up the user's gid
        4. Lookup 'user_group_gid' and look up the user's gid
    :expectedresults:
        1. The user is found with the configured values, and the group is found
        2. The user is found with the configured values, and the group is *NOT* found
        3. The user is found with the configured values, and the group is *NOT* found
        4. The user is found with the configured values, and the group is found
    :customerscenario: True
    :requirement: IDM-SSSD-REQ: SSSD can automatically create user private groups for users
    """
    provider.group("group").add(gid=55555)
    provider.user("user_same_gid").add(uid=111111, gid=111111)
    provider.user("user_diff_gid").add(uid=222222, gid=333333)
    provider.user("user_no_gid").add(uid=444444)
    provider.user("user_group_gid").add(uid=555555, gid=555555)

    client.sssd.domain["auto_private_groups"] = "hybrid"
    client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    result = client.tools.getent.passwd("user_same_gid")
    assert result is not None, "User 'user_same_gid' not found!"
    assert result.gid == 111111, "gid does not match expected value!"
    assert client.tools.getent.group(111111) is not None, "auto private group not found!"

    result = client.tools.getent.passwd("user_diff_gid")
    assert result is not None, "User 'user_diff_gid' not found!"
    assert result.gid == 333333, "gid does not match expected value!"
    assert client.tools.getent.group(333333) is None, "auto private group should not be found!"

    # IPA manages auto_private_groups on the server and is true by default
    if isinstance(provider, IPA):
        result = client.tools.getent.passwd("user_group_gid")
        assert result is not None, "User 'user_group_gid' not found!"
        assert result.gid == 555555, "gid is not found!"
    else:
        assert client.tools.getent.passwd("user_no_id") is None, "gid should not be found!"

    result = client.tools.getent.passwd("user_group_gid")
    assert result is not None, "User 'user_group_gid' not found!"
    assert result.gid == 555555, "gid does not match expected value!"
    assert client.tools.getent.group(555555) is not None, "auto private group not found!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_identity__lookup_when_backend_restarts(client: Client, ldap: LDAP):
    """
    :title: Look up user when backend is restarted with previous lookup unfinished
    :description:
        If there is an active lookup for a user and the backend is restarted
        before this lookup is finished, the next lookup of the same user after
        the restart must not timeout.
    :setup:
        1. Add a user "tuser"
        2. Start SSSD
    :steps:
        1. Add 10s network traffic delay to the LDAP host
        2. Lookup "tuser" asynchronously
        3. Kill sssd_be with SIGKILL so it is restarted
        4. Remove the network traffic delay
        5. Lookup of "tuser" must yield the user and not timeout
    :expectedresults:
        1. Network traffic is delayed
        2. Lookup hangs, does not finish and waits for a timeout
        3. The backend process is restarted
        4. Network traffic is no longer delayed
        5. User lookup returns the user immediately
    :customerscenario: False
    """
    ldap.user("tuser").add()

    client.sssd.start()

    # Add a delay so the next lookup will hang
    client.tc.add_delay(ldap, "10s")
    client.host.conn.async_run("getent passwd tuser")

    # Kill backend and remove the delay
    client.host.conn.run("kill -KILL $(pidof sssd_be)")
    client.tc.remove_delay(ldap)

    # The next lookup should not timeout
    result = client.tools.wait_for_condition("getent passwd tuser", timeout=5)
    assert "tuser" in result.stdout, "tuser was not found"


@pytest.mark.importance("high")
@pytest.mark.ticket(jira="RHEL-128594", gh=8194)
@pytest.mark.topology(KnownTopology.LDAP)
def test_identity__filter_groups_by_name_and_lookup_by_gid(client: Client, ldap: LDAP):
    """
    :title: Filtered groups cannot be looked up by GID and do not cause hangs
    :setup:
        1. Create user 'user-1' and group 'group-1' with GID 20001
        2. Add 'group-1' to filter_groups in SSSD configuration and start SSSD
    :steps:
        1. Lookup group by GID 20001 with getent
        2. Expire SSSD cache
        3. Lookup group by GID 20001 again with a timeout to ensure it doesn't hang
    :expectedresults:
        1. Group is not found (filtered)
        2. Cache is expired successfully
        3. Group lookup completes within timeout and group is still not found
    :customerscenario: False
    """
    u = ldap.user("user-1").add()
    ldap.group("group-1").add(gid=20001).add_member(u)

    client.sssd.nss["filter_groups"] = "group-1"
    client.sssd.start()

    result = client.tools.getent.group(20001)
    assert result is None, "Filtered group was found"

    # Check that the command does not hang when refreshing the GID
    client.sssctl.cache_expire(everything=True)
    client.tools.wait_for_condition("getent group 20001 || :", timeout=5)

    result = client.tools.getent.group(20001)
    assert result is None, "Filtered group was found"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_identity__nested_non_posix_group(client: Client, provider: GenericADProvider):
    """
    :title: Lookup indirect group-members of a nested non-POSIX group
    :setup:
        1. Add a new POSIX user and two new groups, one POSIX the other non-POSIX
        2. Add the user to the non-POSIX group and the non-POSIX group to the POSIX group
        3. Set 'ldap_id_mapping = false' to allow non-POSIX groups, because
           with POSIX id-mapping enabled all groups will get POSIX ID and hence
           there are no non-POSIX groups, and start SSSD
    :steps:
        1. Lookup the POSIX group with getent
    :expectedresults:
        1. Group is present and the new user is a member
    :customerscenario: False
    """
    user = provider.user("nesteduser").add(
        uid=10001, gid=20001, password="Secret123", gecos="User for tests", shell="/bin/bash"
    )
    nested_group = provider.group("nested_nonposix_group").add().add_member(user)
    base_group = provider.group("posix_group").add(gid=30001).add_member(nested_group)

    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    result = client.tools.getent.group(base_group.name)
    assert result is not None, f"Group '{base_group.name}' not found!"
    assert (
        len(result.members) == 1
    ), f"Group '{base_group.name}' has unexpected number of members [{len(result.members)}]!"
    assert f"{user.name}" in result.members, f"Member '{user.name}' of group '{base_group.name}' not found!"

    result = client.tools.getent.group(nested_group.name)
    assert result is None, f"Non-POSIX Group '{nested_group.name}' was found with 'getent group'!"

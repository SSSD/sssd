"""
SSSD NSS tests

:requirement: NSS
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_nss__fallback_homedir(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "fallback_homedir" option
    :description:
        This test checks that the 'fallback_homedir' option in the [nss]
        section of sssd.conf provides a home directory only when the user
        entry in LDAP does not have one.
    :setup:
        1. Create users in provider: one with a home directory and one
           with an empty home directory.
        2. Configure SSSD with 'fallback_homedir = /home/nohome-%u'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify home directories.
    :expectedresults:
        1. The user with a non-empty home directory keeps it.
        2. The user with an empty home directory gets the fallback.
    :customerscenario: False
    """
    expected_homes = {"user1": "/home/A", "user2": "/home/nohome-user2"}
    provider.user("user1").add(home="/home/A")
    provider.user("user2").add(home="")

    client.sssd.nss["fallback_homedir"] = "/home/nohome-%u"
    client.sssd.restart(clean=True)

    for user in expected_homes.keys():
        entry = client.tools.getent.passwd(user)
        assert entry is not None and entry.home == expected_homes[user]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__filter_users(client: Client, provider: LDAP):
    """
    :title: Test filtering of users and groups with 'filter_users' and 'filter_groups'
    :description:
        This test verifies that users can be filtered out from NSS
        lookups using the 'filter_users' options.
    :setup:
        1. Create several users and groups in provider.
        2. Configure SSSD with 'filter_users'.
        3. Start SSSD.
    :steps:
        1. Attempt to look up non-filtered users.
        2. Attempt to look up filtered users.
        3. Check group memberships to ensure filtered users are excluded.
    :expectedresults:
        1. Non-filtered users are found.
        2. Filtered users are not found.
        3. Group does not include filtered users.
    :customerscenario: True
    """
    # Create users
    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()
    u3 = provider.user("user3").add()

    # Create group
    g1 = provider.group("group1").add()
    g1.add_member(u1).add_member(u2).add_member(u3)

    client.sssd.start()
    u2_ent = client.tools.getent.passwd(u2.name)
    assert u2_ent is not None
    client.sssd.stop()

    client.sssd.nss["filter_users"] = u2.name
    client.sssd.start(clean=True)

    # Test if user3 is filtered
    assert client.tools.id(u1.name) is not None
    assert client.tools.id(u2.name) is None
    assert client.tools.getent.passwd(str(u2_ent.uid)) is None
    assert client.tools.id(u3.name) is not None

    # Test if user3 is filtered from group
    g = client.tools.getent.group(g1.name)
    assert g is not None
    assert u1.name in g.members
    assert u2.name not in g.members
    assert u3.name in g.members


# this test does not work with Samba/AD
@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__filter_groups(client: Client, provider: GenericProvider):
    """
    :title: Test filtering of users and groups with 'filter_users' and 'filter_groups'
    :description:
        This test verifies that groups can be filtered out from NSS
        lookups using the 'filter_groups' options.
    :setup:
        1. Create several users and groups in provider.
        2. Configure SSSD with 'filter_groups'.
        3. Start SSSD.
    :steps:
        1. Attempt to look up non-filtered groups.
        2. Attempt to look up filtered groups.
        3. Check user membership to ensure filtered groups are excluded.
    :expectedresults:
        1. Non-filtered groups are found.
        2. Filtered groups are not found.
        3. User is not member of filtered group.
    :customerscenario: True
    """
    # Create users
    u1 = provider.user("user1").add()
    u2 = provider.user("user2").add()

    # Create groups
    g1 = provider.group("group1").add()
    g2 = provider.group("filtered").add()
    g3 = provider.group("group3").add()
    g1.add_member(u1).add_member(u2)
    g2.add_member(u1).add_member(u2)
    g3.add_member(u1).add_member(u2)

    client.sssd.start()
    g1_ent = client.tools.getent.group(g1.name)
    assert g1_ent is not None
    g2_ent = client.tools.getent.group(g2.name)
    assert g2_ent is not None
    g3_ent = client.tools.getent.group(g3.name)
    assert g3_ent is not None
    client.sssd.stop()

    client.sssd.nss["filter_groups"] = g2.name
    client.sssd.start(clean=True)

    # Test groups
    assert client.tools.getent.group(g1.name) is not None
    assert client.tools.getent.group(g2.name) is None
    assert client.tools.getent.group(g3.name) is not None

    # test user's membership
    u1_id = client.tools.id(u1.name)
    assert u1_id is not None
    gids = set([group.id for group in u1_id.groups])
    assert set([g1_ent.gid, g3_ent.gid]).issubset(gids)
    assert g2_ent.gid not in gids


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__override_shell(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "override_shell" option
    :description:
        This test checks that the 'override_shell' option in the [nss]
        section of sssd.conf correctly overrides the login shell for
        all users.
        We skip user with an empty shell for AD/Samba. Both providers
        refuse to create such user.
    :setup:
        1. Create three users with different loginShell attributes.
        2. Configure SSSD with 'override_shell = /bin/B'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify that the login shell for each user is '/bin/B'.
    :expectedresults:
        1. All users are found.
        2. Each user's login shell is overridden to '/bin/B'.
    :customerscenario: True
    """
    is_ad = isinstance(provider, Samba) or isinstance(provider, AD)
    users = [
        {"name": "user1", "shell": "/bin/A"},
        {"name": "user2", "shell": "/bin/B"},
    ]
    if not is_ad:
        users.append({"name": "user3", "shell": ""})

    for user in users:
        provider.user(user["name"]).add(shell=user["shell"])

    client.sssd.nss["override_shell"] = "/bin/B"
    client.sssd.start()

    for user in users:
        result = client.tools.getent.passwd(user["name"])
        assert result is not None, "User '%s' not found" % user["name"]
        assert result.shell == "/bin/B", "User '%s' has incorrect shell" % user["name"]


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__shell_fallback(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "shell_fallback" option
    :description:
        This test checks that the 'shell_fallback' option in the [nss]
        section of sssd.conf provides a shell for users whose shell is
        not in /etc/shells.
        Note that creating user with empty shell does not work with AD/Samba.
    :setup:
        1. Create users with different shells. One valid, one invalid,
           one empty.
        2. Configure SSSD with 'shell_fallback' and 'allowed_shells'.
        3. Start SSSD.
    :steps:
        1. Verify user shells.
    :expectedresults:
        1. User with a valid shell keeps it.
           User with an invalid shell gets the fallback shell and
           user with an empty shell has the default shell for the system.
    :customerscenario: True
    """
    is_ad = isinstance(provider, Samba) or isinstance(provider, AD)
    users = [
        {"name": "user1", "shell": "/bin/sh", "expected_shell": "/bin/sh"},
        {"name": "user2", "shell": "/bin/not_installed", "expected_shell": "/bin/fallback"},
    ]
    if not is_ad:
        users.append({"name": "user3", "shell": "", "expected_shell": ""})
    for user in users:
        provider.user(user["name"]).add(shell=user["shell"])

    # /bin/sh should be in /etc/shells by default in the container.
    # /bin/not_installed should not be.
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.nss["allowed_shells"] = "/bin/not_installed"
    client.sssd.start()

    for user in users:
        result = client.tools.getent.passwd(user["name"])
        assert result is not None, "User '%s' not found" % user["name"]
        assert result.shell == user["expected_shell"], "User '%s' has incorrect shell" % user["name"]


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__default_shell(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "default_shell" option
    :description:
        This test checks that the 'default_shell' option in the [nss]
        section of sssd.conf provides a shell for users who don't have
        one defined.
        Note that creating user with empty shell does not work with AD/Samba.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'default_shell', 'allowed_shells', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Verify user shells.
    :expectedresults:
        1. User with valid shell keeps it.
           User with invalid shell gets fallback.
           User with empty shell gets default shell.
    :customerscenario: True
    """
    is_ad = isinstance(provider, Samba) or isinstance(provider, AD)
    users = [
        {"name": "user1", "shell": "/bin/sh", "expected_shell": "/bin/sh"},
        {"name": "user2", "shell": "/bin/not_installed", "expected_shell": "/bin/fallback"},
    ]
    if not is_ad:
        users.append({"name": "user3", "shell": "", "expected_shell": "/bin/default"})
    for user in users:
        provider.user(user["name"]).add(shell=user["shell"])

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["allowed_shells"] = "/bin/default, /bin/not_installed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    for user in users:
        result = client.tools.getent.passwd(user["name"])
        assert result is not None, "User '%s' not found" % user["name"]
        assert result.shell == user["expected_shell"], "User '%s' has incorrect shell" % user["name"]


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_nss__vetoed_shells(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "vetoed_shells" option
    :description:
        This test checks that the 'vetoed_shells' option in the [nss]
        section of sssd.conf prevents users from having a shell from the
        vetoed list.
        Note that creating user with empty shell does not work with AD/Samba.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'vetoed_shells', 'default_shell', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Verify user shells.
    :expectedresults:
        1. User with a valid, non-vetoed shell keeps it.
           User with a vetoed shell gets the fallback shell.
           user with an empty shell gets the default shell.
    :customerscenario: True
    """
    is_ad = isinstance(provider, Samba) or isinstance(provider, AD)
    users = [
        {"name": "user1", "shell": "/bin/sh", "expected_shell": "/bin/sh"},
        {"name": "user2", "shell": "/bin/vetoed", "expected_shell": "/bin/fallback"},
    ]
    if not is_ad:
        users.append({"name": "user3", "shell": "", "expected_shell": "/bin/default"})
    for user in users:
        provider.user(user["name"]).add(shell=user["shell"])

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["vetoed_shells"] = "/bin/vetoed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    for user in users:
        result = client.tools.getent.passwd(user["name"])
        assert result is not None, "User '%s' not found" % user["name"]
        assert result.shell == user["expected_shell"], "User '%s' has incorrect shell" % user["name"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_nss__filters_cached(client: Client, provider: GenericProvider):
    """
    :title: Test caching of filtered users and groups
    :description:
        This test verifies that filtered users and groups are negatively
        cached and that root user/group are always filtered.
        This test uses LDAP provider only because other provides
        refuse to create such wild users/groups.
    :setup:
        1. Create users and groups in LDAP, including a user named 'root'
           and another with UID 0.
        2. Configure SSSD with 'filter_users', 'filter_groups', and a short
           'entry_negative_timeout'.
        3. Start SSSD.
    :steps:
        1. Look up a non-filtered user to confirm it is found.
        2. Look up a filtered user and group; they should not be found.
        3. Wait for the negative cache to expire and look them up again.
        4. Check that 'root' user and group (both by name and ID 0) are not
           found through SSSD, even if they exist in LDAP.
    :expectedresults:
        1. Non-filtered user is found.
        2. Filtered entries are not found and are negatively cached.
        3. After timeout, filtered entries are still not found.
        4. Root user and group are always filtered.
    :customerscenario: True
    """
    # Create users
    provider.user("user1").add(uid=1001, gid=2001)
    provider.user("user2").add(uid=1002, gid=2002)  # filtered
    provider.user("user3").add(uid=1003, gid=2003)
    provider.user("root").add(uid=1004, gid=2004)  # should be filtered
    provider.user("zerouid").add(uid=0, gid=0)  # should be filtered

    # Create groups
    provider.group("group1").add(gid=2001)
    provider.group("group2").add(gid=2002)  # filtered
    provider.group("group3").add(gid=2003)
    provider.group("root").add(gid=2004)  # should be filtered
    provider.group("zerogid").add(gid=0)  # should be filtered

    client.sssd.nss["filter_users"] = "user2"
    client.sssd.nss["filter_groups"] = "group2"
    client.sssd.nss["entry_negative_timeout"] = "2"
    client.sssd.start()

    assert client.tools.id("user1") is not None
    assert client.tools.id("user3") is not None

    # Test filtered user and caching
    assert client.tools.id("user2") is None
    assert client.tools.id("user2") is None

    # Test filtered group and caching
    assert client.tools.getent.group("group2") is None
    assert client.tools.getent.group("group2") is None

    # Test root is always filtered
    assert client.tools.getent.passwd("root", service="sss") is None
    assert client.tools.getent.group("root", service="sss") is None
    assert client.tools.getent.passwd(0, service="sss") is None
    assert client.tools.getent.group(0, service="sss") is None

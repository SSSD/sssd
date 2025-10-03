"""
SSSD NSS tests
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.IPA)
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
    :customerscenario: True
    """
    expected_homes = {"user1": "/home/A", "user2": "/home/nohome-user2"}
    provider.user("user1").add(home="/home/Assh ")
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
    u2_uid = client.tools.getent.passwd(u2.name).gid
    client.sssd.stop()

    client.sssd.nss["filter_users"] = u2.name
    client.sssd.start(clean=True)

    # Test if user3 is filtered
    assert client.tools.id(u1.name) is not None
    assert client.tools.id(u2.name) is None
    assert client.tools.getent.passwd(u2_uid) is None
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
    g1_gid = client.tools.getent.group(g1.name).gid
    g2_gid = client.tools.getent.group(g2.name).gid
    g3_gid = client.tools.getent.group(g3.name).gid
    client.sssd.stop()

    client.sssd.nss["filter_groups"] = g2.name
    client.sssd.start(clean=True)

    # Test groups
    assert client.tools.getent.group(g1.name) is not None
    assert client.tools.getent.group(g2.name) is None
    assert client.tools.getent.group(g3.name) is not None

    # test user's membership
    gids = set([group.id for group in client.tools.id(u1.name).groups])
    assert set([g1_gid, g3_gid]).issubset(gids)
    assert g2_gid not in gids


@pytest.mark.importance("medium")
#@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
def test_nss__override_shell(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "override_shell" option
    :description:
        This test checks that the 'override_shell' option in the [nss]
        section of sssd.conf correctly overrides the login shell for
        all users.
    :setup:
        1. Create three users in LDAP with different loginShell attributes.
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
    provider.user("user_with_shell_A").add(shell="/bin/A")
    provider.user("user_with_shell_B").add(shell="/bin/B")
    provider.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["override_shell"] = "/bin/B"
    client.sssd.start()

    for user in ["user_with_shell_A", "user_with_shell_B", "user_with_empty_shell"]:
        result = client.tools.getent.passwd(user)
        assert result is not None, f"User '{user}' not found"
        assert result.shell == "/bin/B", f"User '{user}' has incorrect shell"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_nss__shell_fallback(client: Client, provider: GenericProvider):
    """
    :title: Test the effect of the "shell_fallback" option
    :description:
        This test checks that the 'shell_fallback' option in the [nss]
        section of sssd.conf provides a shell for users whose shell is
        not in /etc/shells.
    :setup:
        1. Create users in LDAP with different shells. One valid, one invalid,
           one empty.
        2. Configure SSSD with 'shell_fallback' and 'allowed_shells'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with a valid shell keeps it.
        2. User with an invalid shell gets the fallback shell.
        3. User with an empty shell has the default shell for the system.
    :customerscenario: True
    """
    provider.user("user_with_sh_shell").add(shell="/bin/sh")
    provider.user("user_with_not_installed_shell").add(shell="/bin/not_installed")
    provider.user("user_with_empty_shell").add(shell="")

    # /bin/sh should be in /etc/shells by default in the container.
    # /bin/not_installed should not be.
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.nss["allowed_shells"] = "/bin/not_installed"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_not_installed = client.tools.getent.passwd("user_with_not_installed_shell")
    assert user_not_installed is not None and user_not_installed.shell == "/bin/fallback"

    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    assert user_empty is not None and user_empty.shell == ""


@pytest.mark.importance("medium")
# @pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_nss__default_shell(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "default_shell" option
    :description:
        This test checks that the 'default_shell' option in the [nss]
        section of sssd.conf provides a shell for users who don't have
        one defined in LDAP.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'default_shell', 'allowed_shells', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with valid shell keeps it.
        2. User with invalid shell gets fallback.
        3. User with empty shell gets default shell.
    :customerscenario: True
    """
    ldap.user("user_with_sh_shell").add(shell="/bin/sh")
    ldap.user("user_with_not_installed_shell").add(shell="/bin/not_installed")
    ldap.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["allowed_shells"] = "/bin/default, /bin/not_installed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_not_installed = client.tools.getent.passwd("user_with_not_installed_shell")
    assert user_not_installed is not None and user_not_installed.shell == "/bin/fallback"

    ## TODO: fix
    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    assert user_empty is not None and user_empty.shell == "/bin/default"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
#@pytest.mark.topology(KnownTopology.LDAP)
def test_nss__vetoed_shells(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "vetoed_shells" option
    :description:
        This test checks that the 'vetoed_shells' option in the [nss]
        section of sssd.conf prevents users from having a shell from the
        vetoed list.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'vetoed_shells', 'default_shell', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with a valid, non-vetoed shell keeps it.
        2. User with a vetoed shell gets the fallback shell.
        3. User with an empty shell gets the default shell.
    :customerscenario: True
    """
    ldap.user("user_with_sh_shell").add(shell="/bin/sh")
    ldap.user("user_with_vetoed_shell").add(shell="/bin/vetoed")
    ldap.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["vetoed_shells"] = "/bin/vetoed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_vetoed = client.tools.getent.passwd("user_with_vetoed_shell")
    assert user_vetoed is not None and user_vetoed.shell == "/bin/fallback"

    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    assert user_empty is not None and user_empty.shell == "/bin/default"


@pytest.mark.importance("high")
# @pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_nss__filters_cached(client: Client, ldap: LDAP):
    """
    :title: Test caching of filtered users and groups
    :description:
        This test verifies that filtered users and groups are negatively
        cached and that root user/group are always filtered.
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
    ldap.user("user1").add(uid=1001, gid=2001)
    ldap.user("user2").add(uid=1002, gid=2002)  # filtered
    ldap.user("user3").add(uid=1003, gid=2003)
    ldap.user("root").add(uid=1004, gid=2004)  # should be filtered
    ldap.user("zerouid").add(uid=0, gid=0)  # should be filtered

    # Create groups
    ldap.group("group1").add(gid=2001)
    ldap.group("group2").add(gid=2002)  # filtered
    ldap.group("group3").add(gid=2003)
    ldap.group("root").add(gid=2004)  # should be filtered
    ldap.group("zerogid").add(gid=0)  # should be filtered

    client.sssd.nss["filter_users"] = "user2"
    client.sssd.nss["filter_groups"] = "group2"
    client.sssd.nss["entry_negative_timeout"] = "2"
    client.sssd.start()

    assert client.tools.id("user1") is not None
    assert client.tools.id("user3") is not None

    # Test filtered user and caching
    assert client.tools.id("user2") is None
    time.sleep(3)
    assert client.tools.id("user2") is None

    # Test filtered group and caching
    assert client.tools.getent.group("group2") is None
    time.sleep(3)
    assert client.tools.getent.group("group2") is None

    # Test root is always filtered
    assert client.tools.getent.passwd("root", service="sss") is None
    assert client.tools.getent.group("root", service="sss") is None
    assert client.tools.getent.passwd(0, service="sss") is None
    assert client.tools.getent.group(0, service="sss") is None

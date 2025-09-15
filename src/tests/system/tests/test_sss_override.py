"""
Local OverrideTests.

IPA does not support this feature because, it manages user and group overrides
 using ID views on the IPA master.

 Test setups require an extra restart to update the ldb cache with local
 override attributes.

:requirement:  IDM-SSSD-TC: ldap_provider: local_overrides
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__username(client: Client, provider: GenericProvider):
    """
    :title: Override username

    :setup:
        1. Create user
        2. Start SSSD
        3. Create local override and restart SSSD
    :steps:
        1. Login as the regular and override name
    :expectedresults:
        1. Users logins are successful
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    client.sss_override.user("user1").add(name="o-user1")
    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "Failed 'user1' login!"
    assert client.auth.ssh.password("o-user1", "Secret123"), "Override name 'o-user1' failed login!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1254184)
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__fully_qualified_name(client: Client, provider: GenericProvider):
    """
    :title: Override using fully qualified name
    :setup:
        1. Create user
        2. Configure SSSD with "use_fully_qualified_names=True" and start SSSD
        3. Create user override and restart SSSD
    :steps:
        1. Login with the short username and short overridden name
        2. Login with the fully qualified username and overridden name
    :expectedresults:
        1. Logins fail
        2. Login successful
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()
    client.sss_override.user(f"user1@{client.sssd.default_domain}").add(name="o-user1")
    client.sssd.restart()

    assert not client.auth.ssh.password("user1", "Secret123"), "Short usernames 'user1' should not be able to login!"
    assert not client.auth.ssh.password(
        "o-user1", "Secret123"
    ), "Short override name 'o-user1' should not be able to login!"
    assert client.auth.ssh.password(f"user1@{client.sssd.default_domain}", "Secret123"), "User 'user1' login failed!"
    assert client.auth.ssh.password(
        f"o-user1@{client.sssd.default_domain}", "Secret123"
    ), "User override 'o-user1' login failed!"


@pytest.mark.importance("high")
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__user_attributes(client: Client, provider: GenericProvider):
    """
    :title: Override user attributes
    :setup:
        1. Create user with posix attributes
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
        3. Create local override and restart SSSD
    :steps:
        1. Lookup user and override username
    :expectedresults:
        1. User and override username found and values overridden
    :customerscenario: False
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()
    client.sss_override.user("user1").add(name="o-user1", uid=999999, gid=888888, home="/home/o-user1")
    client.sssd.restart()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User 'user1' not found!"
    assert result.uid == 999999, f"User's uid {result.uid} does not match override value!"
    assert result.gid == 888888, f"User's gid {result.gid} does not match override value!"
    assert result.home == "/home/o-user1", "User's homedir does not match override value!"

    result = client.tools.getent.passwd("o-user1")
    assert result is not None, "User 'o-user1' not found by override name!"
    assert result.uid == 999999, f"Local override uid {result.uid} does not match override value!"
    assert result.gid == 888888, f"Local override gid {result.gid} does not match override value!"
    assert result.home == "/home/o-user1", "User's override name homedir does not match override value!"


@pytest.mark.importance("high")
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__group_attributes_and_members(client: Client, provider: GenericProvider):
    """
    :title: Override group attributes and members
    :setup:
        1. Create user  and group, make the user a group member
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
        3. Create local user and group override and restart SSSD
    :steps:
        1. Lookup group name and overridden name, check gid and group members
        2. Update group gid value for override, check gid and group members
    :expectedresults:
        1. Group is found by both names, gid matches override and user is a member
        2. Group is found by both names, gid matches new override value and user is a member
    :customerscenario: False
    """
    user = provider.user("user1").add(uid=777777, gid=777777)
    provider.group("group1").add(gid=999999).add_member(user)
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    client.sss_override.user("user1").add(name="o-user1")
    client.sss_override.group("group1").add(name="o-group1")
    client.sssd.restart()

    for i in ["group1", "o-group1"]:
        result = client.tools.getent.group(i)
        assert result is not None, f"Group {i} not found!"
        assert result.gid == 999999, f"Group gid {result.gid} does not match original value!"
        assert "o-user1" in result.members, "Local override user 'o-user1' not found in group!"

    client.sss_override.group("group1").add(name="o-group1", gid=888888)
    for i in ["group1", "o-group1"]:
        result = client.tools.getent.group(i)
        assert result is not None, f"Group not {i} found!"
        assert result.gid == 888888, f"Group gid {result.gid} does not match override value!"
        assert "o-user1" in result.members, "Local override username 'o-user1' not found in group!"


@pytest.mark.importance("high")
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__root_user_cannot_be_used(client: Client, provider: GenericProvider):
    """
    :title: Root user cannot be used for overrides
    :setup:
        1. Create users, one named root
        2. Configure SSSD with "ldap_id_mapping = false", "use_fully_qualified_names  = False" and start SSSD
        3. Override username to root and set override attributes to root values
        4. Restart SSSD
    :steps:
        1. Lookup the root user and check his uid and gid
        2. Lookup the root user and use the sss service
        3. Lookup user and check his uid and gid
    :expectedresults:
        1. The root user uid and gid has not been modified
        2. root user is not found
        3. User found and uid and gid is not roots
    :customerscenario: False
    """
    provider.user("user1").add(uid=999011, gid=999011)
    provider.user("root").add(uid=999012, gid=999012)
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.domain["use_fully_qualified_names"] = "False"
    client.sssd.start()
    client.sss_override.user("user1").add(name="root", uid=0, gid=0)

    client.sssd.restart()

    result = client.tools.getent.passwd("root")
    assert result is not None, "root user not found!"
    assert result.uid == 0, f"root uid {result.uid} is not 0!"
    assert result.gid == 0, f"root gid{result.gid} is not 0!"

    # Root should be filtered out from any service other than files
    assert client.tools.getent.passwd("root", service="sss") is None, "root user is found!"

    result = client.tools.getent.passwd("user1")
    assert result is not None, "user1 not found!"
    assert result.uid != 0, f"User uid {result.uid} is 0!"
    assert result.gid != 0, f"User gid {result.gid} is 0!"


@pytest.mark.importance("medium")
@pytest.mark.topology([KnownTopology.LDAP, KnownTopology.AD, KnownTopology.Samba])
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_sss_override__export_then_import_override_data(client: Client, provider: GenericProvider):
    """
        :title: Export then  import override data
    :setup:
        1. Create user, groups and start SSSD
        2. Create user and group overrides and restart SSSD
    :steps:
        1. Export user and group local overrides data to a file
        2. Delete overrides and restart SSSD
        3. Import user and group local overrides data and restart SSSD
        4. Search for user and group local overrides
    :expectedresults:
        1. Local overrides user and group data is exported to a file
        2. SSSD is restarted and overrides data is gone
        3. User and group local override data has been imported from the export
        4. User and group local overrides are found
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: import export user override
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )
    provider.group("group1").add(gid=999999)
    client.sssd.start()
    client.sss_override.group("group1").add(name="o-group1")
    client.sss_override.user("user1").add(name="o-user1")
    client.sssd.restart()

    client.sss_override.export_data()
    client.sss_override.user("user1").delete()
    client.sss_override.group("group1").delete()
    client.sssd.restart()

    assert not client.sss_override.user("user1").get(), "Local overrides user 'user1' found!"
    assert not client.sss_override.group("group1").get(), "Local group overrides group 'group1' found!"
    assert (
        len(
            client.ldb.search(
                f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb",
                f"cn={client.sssd.default_domain},cn=sysdb",
                filter="objectClass=userOverride",
            ).items()
        )
        < 1
    ), "Override database is not empty!"

    client.sss_override.import_data()
    client.sssd.restart()

    assert client.sss_override.user("user1").get(["name"]) == {
        "name": ["o-user1"]
    }, "No local override found for 'user1'!"
    assert client.sss_override.group("group1").get(["name"]) == {
        "name": ["o-group1"]
    }, "No local override found for 'group1'!"

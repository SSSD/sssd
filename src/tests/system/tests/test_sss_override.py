"""
Local Override "sss_override" Tests.

Note: IPA does not support this feature because, it manages user and group overrides using ID views on the IPA master.

:requirement:  IDM-SSSD-TC: ldap_provider: local_overrides
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__overriding_username_and_posix_attributes(client: Client, provider: GenericProvider):
    """
    :title: Locally overriding the name and POSIX attributes of a user
    :setup:
        1. Create POSIX user "user1"
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
        3. Create local override for "user1"
        4. Restart SSSD, this is necessary to enable local overrides
    :steps:
        1. Authenticate as "user1", then as the override name, use the short and fully qualified name
        2. Lookup user by the overridden name, check the uid and gid
        3. Override user's uid, gid and homedir and lookup user by both names, check the uid and gid
    :expectedresults:
        1. Users logins are successful
        2. User is found and uid and gid match original values
        3. User is found using both names and uid, gid and homedir match the new values
    :customerscenario: False
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )

    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    client.sss_override.user("user1").add(name="o-user1")

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123"), "Failed login!"
    assert client.auth.ssh.password(
        f"user1@{client.sssd.default_domain}", "Secret123"
    ), "Fully qualified name failed login!"

    assert client.auth.ssh.password("o-user1", "Secret123"), "Override name failed login!"
    assert client.auth.ssh.password(
        f"o-user1@{client.sssd.default_domain}", "Secret123"
    ), "Override fully qualified name failed login!"

    result = client.tools.getent.passwd("o-user1")
    assert result is not None, "User not found by override name!"
    assert result.uid == 999011, "User's uid does not match original value!"
    assert result.gid == 999011, "User's gid does not match original value!"

    client.sss_override.user("user1").add(name="o-user1", uid=999999, gid=888888, home="/home/o-user1")

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User not found!"
    assert result.uid == 999999, "User's uid does not match override value!"
    assert result.gid == 888888, "User's gid does not match override value!"
    assert result.home == "/home/o-user1", "User's homedir does not match override value!"

    result = client.tools.getent.passwd("o-user1")
    assert result is not None, "User not found by override name!"
    assert result.uid == 999999, "Local override uid does not match override value!"
    assert result.gid == 888888, "Local override gid does not match override value!"
    assert result.home == "/home/o-user1", "User's override name homedir does not match override value!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__overriding_group_name_and_gid(client: Client, provider: GenericProvider):
    """
    :title: Locally overriding the name and GID of a group
    :setup:
        1. Create POSIX group "group1"
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
        3. Create local override for "group1"
        4. Restart SSSD, this is necessary to enable local overrides
    :steps:
        1. Lookup group name and overridden name and check gid
        2. Override group gid to a new value, lookup group name by both names and check gid
    :expectedresults:
        1. Groups are found and gid match original values
        2. Groups are found and gid matches new overridden value
    :customerscenario: False
    """
    provider.group("group1").add(gid=999999)
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    group = client.sss_override.group("group1")

    group.add(name="o-group1")

    client.sssd.restart()

    result = client.tools.getent.group("group1")
    assert result is not None, "Group not found!"
    assert result.gid == 999999, "Group gid does not match original value!"
    result = client.tools.getent.group("o-group1")
    assert result is not None, "Group not found by override name!"
    assert result.gid == 999999, "Local override gid does match original value! "

    group.add(name="o-group1", gid=888888)

    result = client.tools.getent.group("group1")
    assert result is not None, "Group not found!"
    assert result.gid == 888888, "Group gid does not match override value!"

    result = client.tools.getent.group("o-group1")
    assert result is not None, "Group not found by override name!"
    assert result.gid == 888888, "Local override gid does not match override value!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__root_uid_gid_cannot_be_used(client: Client, provider: GenericProvider):
    """
    :title: Root user UID/GID cannot be overridden
    :setup:
        1. Create POSIX user "user1" and "root"
        2. Configure SSSD with "use_fully_qualified_names = false" and start SSSD
        3. Create local override for "user1" and name it "root" root, set the uid/gid to '0'
        4. Restart SSSD, this is necessary to enable local overrides
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
    assert result.uid == 0, "root uid is not 0"
    assert result.gid == 0, "root gid is not 0"

    # Root should be filtered out from any service other than files
    assert client.tools.getent.passwd("root", service="sss") is None, "root user is found!"

    result = client.tools.getent.passwd("user1")
    assert result is not None, "user1 not found!"
    assert result.uid != 0, "User uid is 0!"
    assert result.gid != 0, "User gid is 0!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__export_then_import_user_and_group_override_data(client: Client, provider: GenericProvider):
    """
        :title: Export and import the user and group local override data
    :setup:
        1. Create posix user "user1" with posix attributes defined
        2. Start SSSD
    :steps:
        1. Override user "user1" to "o-user1"
        2. Restart SSSD, this is necessary to enable local overrides
        3. Override group "group1" to "o-group1"
        4. Export user and group local overrides data to a file
        5. Delete overrides and restart SSSD
        6. Import user and group local overrides data and restart SSSD
        7. Search for user and group local overrides
    :expectedresults:
        1. User local override has been created
        2. SSSD has been restarted successfully
        3. Group local override has been created
        4. Local overrides user and group data is exported to a file
        5. SSSD is restarted and overrides data is gone
        6. User and group local override data has been imported from the export
        7. User and group local overrides is found
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: import export user override
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )
    provider.group("group1").add(gid=999999)
    client.sssd.start()

    user = client.sss_override.user("user1")
    group = client.sss_override.group("group1")
    override = client.sss_override

    user.add(name="o-user1")
    client.sssd.restart()
    group.add(name="o-group1")

    # local_override.export_data(users=None) exports all user data
    override.export_data()
    user.delete()
    group.delete()

    client.sssd.restart()
    assert not client.sss_override.user("user1").get()
    assert not client.sss_override.group("group1").get()

    assert (
        len(
            client.ldb.search(
                f"/var/lib/sss/db/cache_{client.sssd.default_domain}.ldb",
                f"cn={client.sssd.default_domain},cn=sysdb",
                filter="objectClass=userOverride",
            ).items()
        )
        < 1
    ), "Override is not empty!"

    client.sss_override.import_data()
    client.sssd.restart()

    assert client.sss_override.user("user1").get(["name"]) == {"name": ["o-user1"]}
    assert client.sss_override.group("group1").get(["name"]) == {"name": ["o-group1"]}


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1254184)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__use_fully_qualified_names_is_true(client: Client, provider: GenericProvider):
    """
    :title: Overriding user when use_fully_qualified_names is true
    :setup:
        1. Create user "user1"
        2. Edit SSSD configuration and set "use_fully_qualified_names" = True
        3. Start SSSD
        4. Create override for "user1"
        5. Restart SSSD, this is necessary to enable local overrides
    :steps:
        1. Login with the username and overridden name
        2. Login with the fully qualified username and overridden name
    :expectedresults:
        1. Logins fail
        2. Login succeed
    :customerscenario: False
    """
    provider.user("user1").add()
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()

    client.sss_override.user(f"user1@{client.sssd.default_domain}").add(name="o-user1")

    client.sssd.restart()

    assert not client.auth.ssh.password("user1", "Secret123"), "User logged in!"
    assert not client.auth.ssh.password("o-user1", "Secret123"), "User logged in!"
    assert client.auth.ssh.password(f"user1@{client.sssd.default_domain}", "Secret123"), "Login failed!"
    assert client.auth.ssh.password(f"o-user1@{client.sssd.default_domain}", "Secret123"), "Login failed!"

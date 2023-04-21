from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__overriding_username_and_posix_attributes(client: Client, provider: GenericProvider):
    """
    :title: Locally overriding the name and POSIX attributes of a user
    :setup:
        1. Create POSIX user "user1" with standard POSIX attributes defined
        2. Start SSSD
    :steps:
        1. Create local override for "user1" and name it "o-user1"
        2. Restart SSSD, this is necessary to enable local overrides
        3. Authenticate as "user1", the short and fully qualified name
        4. Authenticate as "o-user1", the short and fully qualified name
        5. Query the user "user1" and then override the POSIX attributes
        6. Query the username "user1", and local override name, "o-user1"
    :expectedresults:
        1. Local override is created for "user1"
        2. SSSD has restarted successfully
        3. Authentication successful for both short and fully qualified name
        4. Authentication successful for both short and fully qualified name
        5. POSIX attributes for local override has been changed
        6. The name and overriden name is found and POSIX attributes are updated
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: simple user override
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )

    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    client.sss_override.user("user1").add(name="o-user1")

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123")
    assert client.auth.ssh.password(f"user1@{client.sssd.default_domain}", "Secret123")
    assert client.auth.ssh.password("o-user1", "Secret123")
    assert client.auth.ssh.password(f"o-user1@{client.sssd.default_domain}", "Secret123")

    result = client.tools.getent.passwd("o-user1")

    assert result is not None
    assert result.uid == 999011
    assert result.gid == 999011

    client.sss_override.user("user1").add(name="o-user1", uid=999999, gid=888888, home="/home/o-user1")

    result = client.tools.getent.passwd("user1")
    assert result is not None
    assert result.uid == 999999
    assert result.gid == 888888
    assert result.home == "/home/o-user1"

    result = client.tools.getent.passwd("o-user1")
    assert result is not None
    assert result.uid == 999999
    assert result.gid == 888888
    assert result.home == "/home/o-user1"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__overriding_group_name_and_gid(client: Client, provider: GenericProvider):
    """
    :title: Locally overriding the name and GID of a group
    :setup:
        1. Create group "group1" with posix attributes defined
        2. Start SSSD
    :steps:
        1. Create local override "group1" and name it "o-group1"
        2. Restart SSSD, this is necessary to enable local overrides
        3. Query groups by the local override name
        4. Override the GID for the group "group1"
        5. Query groups by the override name
    :expectedresults:
        1. Group local override is created
        2. SSSD has restarted successfully
        3. Group is found by the overriden name "o-group1"
        4. Local override POSIX attribute updated
        5. Group is found by the overriden name "o-group1" and GID changed
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: simple group override
    """
    provider.group("group1").add(gid=999999)
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    group = client.sss_override.group("group1")

    group.add(name="o-group1")

    client.sssd.restart()

    result = client.tools.getent.group("group1")
    assert result is not None
    assert result.gid == 999999
    assert client.tools.getent.group("o-group1")

    group.add(name="o-group1", gid=888888)

    assert client.tools.getent.group("group1")
    assert client.tools.getent.group("o-group1")


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__root_uid_gid_cannot_be_used(client: Client, provider: GenericProvider):
    """
    :title: Root user UID/GID cannot be overridden
    :setup:
        1. Create POSIX user "user1" with standard POSIX attributes defined
        2. Start SSSD
    :steps:
        1. Create local override "root" for user1 and set UID/GID to 0
        2. Restart SSSD, this is necessary to enable local overrides
        3. Query the root user
        4. Query the root user and use sss as the service
        5. Query the POSIX user that is overridden to the root user
    :expectedresults:
        1. Local override is created
        2. SSSD has restarted successfully
        3. The root user UID/GID has not been modified
        4. The override has no UID/GID attribute
        5. The POSIX user UID/GID has not been changed
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: root user override
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )
    client.sssd.domain["ldap_id_mapping"] = "False"
    client.sssd.start()

    client.sss_override.user("user1").add(name="root", uid=0, gid=0)

    client.sssd.restart()

    result = client.tools.getent.passwd("root")
    assert result is not None
    assert result.uid == 0
    assert result.gid == 0

    result = client.tools.getent.passwd("root", service="sss")
    assert result is None

    result = client.tools.getent.passwd("user1")
    assert result is not None


@pytest.mark.importance("high")
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
        5. Delete overrides
        6. Restart SSSD
        7. Import user and group local overrides data
        8. Restart SSSD
        9. Search for user and group local overrides
    :expectedresults:
        1. User local override has been created
        2. SSSD has been restarted successfully
        3. Group local override has been created
        4. Local overrides user and group data is exported to a file
        5. Local overrides are deleted
        6. SSSD has restarted successfully
        7. User and group local override data has been imported from the export
        8. SSSD has restarted successfully
        9. User and group local overrides are found
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
    client.sss_override.import_data()
    client.sssd.restart()

    assert client.sss_override.user("user1").get(["name"]) == {"name": ["o-user1"]}
    assert client.sss_override.group("group1").get(["name"]) == {"name": ["o-group1"]}


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1254184)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_sss_overrides__use_fully_qualified_names_is_true(client: Client, provider: GenericProvider):
    """
    :title: Overriding user when use_fully_qualified_names is true
    :setup:
        1. Create posix user "user1" with posix attributes defined
        2. Edit SSSD configuration and set "use_fully_qualified_names" = True
        3. Start SSSD
    :steps:
        1. Override "user1" to "o-user1"
        2. Restart SSSD, this is necessary to enable local overrides
        3. Authenticate as "user1", only the fully qualified name
        4. Authenticate as "o-user1", only the fully qualified name
    :expectedresults:
        1. User local override is created
        2. SSSD has restarted successfully
        3. Authentication successful
        4. Authentication successful
    :customerscenario: False
    :requirement: IDM-SSSD-TC: ldap_provider: local_overrides: regression 2757 override
    :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1254184
    """
    provider.user("user1").add(
        uid=999011, gid=999011, home="/home/user1", gecos="user", shell="/bin/bash", password="Secret123"
    )
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()

    client.sss_override.user(f"user1@{client.sssd.default_domain}").add(name="o-user1")

    client.sssd.restart()

    assert client.auth.ssh.password("user1", "Secret123") is False
    assert client.auth.ssh.password("o-user1", "Secret123") is False
    assert client.auth.ssh.password(f"user1@{client.sssd.default_domain}", "Secret123")
    assert client.auth.ssh.password(f"o-user1@{client.sssd.default_domain}", "Secret123")

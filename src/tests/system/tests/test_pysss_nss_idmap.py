"""
SSSD Python Client identity Lookups

:requirement: Python binding of libsss_nss_idmap.so
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology


def get_sid_name(provider: GenericProvider):
    if isinstance(provider, Samba):
        return "objectSid"
    elif isinstance(provider, AD):
        return "SID"
    elif isinstance(provider, IPA):
        return "ipaNTSecurityIdentifier"
    return None


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.IPA)
def test_user_operations(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a user in different ways
    :setup:
        1. Add 'user1'
        2. Start SSSD
        3. Determine UID and SID as a reference
    :steps:
        1. Lookup SID by name
        2. Lookup SID by user name
        3. Lookup SID by group name
        4. Lookup SID by ID
        5. Lookup SID by UID
        6. Lookup SID by GID
        7. Lookup ID by SID
        8. Lookup name by SID
    :expectedresults:
        1. success
        2. success
        3. no result
        4. success
        5. success
        6. no result
        7. success
        8. success
    :customerscenario: False
    """

    sid_name = get_sid_name(provider)
    assert sid_name is not None

    user = provider.user("user1").add()
    user_sid = user.get([sid_name])[sid_name][0]

    client.sssd.restart()

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' missing"
    assert result.name == user.name, f"'{user.name}' has wrong name {result.name}"
    user_id = result.uid

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyname("{user.name}"))'"""
    )
    assert output.stdout == "{'" + user.name + "': {'sid': '" + user_sid + "', 'type': 1}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyusername("{user.name}"))'"""
    )
    assert output.stdout == "{'" + user.name + "': {'sid': '" + user_sid + "', 'type': 1}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbygroupname("{user.name}"))'"""
    )
    assert output.stdout == "{}"

    output = client.host.conn.run(f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyid({user_id}))'")
    assert output.stdout == "{" + str(user_id) + ": {'sid': '" + user_sid + "', 'type': 1}}"

    output = client.host.conn.run(f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyuid({user_id}))'")
    assert output.stdout == "{" + str(user_id) + ": {'sid': '" + user_sid + "', 'type': 1}}"

    output = client.host.conn.run(f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbygid({user_id}))'")
    assert output.stdout == "{}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getidbysid("{user_sid}"))'"""
    )
    assert output.stdout == "{'" + user_sid + "': {'id': " + str(user_id) + ", 'type': 1}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getnamebysid("{user_sid}"))'"""
    )
    assert output.stdout == "{'" + user_sid + "': {'name': '" + user.name + "', 'type': 1}}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.IPA)
def test_group_operations(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a group in different ways
    :setup:
        1. Add 'group1'
        2. Start SSSD
        3. Determine GID and SID as a reference
    :steps:
        1. Lookup group SID by name
        2. Lookup group SID by group name
        3. Lookup group SID by user name
        4. Lookup group SID by ID
        5. Lookup group SID by GID
        6. Lookup group SID by UID
        7. Lookup ID by group SID
        8. Lookup name by group SID
    :expectedresults:
        1. success
        2. success
        3. no result
        4. success
        5. success
        6. no result
        7. success
        8. success
    :customerscenario: False
    """

    sid_name = get_sid_name(provider)
    assert sid_name is not None

    group = provider.group("group1").add()
    group_sid = group.get([sid_name])[sid_name][0]

    client.sssd.restart()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"'{group.name}' missing"
    assert result.name == group.name, f"'{group.name}' has wrong name {result.name}"
    group_id = result.gid

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyname("{group.name}"))'"""
    )
    assert output.stdout == "{'" + group.name + "': {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbygroupname("{group.name}"))'"""
    )
    assert output.stdout == "{'" + group.name + "': {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyusername("{group.name}"))'"""
    )
    assert output.stdout == "{}"

    output = client.host.conn.run(f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyid({group_id}))'")
    assert output.stdout == "{" + str(group_id) + ": {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbygid({group_id}))'"
    )
    assert output.stdout == "{" + str(group_id) + ": {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyuid({group_id}))'"
    )
    assert output.stdout == "{}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getidbysid("{group_sid}"))'"""
    )
    assert output.stdout == "{'" + group_sid + "': {'id': " + str(group_id) + ", 'type': 2}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getnamebysid("{group_sid}"))'"""
    )
    assert output.stdout == "{'" + group_sid + "': {'name': '" + group.name + "', 'type': 2}}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
def test_case_insensitive(client: Client, provider: GenericProvider):
    """
    :title: Lookup group with upper and lower case in the name
    :setup:
        1. Add 'Group1' with upper and lower case in the name
        2. Start SSSD
        3. Determine group SID as a reference
    :steps:
        1. Lookup group SID by original name
        2. Lookup group SID by lower case name
        3. Lookup name by SID
    :expectedresults:
        1. Success
        2. Success
        3. Success, result contains lower case name
    :customerscenario: False
    """

    sid_name = get_sid_name(provider)
    assert sid_name is not None

    group = provider.group("Group1").add()
    group_sid = group.get([sid_name])[sid_name][0]

    client.sssd.restart()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"'{group.name}' missing"
    assert result.name == group.name.lower(), f"'{group.name.lower()}' has wrong name {result.name}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyname("{group.name}"))'"""
    )
    assert output.stdout == "{'" + group.name + "': {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyname("{group.name.lower()}"))'"""
    )
    assert output.stdout == "{'" + group.name.lower() + "': {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getnamebysid("{group_sid}"))'"""
    )
    assert output.stdout == "{'" + group_sid + "': {'name': '" + group.name.lower() + "', 'type': 2}}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
def test_ignore_unreadable_references(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of the user in different ways
    :setup:
        1. Add 'group1' and 'group2' to AD
        2. Make 'group2' a member of 'group1'
        3. Remove 'ReadProperty' for 'Domain Computers' from 'group2' so that
           it will be inaccessible for SSSD
        4. Restart SSSD and check that 'group1' lookup fails
        5. Add 'ldap_ignore_unreadable_references = True' to SSSD configuration
           and restart SSSD
        6. Determine group_sid and group_id for reference
    :steps:
        1. Lookup group SID by name
        2. Lookup group SID by ID
        3. Lookup group SID by GID
        4. Lookup group SID by UID
        5. Lookup ID by group SID
        6. Lookup name by group SID
    :expectedresults:
        1. success
        2. success
        3. success
        4. no result
        5. success
        6. success
    :customerscenario: False
    """

    sid_name = get_sid_name(provider)
    assert sid_name is not None

    group = provider.group("group1").add()

    group2 = provider.group("group2").add()
    group.add_member(group2)

    provider.host.conn.run(
        f"""
        # Remove read access for 'Domain Computers' group from the group member
        Import-Module ActiveDirectory
        $my_group = Get-ADGroup("{group2.name}")
        $domain_computers = New-Object System.Security.Principal.NTAccount("Domain Computers")
        $acl = new-object System.DirectoryServices.ActiveDirectoryAccessRule($domain_computers, "ReadProperty", "Deny")
        $path = "LDAP://" + $my_group.DistinguishedName
        $adsi_group = [ADSI]"$path"
        $adsi_group.psbase.get_objectSecurity().AddAccessRule($acl)
        $adsi_group.psbase.CommitChanges()
        """
    )
    client.sssd.restart()

    result = client.tools.getent.group(group.name)
    assert result is None, f"'{group.name}' found unexpectedly"

    client.sssd.domain["ldap_ignore_unreadable_references"] = "True"
    client.sssd.config_apply
    client.sssd.restart()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"'{group.name}' missing"
    assert result.name == group.name, f"'{group.name}' has wrong name {result.name}"
    group_sid = group.get([sid_name])[sid_name][0]
    group_id = result.gid

    output = client.host.conn.run(
        f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyname("{group.name}"))'"""
    )
    assert output.stdout == "{'" + group.name + "': {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyid({group_id}))'")
    assert output.stdout == "{" + str(group_id) + ": {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbygid({group_id}))'"
    )
    assert output.stdout == "{" + str(group_id) + ": {'sid': '" + group_sid + "', 'type': 2}}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getsidbyuid({group_id}))'"
    )
    assert output.stdout == "{}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getidbysid(\"{group_sid}\"))'"
    )
    assert output.stdout == "{'" + group_sid + "': {'id': " + str(group_id) + ", 'type': 2}}"

    output = client.host.conn.run(
        f"python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.getnamebysid(\"{group_sid}\"))'"
    )
    assert output.stdout == "{'" + group_sid + "': {'name': '" + group.name + "', 'type': 2}}"

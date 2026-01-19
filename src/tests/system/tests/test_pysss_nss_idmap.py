"""
SSSD Python Client identity Lookups

:requirement: Python binding of libsss_nss_idmap.so
"""

from __future__ import annotations

import ast

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


def get_sid_name(provider: GenericProvider):
    if isinstance(provider, Samba):
        return "objectSid"
    elif isinstance(provider, AD):
        return "SID"
    elif isinstance(provider, IPA):
        return "ipaNTSecurityIdentifier"
    return None


def user_setup(provider: GenericProvider, client: Client):
    sid_name = get_sid_name(provider)
    assert sid_name is not None

    user = provider.user("user1").add()
    user_sid = user.get([sid_name])[sid_name][0]

    client.sssd.restart()

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' missing"
    assert result.name == user.name, f"'{user.name}' has wrong name {result.name}"
    user_id = result.uid

    return (user, user_id, user_sid)


def group_setup(provider: GenericProvider, client: Client):
    sid_name = get_sid_name(provider)
    assert sid_name is not None

    group = provider.group("group1").add()
    group_sid = group.get([sid_name])[sid_name][0]

    client.sssd.restart()

    result = client.tools.getent.group(group.name)
    assert result is not None, f"'{group.name}' missing"
    assert result.name == group.name, f"'{group.name}' has wrong name {result.name}"
    group_id = result.gid

    return (group, group_id, group_sid)


def run_pysss_nss_idmap(client: Client, command: str, input):
    if isinstance(input, str):
        input = f'"{input}"'

    return client.host.conn.run(f"""python -c 'import pysss_nss_idmap; print(pysss_nss_idmap.{command}({input}))'""")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_user_by_name(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a user by name
    :setup:
        1. Add user and start SSSD
    :steps:
        1. Lookup SID by name and user name
        2. Lookup SID by group name
    :expectedresults:
        1. User found
        2. User not found
    :customerscenario: False
    """

    user, user_id, user_sid = user_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getsidbyname", user.name)
    assert ast.literal_eval(output.stdout) == {user.name: {"sid": user_sid, "type": 1}}

    output = run_pysss_nss_idmap(client, "getsidbyusername", user.name)
    assert ast.literal_eval(output.stdout) == {user.name: {"sid": user_sid, "type": 1}}

    output = run_pysss_nss_idmap(client, "getsidbygroupname", user.name)
    assert ast.literal_eval(output.stdout) == {}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_user_by_id(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a user by ID
    :setup:
        1. Add user and start SSSD
    :steps:
        1. Lookup SID by ID and UID
        2. Lookup SID by GID
    :expectedresults:
        1. User found
        2. User not found
    :customerscenario: False
    """

    user, user_id, user_sid = user_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getsidbyid", user_id)
    assert ast.literal_eval(output.stdout) == {user_id: {"sid": user_sid, "type": 1}}

    output = run_pysss_nss_idmap(client, "getsidbyuid", user_id)
    assert ast.literal_eval(output.stdout) == {user_id: {"sid": user_sid, "type": 1}}

    output = run_pysss_nss_idmap(client, "getsidbygid", user_id)
    assert ast.literal_eval(output.stdout) == {}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_user_by_sid(client: Client, provider: GenericProvider):
    """
    :title: Lookup the name and and ID of a user by SID
    :setup:
        1. Add user and start SSSD
    :steps:
        1. Lookup ID and name by SID
    :expectedresults:
        1. User found
    :customerscenario: False
    """

    user, user_id, user_sid = user_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getidbysid", user_sid)
    assert ast.literal_eval(output.stdout) == {user_sid: {"id": user_id, "type": 1}}

    output = run_pysss_nss_idmap(client, "getnamebysid", user_sid)
    assert ast.literal_eval(output.stdout) == {user_sid: {"name": user.name, "type": 1}}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_group_by_name(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a group by name
    :setup:
        1. Add group and start SSSD
    :steps:
        1. Lookup SID by name and group name
        2. Lookup SID by user name
    :expectedresults:
        1. Group found
        2. Group not found
    :customerscenario: False
    """

    group, group_id, group_sid = group_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getsidbyname", group.name)
    assert ast.literal_eval(output.stdout) == {group.name: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbygroupname", group.name)
    assert ast.literal_eval(output.stdout) == {group.name: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbyusername", group.name)
    assert ast.literal_eval(output.stdout) == {}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_group_by_id(client: Client, provider: GenericProvider):
    """
    :title: Lookup the SID of a group by ID
    :setup:
        1. Add group and start SSSD
    :steps:
        1. Lookup SID by ID and GID
        2. Lookup SID by UID
    :expectedresults:
        1. Group found
        2. Group not found
    :customerscenario: False
    """

    group, group_id, group_sid = group_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getsidbyid", group_id)
    assert ast.literal_eval(output.stdout) == {group_id: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbygid", group_id)
    assert ast.literal_eval(output.stdout) == {group_id: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbyuid", group_id)
    assert ast.literal_eval(output.stdout) == {}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyDC)
def test_group_by_sid(client: Client, provider: GenericProvider):
    """
    :title: Lookup the name and and ID of a user by SID
    :setup:
        1. Add user and start SSSD
    :steps:
        1. Lookup ID and name by SID
    :expectedresults:
        1. Group found
    :customerscenario: False
    """

    group, group_id, group_sid = group_setup(provider, client)

    output = run_pysss_nss_idmap(client, "getidbysid", group_sid)
    assert ast.literal_eval(output.stdout) == {group_sid: {"id": group_id, "type": 2}}

    output = run_pysss_nss_idmap(client, "getnamebysid", group_sid)
    assert ast.literal_eval(output.stdout) == {group_sid: {"name": group.name, "type": 2}}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
def test_case_insensitive(client: Client, provider: GenericProvider):
    """
    :title: Lookup group with upper and lower case in the name
    :setup:
        1. Add 'Group1' with upper and lower case in the name and start SSSD
    :steps:
        1. Lookup group SID by original and lower case name
        2. Lookup name by SID
    :expectedresults:
        1. Group found
        2. Group found, result contains lower case name
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

    output = run_pysss_nss_idmap(client, "getsidbyname", group.name)
    assert ast.literal_eval(output.stdout) == {group.name: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbyname", group.name.lower())
    assert ast.literal_eval(output.stdout) == {group.name.lower(): {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getnamebysid", group_sid)
    assert ast.literal_eval(output.stdout) == {group_sid: {"name": group.name.lower(), "type": 2}}


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
def test_ignore_unreadable_references(client: Client, provider: GenericProvider):
    """
    :title: Make sure unreadable references are ignored while reading nested groups
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
        1. Lookup group SID by name, ID, GID
        2. Lookup group SID by UID
        3. Lookup ID and name by group SID
    :expectedresults:
        1. Group found
        2. Group not found
        3. Group found
    :customerscenario: False
    """

    sid_name = get_sid_name(provider)
    assert sid_name is not None

    group = provider.group("group1").add()

    group2 = provider.group("group2").add()
    group.add_member(group2)

    provider.host.conn.run(f"""
        # Remove read access for 'Domain Computers' group from the group member
        Import-Module ActiveDirectory
        $my_group = Get-ADGroup("{group2.name}")
        $domain_computers = New-Object System.Security.Principal.NTAccount("Domain Computers")
        $acl = new-object System.DirectoryServices.ActiveDirectoryAccessRule($domain_computers, "ReadProperty", "Deny")
        $path = "LDAP://" + $my_group.DistinguishedName
        $adsi_group = [ADSI]"$path"
        $adsi_group.psbase.get_objectSecurity().AddAccessRule($acl)
        $adsi_group.psbase.CommitChanges()
        """)
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

    output = run_pysss_nss_idmap(client, "getsidbyname", group.name)
    assert ast.literal_eval(output.stdout) == {group.name: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbyid", group_id)
    assert ast.literal_eval(output.stdout) == {group_id: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbygid", group_id)
    assert ast.literal_eval(output.stdout) == {group_id: {"sid": group_sid, "type": 2}}

    output = run_pysss_nss_idmap(client, "getsidbyuid", group_id)
    assert ast.literal_eval(output.stdout) == {}

    output = run_pysss_nss_idmap(client, "getidbysid", group_sid)
    assert ast.literal_eval(output.stdout) == {group_sid: {"id": group_id, "type": 2}}

    output = run_pysss_nss_idmap(client, "getnamebysid", group_sid)
    assert ast.literal_eval(output.stdout) == {group_sid: {"name": group.name, "type": 2}}

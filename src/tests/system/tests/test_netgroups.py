"""
Netgroup tests.

:requirement: netgroup
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("medium")
@pytest.mark.cache
@pytest.mark.ticket(gh=6652, bz=2162552)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroups__add_remove_netgroup_triple(client: Client, provider: GenericProvider):
    """
    :title: Netgroup triple is correctly removed from cached record
    :setup:
        1. Create local user "user-1"
        2. Create netgroup "ng-1"
        3. Add "(-,user-1,)" triple to the netgroup
        4. Start SSSD
    :steps:
        1. Run "getent netgroup ng-1"
        2. Remove "(-,user-1,)" triple from "ng-1"
        3. Invalidate netgroup in cache "sssctl cache-expire -n ng-1"
        4. Run "getent netgroup ng-1"
    :expectedresults:
        1. "(-,user-1,)" is present in the netgroup
        2. Triple was removed from the netgroup
        3. Cached record was invalidated
        4. "(-,user-1,)" is not present in the netgroup
    :customerscenario: True
    """
    user = provider.user("user-1").add()
    ng = provider.netgroup("ng-1").add().add_member(user=user)

    client.sssd.start()

    result = client.tools.getent.netgroup("ng-1")
    assert result is not None
    assert result.name == "ng-1"
    assert len(result.members) == 1
    assert "(-, user-1)" in result.members

    ng.remove_member(user=user)
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-1")
    assert result is not None
    assert result.name == "ng-1"
    assert len(result.members) == 0


@pytest.mark.importance("medium")
@pytest.mark.cache
@pytest.mark.ticket(gh=6652, bz=2162552)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroups__add_remove_netgroup_member(client: Client, provider: GenericProvider):
    """
    :title: Netgroup member is correctly removed from cached record
    :setup:
        1. Create local user "user-1"
        2. Create local user "user-2"
        3. Create netgroup "ng-1"
        4. Create netgroup "ng-2"
        5. Add "(-,user-1,)" triple to the netgroup "ng-1"
        6. Add "(-,user-2,)" triple to the netgroup "ng-2"
        7. Add "ng-1" as a member to "ng-2"
        8. Start SSSD
    :steps:
        1. Run "getent netgroup ng-2"
        2. Remove "ng-1" from "ng-2"
        3. Invalidate netgroup "ng-2" in cache "sssctl cache-expire -n ng-2"
        4. Run "getent netgroup ng-2"
    :expectedresults:
        1. "(-,user-1,)", "(-,user-2,)" is present in the netgroup
        2. Netgroup member was removed from the netgroup
        3. Cached record was invalidated
        4. "(-,user-1,)" is not present in the netgroup, only "(-,user-2,)"
    :customerscenario: True
    """
    u1 = provider.user("user-1").add()
    u2 = provider.user("user-2").add()

    ng1 = provider.netgroup("ng-1").add().add_member(user=u1)
    ng2 = provider.netgroup("ng-2").add().add_member(user=u2, ng=ng1)

    client.sssd.start()

    result = client.tools.getent.netgroup("ng-2")
    assert result is not None
    assert result.name == "ng-2"
    assert len(result.members) == 2
    assert "(-, user-1)" in result.members
    assert "(-, user-2)" in result.members

    ng2.remove_member(ng=ng1)
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-2")
    assert result is not None
    assert result.name == "ng-2"
    assert len(result.members) == 1
    assert "(-, user-1)" not in result.members
    assert "(-, user-2)" in result.members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__user_attribute_membernisnetgroup_uses_group_dn(client: Client, provider: GenericProvider):
    """
    :title: User's 'memberNisNetgroup' attribute values are the DN of the group
    :setup:
        1. Create users and groups
        2. Create a new netgroup "group" and add a member (ng1)
        3. Create another netgroup "nested_group" and add a member (ng2)
        4. Modify the "nested_group" to replace its members with the members of group
        5. Start SSSD
    :steps:
        1. Retrieve all members of the "nested_group"
        2. Confirm that the member directly added to "nested_group" is present
        3. Confirm that the member from "group" is now part of "nested_group"
    :expectedresults:
        1. All members should be retrieved
        2. Members directly added to "nested_group" is present
        3. Members from group is now part of "nested_group"
    :customerscenario: False
    """
    if not isinstance(provider, (LDAP, Samba, AD)):
        raise ValueError("IPA does not support domain in netgroups")
    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_group = provider.netgroup("group").add()
    netgroup_group.add_member(host="testhost1", user="ng1", domain="ldap.test")

    netgroup_nested = provider.netgroup("nested_group").add()
    netgroup_nested.add_member(host="testhost2", user="ng2", domain="ldap.test")
    netgroup_nested.add_member(ng="group")
    client.sssd.start()

    result = client.tools.getent.netgroup("nested_group")
    assert result is not None
    assert "(testhost2, ng2, ldap.test)" in result.members
    assert "(testhost1, ng1, ldap.test)" in result.members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__lookup_nested_groups(client: Client, provider: GenericProvider):
    """
    :title: Looking up nested netgroups
    :setup:
        1. Create users and groups
        2. Create netgroups and add members
        3. Add members to "nested_netgroup"
        4. Make "netgroup" and "nested_netgroup" members of one another, looping the groups
        5. Start SSSD
    :steps:
        1. Lookup "nested_netgroup"
    :expectedresults:
        1. Netgroup is found and both netgroups and users are members
    :customerscenario: False
    """
    if not isinstance(provider, (LDAP, Samba, AD)):
        raise ValueError("IPA does not support domain in netgroups")
    for id in [1, 2, 3]:
        provider.user(f"ng{id}").add()

    netgroup = provider.netgroup("group").add()
    netgroup.add_member(host="testhost1", user="ng1", domain="ldap.test")

    nested_netgroup = provider.netgroup("nested_netgroup").add()
    nested_netgroup.add_member(ng=netgroup)
    nested_netgroup.add_member(host="testhost2", user="ng2", domain="ldap.test")
    nested_netgroup.add_member(user="ng3")

    netgroup.add_member(ng=nested_netgroup)

    client.sssd.start()

    result = client.tools.getent.netgroup("nested_netgroup")
    assert result is not None
    assert "(testhost1,ng1,ldap.test)" in result.members
    assert "(-,ng3,)" in result.members
    assert "(testhost2,ng2,ldap.test)" in result.members


@pytest.mark.parametrize(
    "user, domain, expected",
    [("host", "host.ldap.test", "(host,-,host.ldap.test)"), ("ng3", "", "(-,ng3,)")],
)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__lookup_nested_groups_with_host_and_domain_values_present(
    client: Client, provider: GenericProvider, user: str, domain: str, expected: str
):
    """
    :title: Netgroup contains a member that has a host and domain specified
    :setup:
        1. Create users and groups
        2. Create netgroups and add members
        3. Start SSSD
    :steps:
        1. Lookup netgroup "nested_group"
    :expectedresults:
        1. Member is present in the "nested_group"
    :customerscenario: False
    """
    if not isinstance(provider, (LDAP, Samba, AD)):
        raise ValueError("IPA does not support domain in netgroups")
    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_group = provider.netgroup("group").add()
    netgroup_group.add_member(host="testhost1", user="ng1", domain="ldap.test")

    netgroup_nested = provider.netgroup("nested_group").add()
    netgroup_nested.add_member(host="testhost2", user="ng2", domain="ldap.test")
    if domain == "host.ldap.test":
        netgroup_nested.add_member(host=user, domain=domain)
    else:
        netgroup_nested.add_member(user=user)

    client.sssd.start()

    result = client.tools.getent.netgroup("nested_group")
    assert result is not None
    assert expected in result.members


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=802207)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__fully_qualified_names(client: Client, provider: GenericProvider):
    """
    :title: Netgroups with fully qualified names resolves and contains the members
    :setup:
        1. Configure SSSD domain to use fully qualified names
        2. Create user "user-1"
        3. A netgroup named "ng-1" is created, "user-1" is added to this netgroup
    :steps:
        1. Verify the existence and membership of the netgroup "ng-1"
    :expectedresults:
        1. SSSD should return netgroup "ng-1" and members of the netgroup
    :customerscenario: True
    """
    client.sssd.dom("test")["use_fully_qualified_names"] = "true"
    user = provider.user("user-1").add()
    provider.netgroup("ng-1").add().add_member(user=user)
    client.sssd.start()

    result = client.tools.getent.netgroup("ng-1")
    assert result is not None and result.name == "ng-1", "'ng-1' Netgroup name did not match '{result.name}'"
    assert len(result.members) == 1, "'ng-1' contains more than 1 member!"
    assert "(-, user-1)" in result.members, "'ng-1' members did not match the expected ones!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=645449)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__uid_gt_2147483647(client: Client, provider: GenericProvider):
    """
    :title: SSSD resolves users and groups with id greater than 2147483647 (Integer.MAX_VALUE)
    :setup:
        1. Users are added with large uid values
        2. Groups are added with large gid values
    :steps:
        1. Check that SSSD resolves users and groups
    :expectedresults:
        1. Users and groups are resolved
    :customerscenario: True
    """
    if not isinstance(provider, (LDAP, Samba, AD)):
        pytest.skip("For ipa, 'uid': can be at most 2147483647")

    client.sssd.start()

    for name, uid in [("bigusera", 2147483646), ("biguserb", 2147483647), ("biguserc", 2147483648)]:
        provider.user(name).add(uid=uid, gid=uid, password="Secret123")
    for name, uid in [
        ("biggroup1", 2147483646),
        ("biggroup2", 2147483647),
        ("biggroup3", 2147483648),
    ]:
        provider.group(name).add(gid=uid)

    for username in ["bigusera", "biguserb", "biguserc"]:
        result = client.tools.getent.passwd(username)
        assert result is not None, f"getent passwd for user '{username}' is empty!"
        assert result.name == username, f"User name '{username}' did not match result '{result.name}'!"
    for grpname in ["biggroup1", "biggroup2", "biggroup3"]:
        result = client.tools.getent.group(grpname)
        assert result is not None, f"getent group for group '{grpname}' is empty!"
        assert result.name == grpname, f"Group name '{grpname}' did not match result '{result.name}'!"

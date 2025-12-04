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
def test_netgroup__user_attribute_membernisnetgroup_uses_group_dn(client: Client, provider: AD | LDAP | Samba):
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
    domain = provider.domain

    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_group = provider.netgroup("group").add()
    netgroup_group.add_member(host="testhost1", user="ng1", domain=domain)

    netgroup_nested = provider.netgroup("nested_group").add()
    netgroup_nested.add_member(host="testhost2", user="ng2", domain=domain)
    netgroup_nested.add_member(ng="group")
    client.sssd.start()

    result = client.tools.getent.netgroup("nested_group")
    assert result is not None
    assert f"(testhost2, ng2, {domain})" in result.members
    assert f"(testhost1, ng1, {domain})" in result.members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__lookup_nested_groups(client: Client, provider: AD | LDAP | Samba):
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
    domain = provider.domain

    for id in [1, 2, 3]:
        provider.user(f"ng{id}").add()

    netgroup = provider.netgroup("group").add()
    netgroup.add_member(host="testhost1", user="ng1", domain=domain)

    nested_netgroup = provider.netgroup("nested_netgroup").add()
    nested_netgroup.add_member(ng="group")
    nested_netgroup.add_member(host="testhost2", user="ng2", domain=domain)
    nested_netgroup.add_member(user="ng3")

    netgroup.add_member(ng="nested_netgroup")

    client.sssd.start()

    result = client.tools.getent.netgroup("nested_netgroup")
    assert result is not None
    assert f"(testhost1,ng1,{domain})" in result.members
    assert "(-,ng3,)" in result.members
    assert f"(testhost2,ng2,{domain})" in result.members


@pytest.mark.parametrize(
    "use_host_domain, expected_suffix",
    [
        pytest.param(True, "(host,-,host.{domain})", id="with-host-domain"),
        pytest.param(False, "(-,ng3,)", id="without-domain"),
    ],
)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__lookup_nested_groups_with_host_and_domain_values_present(
    client: Client, provider: AD | LDAP | Samba, use_host_domain: bool, expected_suffix: str
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
    domain = provider.domain
    expected = expected_suffix.format(domain=domain)

    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_group = provider.netgroup("group").add()
    netgroup_group.add_member(host="testhost1", user="ng1", domain=domain)

    netgroup_nested = provider.netgroup("nested_group").add()
    netgroup_nested.add_member(host="testhost2", user="ng2", domain=domain)
    if use_host_domain:
        netgroup_nested.add_member(host="host", domain=f"host.{domain}")
    else:
        netgroup_nested.add_member(user="ng3")

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
def test_netgroup__uid_gt_2147483647(client: Client, provider: AD | LDAP | Samba):
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
        passwd_result = client.tools.getent.passwd(username)
        assert passwd_result is not None, f"getent passwd for user '{username}' is empty!"
        assert passwd_result.name == username, f"User name '{username}' did not match!"
    for grpname in ["biggroup1", "biggroup2", "biggroup3"]:
        group_result = client.tools.getent.group(grpname)
        assert group_result is not None, f"getent group for group '{grpname}' is empty!"
        assert group_result.name == grpname, f"Group name '{grpname}' did not match!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__incomplete_triples(client: Client, provider: AD | LDAP | Samba):
    """
    :title: Netgroups with incomplete triples
    :description: Netgroups with incomplete triples can be created and used.
    :setup:
        1. Create an empty netgroup
        2. Create a netgroup with only host
        3. Create a netgroup with only user
        4. Create a netgroup with only domain
        5. Create a netgroup with missing host
        6. Create a netgroup with missing user
        7. Create a netgroup with missing domain
        8. Start SSSD
    :steps:
        1. Show the netgroups
    :expectedresults:
        1. Netgroups are shown and match the expectations
    :customerscenario: False
    """
    domain = provider.domain

    # (setup_params, expected_members)
    cases = {
        "ng-empty": ({}, set()),
        "ng-only-host": ({"host": "testhost"}, {"(testhost,-,)"}),
        "ng-only-user": ({"user": "testuser"}, {"(-,testuser,)"}),
        "ng-only-domain": ({"domain": domain}, {f"(-,-,{domain})"}),
        "ng-missing-host": (
            {"user": "testuser", "domain": domain},
            {f"(-,testuser,{domain})"},
        ),
        "ng-missing-user": (
            {"host": "testhost", "domain": domain},
            {f"(testhost,-,{domain})"},
        ),
        "ng-missing-domain": (
            {"host": "testhost", "user": "testuser"},
            {"(testhost,testuser,)"},
        ),
    }

    for name, (params, _) in cases.items():
        ng = provider.netgroup(name).add()
        if params:
            ng.add_member(**params)

    client.sssd.start()

    for name, (_, expected) in cases.items():
        result = client.tools.getent.netgroup(name)
        assert result is not None, f"Netgroup '{name}' not found!"
        assert result.name == name
        actual = {str(m) for m in result.members}
        assert actual == expected, f"Netgroup '{name}': expected {expected}, got {actual}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroups__complex_hierarchy(client: Client, provider: AD | LDAP | Samba):
    """
    :title: Complex netgroup hierarchy
    :description: Netgroups with multiple levels of nesting work correctly
    :setup:
        1. Create multiple netgroups with various combinations of triples
           and nested members
        2. Create complex hierarchy with mixed triples and netgroup members
        3. Start SSSD
    :steps:
        1. Query each netgroup in the hierarchy
    :expectedresults:
        1. Each netgroup returns correct combination of direct triples
           and inherited members
    :customerscenario: False
    """
    # Hierarchy:
    # ng-top -> ng-mid1 -> ng-base1
    #        -> ng-mid2 -> ng-base2
    #                   -> ng-base3

    domain = provider.domain

    # Level 1: Base netgroups with only triples (no nested members)
    provider.netgroup("ng-base1").add().add_member(host="host1", user="user1", domain=domain)
    provider.netgroup("ng-base2").add().add_member(host="host2", user="user2", domain=domain)
    provider.netgroup("ng-base3").add().add_member(user="user3")

    # Level 2: Mid-level netgroups with both triples and nested members
    ng_mid1 = provider.netgroup("ng-mid1").add()
    ng_mid1.add_member(host="host4", user="user4", domain=domain)
    ng_mid1.add_member(ng="ng-base1")

    ng_mid2 = provider.netgroup("ng-mid2").add()
    ng_mid2.add_member(user="user5")
    ng_mid2.add_member(ng="ng-base2")
    ng_mid2.add_member(ng="ng-base3")

    # Level 3: Top-level netgroup containing mid-level netgroups
    ng_top = provider.netgroup("ng-top").add()
    ng_top.add_member(host="host6", user="user6", domain=domain)
    ng_top.add_member(ng="ng-mid1")
    ng_top.add_member(ng="ng-mid2")

    client.sssd.start()

    # Verify base netgroups (Level 1)
    base_expectations = {
        "ng-base1": {f"(host1,user1,{domain})"},
        "ng-base2": {f"(host2,user2,{domain})"},
        "ng-base3": {"(-,user3,)"},
    }
    for name, expected in base_expectations.items():
        result = client.tools.getent.netgroup(name)
        assert result is not None, f"Netgroup '{name}' not found!"
        actual = {str(m) for m in result.members}
        assert actual == expected, f"Netgroup '{name}': expected {expected}, got {actual}"

    # Verify mid-level netgroups (Level 2)
    mid_expectations = {
        "ng-mid1": {
            f"(host4,user4,{domain})",
            f"(host1,user1,{domain})",
        },
        "ng-mid2": {
            "(-,user5,)",
            f"(host2,user2,{domain})",
            "(-,user3,)",
        },
    }
    for name, expected in mid_expectations.items():
        result = client.tools.getent.netgroup(name)
        assert result is not None, f"Netgroup '{name}' not found!"
        actual = {str(m) for m in result.members}
        assert actual == expected, f"Netgroup '{name}': expected {expected}, got {actual}"

    # Verify top-level netgroup (Level 3)
    result = client.tools.getent.netgroup("ng-top")
    assert result is not None, "Netgroup 'ng-top' not found!"
    expected = {
        f"(host6,user6,{domain})",
        f"(host4,user4,{domain})",
        f"(host1,user1,{domain})",
        "(-,user5,)",
        f"(host2,user2,{domain})",
        "(-,user3,)",
    }
    actual = {str(m) for m in result.members}
    assert actual == expected, f"Netgroup 'ng-top': expected {expected}, got {actual}"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroup__offline(client: Client, provider: AD | LDAP | Samba):
    """
    :title: Netgroup is accessible when backend goes offline
    :description:
        Verifies that netgroups cached by SSSD remain accessible when the
        backend server becomes unreachable. This ensures offline functionality
        works correctly for netgroup lookups.
    :setup:
        1. Create a netgroup with host, user, and domain triple
        2. Start SSSD
    :steps:
        1. Lookup the netgroup while backend is online
        2. Block network access to the backend and bring SSSD offline
        3. Lookup the netgroup again while offline
    :expectedresults:
        1. Netgroup is found with correct members
        2. SSSD transitions to offline mode
        3. Netgroup is still accessible from cache with same members
    :customerscenario: False
    """
    domain = provider.domain
    provider.user("user-1").add()
    provider.netgroup("ng-1").add().add_member(host="testhost", user="user-1", domain=domain)

    client.sssd.start()

    # Online lookup
    result = client.tools.getent.netgroup("ng-1")
    assert result is not None
    assert result.name == "ng-1"
    assert len(result.members) == 1
    assert f"(testhost, user-1, {domain})" in result.members

    # Bring backend offline
    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    # Offline lookup
    result = client.tools.getent.netgroup("ng-1")
    assert result is not None
    assert result.name == "ng-1"
    assert len(result.members) == 1
    assert f"(testhost, user-1, {domain})" in result.members


@pytest.mark.importance("medium")
@pytest.mark.cache
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroups__step_by_step_removal(client: Client, provider: AD | LDAP | Samba):
    """
    :title: Netgroup hierarchy updates correctly during step-by-step removal
    :description:
        Verifies that when netgroups are removed from a nested hierarchy,
        the cache is properly invalidated and the changes are reflected
        in subsequent lookups. Tests both removing a netgroup from its
        parent and deleting a netgroup entirely.
    :setup:
        1. Create user "user-1" and "user-2"
        2. Create nested netgroups: ng-parent contains ng-child
        3. Add user-1 to ng-child, user-2 to ng-parent
        4. Start SSSD
    :steps:
        1. Verify both users are visible in ng-parent lookup
        2. Remove ng-child from ng-parent and expire cache
        3. Verify ng-child still exists independently
        4. Delete ng-child entirely and expire cache
    :expectedresults:
        1. ng-parent shows user-1 and user-2
        2. ng-parent only shows user-2, ng-child still has user-1
        3. ng-child is accessible with user-1
        4. ng-child no longer exists
    :customerscenario: False
    """
    provider.user("user-1").add()
    provider.user("user-2").add()

    # Create nested structure: ng-parent -> ng-child -> user-1
    ng_child = provider.netgroup("ng-child").add().add_member(user="user-1")
    ng_parent = provider.netgroup("ng-parent").add().add_member(user="user-2", ng="ng-child")

    client.sssd.start()

    # Verify initial state
    result = client.tools.getent.netgroup("ng-parent")
    assert result is not None
    assert len(result.members) == 2
    assert "(-, user-1)" in result.members
    assert "(-, user-2)" in result.members

    result = client.tools.getent.netgroup("ng-child")
    assert result is not None
    assert len(result.members) == 1
    assert "(-, user-1)" in result.members

    # Remove ng-child from ng-parent
    ng_parent.remove_member(ng="ng-child")
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-parent")
    assert result is not None
    assert len(result.members) == 1
    assert "(-, user-1)" not in result.members
    assert "(-, user-2)" in result.members

    # ng-child should still exist independently
    result = client.tools.getent.netgroup("ng-child")
    assert result is not None
    assert len(result.members) == 1
    assert "(-, user-1)" in result.members

    # Delete ng-child entirely
    ng_child.delete()
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-child")
    assert result is None


@pytest.mark.importance("medium")
@pytest.mark.cache
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_netgroups__nested_modification(client: Client, provider: AD | LDAP | Samba):
    """
    :title: Modifications to nested netgroups propagate through hierarchy
    :description:
        Verifies that adding or removing members at any level of a nested
        netgroup hierarchy is correctly reflected when looking up the
        top-level netgroup. Tests a 3-level deep hierarchy where changes
        to middle and leaf netgroups affect the top-level view.
    :setup:
        1. Create users "user-1", "user-2", and "user-3"
        2. Create 3-level nested structure: ng-top -> ng-middle -> ng-leaf
        3. Add user-1 to ng-leaf, user-2 to ng-top
        4. Start SSSD
    :steps:
        1. Verify initial structure shows user-1 and user-2 via ng-top
        2. Add user-3 to ng-middle and expire cache
        3. Remove user-1 from ng-leaf and expire cache
    :expectedresults:
        1. ng-top lookup returns user-1 and user-2
        2. ng-top lookup returns user-1, user-2, and user-3
        3. ng-top lookup returns only user-2 and user-3
    :customerscenario: True
    """
    # https://fedorahosted.org/sssd/ticket/2841

    provider.user("user-1").add()
    provider.user("user-2").add()
    provider.user("user-3").add()

    # Create 3-level nested structure:
    # ng-top -> ng-middle -> ng-leaf -> user-1
    ng_leaf = provider.netgroup("ng-leaf").add().add_member(user="user-1")
    ng_middle = provider.netgroup("ng-middle").add().add_member(ng="ng-leaf")
    provider.netgroup("ng-top").add().add_member(user="user-2", ng="ng-middle")

    client.sssd.start()

    # Verify initial nested structure
    result = client.tools.getent.netgroup("ng-top")
    assert result is not None
    assert len(result.members) == 2
    assert "(-, user-1)" in result.members
    assert "(-, user-2)" in result.members

    # Add new user to middle-level netgroup
    ng_middle.add_member(user="user-3")
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-top")
    assert result is not None
    assert len(result.members) == 3
    assert "(-, user-1)" in result.members
    assert "(-, user-2)" in result.members
    assert "(-, user-3)" in result.members

    # Remove user from leaf netgroup
    ng_leaf.remove_member(user="user-1")
    client.sssctl.cache_expire(netgroups=True)

    result = client.tools.getent.netgroup("ng-top")
    assert result is not None
    assert len(result.members) == 2
    assert "(-, user-1)" not in result.members
    assert "(-, user-2)" in result.members
    assert "(-, user-3)" in result.members

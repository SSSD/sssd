"""
Netgroup tests.

:requirement: netgroup
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("medium")
@pytest.mark.cache
@pytest.mark.ticket(gh=6652, bz=2162552)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
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


@pytest.mark.parametrize("Operation", ["Add", "Replace"])
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__user_attribute_membernisnetgroup_uses_group_dn(
    client: Client, provider: GenericProvider, Operation: str
):
    """
    :title: User's 'memberNisNetgroup' attribute values are the DN of the group.
    :setup:
        1. Create users, groups.
        2. Create a new netgroup called QAUsers and add a member (ng1) to QAUsers
        3. Create another netgroup named DEVUsers and add a member (ng2) to DEVUsers
        4. Modify the DEVUsers netgroup to replace its members with the members of QAUsers.
        5. Start sssd
    :steps:
        1. Retrieve all members of the DEVUsers netgroup.
        2. Confirm that the member directly added to DEVUsers is present.
        3. Confirm that the member from QAUsers is now part of DEVUsers.
    :expectedresults:
        1. All members should be retrieved
        2. Members directly added to DEVUsers is present.
        3. Members from QAUsers is now part of DEVUsers.
    :customerscenario: False
    """
    if isinstance(provider, IPA):
        pytest.skip(reason="Not for IPA povider")

    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_qa = provider.netgroup("QAUsers").add()
    netgroup_qa.add_member(host="testhost1", user="ng1", domain="ldap.test")

    netgroup_dev = provider.netgroup("DEVUsers").add()
    netgroup_dev.add_member(host="testhost5", user="ng2", domain="ldap.test")
    if Operation == "Replace":
        netgroup_dev.add_member(ng=netgroup_qa.dn)
    else:
        netgroup_dev.add_member(ng="QAUsers")
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(testhost5, ng2, ldap.test)" in member
    assert "(testhost1, ng1, ldap.test)" in member


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__lookup_nested_groups(client: Client, provider: GenericProvider):
    """
    :title: Nesting netgroups and verifying user memberships using LDAP with sssd.
    :setup:
        1. Create users, groups.
        2. Create netgroup named netgroup and Add Member
        3. Create another netgroup named nested_netgroup
        4. Add Members to nested_netgroup
        5. Add Circular Netgroup Nesting to nested_netgroup
        6. Start sssd
    :steps:
        1. Retrieves all members of the "nested_netgroup" group using the getent netgroup tool.
        2. Verify that users from another group is also part of "nested_netgroup".
        3. Checks if a user who is not in any netgroup is part of "nested_netgroup".
        4. After the SSSD restart, it retrieves the members of "nested_netgroup" again to ensure they still intact.
    :expectedresults:
        1. All members of the "nested_netgroup" group be there
        2. Users from another group is also part of "nested_netgroup".
        3. User who is not in any netgroup is part of "nested_netgroup".
        4. After restart all members of the "nested_netgroup" group be there
    """
    if isinstance(provider, IPA):
        pytest.skip(reason="Not for IPA povider")

    for id in [1, 2, 3]:
        provider.user(f"ng{id}").add()

    netgroup = provider.netgroup("netgroup").add()
    netgroup.add_member(host="testhost1", user="ng1", domain="ldap.test")

    nested_netgroup = provider.netgroup("nested_netgroup").add()
    nested_netgroup.add_member(ng=netgroup.dn)
    nested_netgroup.add_member(host="testhost5", user="ng2", domain="ldap.test")
    nested_netgroup.add_member(user="ng3")

    netgroup.add_member(ng=nested_netgroup.dn)

    client.sssd.start()

    member = client.tools.getent.netgroup("nested_netgroup").members
    assert "(testhost1,ng1,ldap.test)" in member
    assert "(-,ng3,)" in member
    assert "(testhost5,ng2,ldap.test)" in member

    client.sssd.restart()

    member = client.tools.getent.netgroup("nested_netgroup").members
    assert "(testhost1,ng1,ldap.test)" in member
    assert "(-,ng3,)" in member
    assert "(testhost5,ng2,ldap.test)" in member


@pytest.mark.parametrize(
    "user, domain, expected",
    [("host", "host.ldap.test", "(host,-,host.ldap.test)"), ("ng3", "", "(-,ng3,)")],
)
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__host_and_domain(client: Client, provider: GenericProvider, user: str, domain: str, expected: str):
    """
    :title: Netgroup contains a member that only has a host and domain specified, but no associated user.
    :setup:
        1. Create users, groups.
        2. Create QAUsers Netgroup and Add Member
        3. Create DEVUsers Netgroup and Add Members
        4. Start sssd
    :steps:
        1.  Check whether the expected member is present in the DEVUsers netgroup.
    :expectedresults:
        1. Member is present in the DEVUsers netgroup.
    :customerscenario: False
    """
    if isinstance(provider, IPA):
        pytest.skip(reason="Not for IPA povider")

    for id in [1, 2]:
        provider.user(f"ng{id}").add()

    netgroup_qa = provider.netgroup("QAUsers").add()
    netgroup_qa.add_member(host="testhost1", user="ng1", domain="ldap.test")

    netgroup_dev = provider.netgroup("DEVUsers").add()
    netgroup_dev.add_member(host="testhost5", user="ng2", domain="ldap.test")
    if domain == "host.ldap.test":
        netgroup_dev.add_member(host=user, domain=domain)
    else:
        netgroup_dev.add_member(user=user)

    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert expected in member

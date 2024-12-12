"""
Netgroup tests.

:requirement: netgroup
"""

from __future__ import annotations

import time

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


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
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
def test_netgroup__getent_netgroup_hangs(client: Client, provider: GenericProvider):
    """
    :title: Getent netgroup hangs when use fully qualified names set to true
    :setup:
        1. Configures the SSSD domain to use fully qualified names
        2. User with the name "user-1" is created
        3. A netgroup named "ng-1" is created and the previously added user "user-1" is added to this netgroup
    :steps:
        1. The netgroup_test function is executed three times to ensure
            consistency and reliability of the configuration
    :expectedresults:
        1. Getent netgroup does not hang
    :customerscenario: True
    """
    client.sssd.dom("test")["use_fully_qualified_names"] = "true"
    user = provider.user("user-1").add()
    provider.netgroup("ng-1").add().add_member(user=user)
    client.sssd.start()

    def netgroup_test():
        result = client.tools.getent.netgroup("ng-1")
        assert result is not None
        assert result.name == "ng-1"
        assert len(result.members) == 1
        assert "(-, user-1)" in result.members

    for _ in range(3):
        netgroup_test()


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=678410)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__deleted_users(client: Client, provider: GenericProvider):
    """
    :title: Id command shows recently deleted users
    :setup:
        1. Create user with password
    :steps:
        1. User is present and can be used for authentication
        2. Delete user
        3. Ensure user exists immediately after deletion
        4. Ssh authentication for deleted user
        5. After 15 seconds as per entry_negative_timeout user is no longer present in sssd cache
    :expectedresults:
        1. User can be used for authentication
        2. User deleted
        3. User exists immediately after deletion
        4. Fail ssh authentication for deleted user
        5. After 20 seconds as per entry_negative_timeout user is no longer present in sssd cache
    :customerscenario: True
    """
    user = provider.user("user1").add(password="Secret123")
    client.sssd.start()

    assert client.tools.id(user.name) is not None
    client.auth.ssh.password("user1", "Secret123")

    user.delete()
    assert client.tools.id(user.name) is not None

    for _ in range(3):
        assert not client.auth.ssh.password("user1", "Secret123")

    time.sleep(20)
    assert client.tools.id(user.name) is None


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=645449)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.topology(KnownTopology.Samba)
def test_netgroup__syslog_warn(client: Client, provider: GenericProvider):
    """
    :title: Getent passwd username returns nothing if its uidNumber gt 2147483647
    :setup:
        1. Six users are added with large uid values
        2. Six groups are created, each with large gid values
    :steps:
        1. Check that the created users and groups are exist in the system
    :expectedresults:
        1. created users and groups are exist in the system
    :customerscenario: True
    """
    if not isinstance(provider, (LDAP, Samba, AD)):
        raise ValueError("For ipa, 'uid': can be at most 2147483647")

    client.sssd.start()

    for name, uid in [
        ("biguserA", 2147483646),
        ("biguserB", 2147483647),
        ("biguserC", 2147483648),
        ("biguserD", 2147483649),
        ("biguserE", 3147483649),
        ("biguserF", 4147483649),
    ]:
        provider.user(name).add(uid=uid, gid=uid, password="Secret123")
    for name, uid in [
        ("biggroup1", 2147483646),
        ("biggroup2", 2147483647),
        ("biggroup3", 2147483648),
        ("biggroup4", 2147483649),
        ("biggroup5", 3147483649),
        ("biggroup6", 4147483649),
    ]:
        provider.group(name).add(gid=uid)

    for username in ["biguserA", "biguserB", "biguserC", "biguserD", "biguserE", "biguserF"]:
        result = client.tools.getent.passwd(username)
        assert result is not None
        if provider.role in ["ad", "samba"]:
            assert result.name == username.lower()
        else:
            assert result.name == username
    for grpname in ["biggroup1", "biggroup2", "biggroup3", "biggroup4", "biggroup5", "biggroup6"]:
        result = client.tools.getent.group(grpname)
        assert result is not None
        if provider.role in ["ad", "samba"]:
            assert result.name == grpname.lower()
        else:
            assert result.name == grpname

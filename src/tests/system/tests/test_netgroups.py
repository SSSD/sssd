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
from sssd_test_framework.roles.ipa import IPA
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


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1576852)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__nss_responder(client: Client, provider: GenericProvider):
    """
    :title: SSSD nss responder handles correctly netgroup timeout when backend is offline
    :setup:
        1. A user (user-1) and a netgroup (ng-1) are created, and the user is added as a member of the netgroup
    :steps:
        1. Update SSSD configuration with an incorrect server URI (e.g., typo.dc.hostname).
        2. SSSD is restarted to apply the new configuration
        3. Checks the status of the SSSD domain
        4. Capture the process ID (PID) of the sssd_nss process
        5. Try to retrieve the netgroup information again, expecting it to fail since the SSSD domain is offline
        6. Verify that the sssd_nss process ID has not changed, indicating that SSSD has not
            crashed or restarted unexpectedly
    :expectedresults:
        1. SSSD configured with incorrect server uri
        2. SSSD restarted
        3. SSSD domain is offline
        4. Pid of sssd_nss captured
        5. Netgroup info can't be retrieved
        6. SSSD nss responder has the same pid as before
    :customerscenario: True
    """
    user = provider.user("user-1").add()
    netgroup = provider.netgroup("ng-1").add().add_member(user=user)

    hostname = client.host.hostname
    if isinstance(provider, (AD)) or isinstance(provider, (Samba)):
        bad_ldap_uri = "typo.dc.%s" % hostname
        client.sssd.dom("test").update(ad_server=bad_ldap_uri)

    elif isinstance(provider, (IPA)):
        bad_ldap_uri = "typo.master.%s" % hostname
        client.sssd.dom("test").update(ipa_server=bad_ldap_uri)

    elif isinstance(provider, (LDAP)):
        bad_ldap_uri = "ldaps://typo.%s" % hostname
        client.sssd.dom("test").update(ldap_uri=bad_ldap_uri)

    client.sssd.restart(clean=True)

    # Check backend status
    assert client.sssd.default_domain is not None, "Failed to load default domain!"
    result = client.sssctl.domain_status(client.sssd.default_domain)
    assert result is not None
    assert "status: Offline" in result.stdout, "Backend is online!"

    pid_nss = "pidof sssd_nss"
    pid_nss1 = client.host.conn.run(pid_nss).stdout

    # request for netgroup
    assert not client.tools.getent.netgroup(netgroup.name), f"Netgroup {netgroup.name} was unexpectedly retrieved."

    pid_nss2 = client.host.conn.run(pid_nss).stdout
    assert pid_nss1 == pid_nss2, "sssd_nss process id changed!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1779486)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_netgroup__background_refresh(client: Client, provider: GenericProvider):
    """
    :title: Verify Netgroup Membership Updates in SSSD Cache After User Addition and Cache Expiry
    :setup:
        1. Update SSSD configuration
        2. Restart SSSD
        3. Create a user and netgroup
        4. A second user is created and added to the netgroup
    :steps:
        1. The getent command succeeds in retrieving the netgroup
        2. Verify that user is member of the netgroup
        3. Wait for 30 seconds to allow the cache to expire and be refreshed
        4. The ldbsearch command is used to query the SSSD cache database (cache_test.ldb)
            to verify that second user is now part of the netgroup in the cache
    :expectedresults:
        1. Retrieves the netgroup information
        2. User is member of the netgroup
        3. Cache to expire and be refreshed
        4. Second user is now part of the netgroup in the cache
    :customerscenario: True
    """
    client.sssd.dom("test").update(entry_cache_timeout="10", refresh_expired_interval="5")
    client.sssd.restart(clean=True)
    user = provider.user("user-1").add()
    netgroup = provider.netgroup("ng-1").add().add_member(user=user)

    result = client.tools.getent.netgroup(netgroup.name)
    assert result is not None, "Could not get netgroup ng-1"
    assert result.members[0].user == "user-1"

    user2 = provider.user("user-2").add()
    netgroup.add_member(user=user2.name)

    time.sleep(30)

    search_result = client.ldb.search("/var/lib/sss/db/cache_test.ldb", "cn=Netgroups,cn=test,cn=sysdb")
    assert search_result is not None, "Empty search result!"
    assert user2.name in str(search_result), "user2 is not part of the netgroup in the cache!"

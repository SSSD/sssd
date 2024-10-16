"""
Netgroup tests.

:requirement: netgroup
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


def create_users(ldap: LDAP):
    """
    Creates users/groups needed for this test script.
    """
    ou_people = ldap.ou("People").add()
    ou_group = ldap.ou("groups").add()
    ldap.ou("Netgroup").add()

    for id in [9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010]:
        ldap.user(f"ng{id}", basedn=ou_people).add()
        ldap.user(f"ng{id}", basedn=ou_group).add()


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
def test_netgroup__netgroup_nisnetgrouptriple(client: Client, ldap: LDAP):
    """
    :title: Netgroup with nisNetgroupTriple
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Check nisNetgroupTriple contains members as added in the test.
    :expectedresults:
        1. NisNetgroupTriple should contain members as added in the test.
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    client.sssd.start()

    assert "(testhost1, ng9000, ldap.test)" in client.tools.getent.netgroup("QAUsers").members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__cache_time_out(client: Client, ldap: LDAP):
    """
    :title: Decrease the cache time out and add new entry for nisNetgroupTriple
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Check if the netgroup "QAUsers" contains the tuple (testhost1, ng9000, ldap.test),
            verifying that the member added earlier exists.
        2. Check that (testhost1, ng9001, ldap.test) does not exist in the netgroup,
            confirming that the user ng9001 has not yet been added.
        3. Add another member to the "QAUsers" netgroup.
        4. Check if after the cache expires, the user ng9001 and host testhost2
            are now correctly considered part of the netgroup "QAUsers".
        5. Check if both tuples (testhost1, ng9000, ldap.test) and (testhost2, ng9001, ldap.test)
            are present in the "QAUsers" netgroup after the changes.
    :expectedresults:
        1. Netgroup "QAUsers" contains the tuple (testhost1, ng9000, ldap.test)
        2. Tuple (testhost1, ng9001, ldap.test) does not exist in the netgroup
        3. Another member should be added to the "QAUsers" netgroup.
        4. The user ng9001 and host testhost2 are now correctly considered part of the netgroup "QAUsers".
        5. Both tuples (testhost1, ng9000, ldap.test) and (testhost2, ng9001, ldap.test)
            are present in the "QAUsers" netgroup after the changes.
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    assert "(testhost1, ng9000, ldap.test)" in client.tools.getent.netgroup("QAUsers").members
    assert not "(testhost1, ng9001, ldap.test)" in client.tools.getent.netgroup("QAUsers").members

    qa_users.add_member(host="testhost2", user="ng9001", domain="ldap.test")

    time.sleep(70)

    assert "(testhost1, ng9000, ldap.test)" in client.tools.getent.netgroup("QAUsers").members
    assert "(testhost2, ng9001, ldap.test)" in client.tools.getent.netgroup("QAUsers").members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__multiple_netgroups(client: Client, ldap: LDAP):
    """
    :title: Create multiple netgroups
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Verify if the tuple (testhost5,ng9005,ldap.test) exists in the "DEVUsers" netgroup,
            using the getent netgroup command.
        2. Check if the combination of host (testhost5), user (ng9005), and domain (ldap.test)
            is correctly part of the "DEVUsers" netgroup using libc.innetgr.
    :expectedresults:
        1. Tuple (testhost5,ng9005,ldap.test) exists in the "DEVUsers" netgroup
        2. Combination of host (testhost5), user (ng9005), and domain (ldap.test)
            is correctly part of the "DEVUsers" netgroup
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")
    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    assert "(testhost5,ng9005,ldap.test)" in client.tools.getent.netgroup("DEVUsers").members


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__membernisnetgroup(client: Client, ldap: LDAP):
    """
    :title: Add more complex LDAP netgroup structure by nesting one netgroup within another.
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Check that (testhost5, ng9005, ldap.test) is present as a direct member of "DEVUsers".
        2. Check that (testhost1, ng9000, ldap.test) is also present,
            even though this tuple was added to "QAUsers", not "DEVUsers".
            This confirms that the nested group membership is working correctly
            (since "QAUsers" is nested within "DEVUsers").
    :expectedresults:
        1. (testhost5, ng9005, ldap.test) is present as a direct member of "DEVUsers".
        2. (testhost1, ng9000, ldap.test) is present as a direct member of "DEVUsers".
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")
    ldap.ldap.modify(dev_users.dn, add={"memberNisNetgroup": "QAUsers"})

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(testhost5, ng9005, ldap.test)" in member
    assert "(testhost1, ng9000, ldap.test)" in member


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__add_dn_membernisnetgroup(client: Client, ldap: LDAP):
    """
    :title: Adding dn to memberNisNetgroup
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Check that the tuple (testhost5, ng9005, ldap.test) is present as a direct member of "DEVUsers".
        2. Check that the tuple (testhost1, ng9000, ldap.test) is also present.
            Since "QAUsers" is now referenced as part of "DEVUsers", its members
            (like ng9000 on testhost1) are inherited by "DEVUsers".
    :expectedresults:
        1. Tuple (testhost5, ng9005, ldap.test) is present as a direct member of "DEVUsers".
        2. Tuple (testhost1, ng9000, ldap.test) is also present.
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")
    ldap.ldap.modify(dev_users.dn, replace={"memberNisNetgroup": qa_users.dn})

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(testhost5, ng9005, ldap.test)" in member
    assert "(testhost1, ng9000, ldap.test)" in member


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__different_syntax(client: Client, ldap: LDAP):
    """
    :title: Using different syntax for nisNetgroupTriple
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Check that the user ng9006 appears in the group members list, represented as the tuple (-,ng9006,).
    :expectedresults:
        1. The user ng9006 appears in the group members list
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")
    dev_users.add_member(user="ng9006")

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(-,ng9006,)" in member


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__host_and_domain(client: Client, ldap: LDAP):
    """
    :title: A scenario where an LDAP netgroup contains a member that
        only has a host and domain specified, but no associated user.
    :setup:
        1.  Check that the tuple (samplehost, -, samplehost.domain.com) is part of the group
    :expectedresults:
        1. The tuple (samplehost, -, samplehost.domain.com) is part of the group
    :customerscenario: False
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")
    dev_users.add_member(host="samplehost", domain="samplehost.domain.com")

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(samplehost,-,samplehost.domain.com)" in member


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_netgroup__with_nested_loop(client: Client, ldap: LDAP):
    """
    :title: Create and manages nested LDAP netgroups and tests their behavior
        through several scenarios involving caching, membership queries, and restarts of the SSSD service.
    :setup:
        1. Create users, groups and start sssd.
    :steps:
        1. Retrieves all members of the "DEVUsers" group using the getent netgroup tool.
        2. Check for ng9000: Verifies that ng9000 (from QAUsers) is also part of "DEVUsers".
        3. Checks if a user random (who is not in any netgroup) is part of "DEVUsers".
        4. After the SSSD restart, it retrieves the members of "DEVUsers" again to ensure they are still intact.
    :expectedresults:
        1. All members of the "DEVUsers" group be there
        2. ng9000 (from QAUsers) is also part of "DEVUsers"
        3. random (who is not in any netgroup) is not part of "DEVUsers".
        4. All members of the "DEVUsers" group be there
    """
    ou = ldap.ou("Netgroup")
    create_users(ldap)

    qa_users = ldap.netgroup("QAUsers", basedn=ou).add()
    qa_users.add_member(host="testhost1", user="ng9000", domain="ldap.test")

    dev_users = ldap.netgroup("DEVUsers", basedn=ou).add()
    ldap.ldap.modify(dev_users.dn, add={"memberNisNetgroup": qa_users.dn})
    dev_users.add_member(host="testhost5", user="ng9005", domain="ldap.test")
    dev_users.add_member(user="ng9006")

    ldap.ldap.modify(qa_users.dn, add={"memberNisNetgroup": dev_users.dn})

    client.sssd.dom("test")["entry_cache_timeout"] = "60"
    client.sssd.start()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(testhost1,ng9000,ldap.test)" in member
    assert "(-,ng9006,)" in member
    assert "(testhost5,ng9005,ldap.test)" in member

    client.sssd.restart()

    member = client.tools.getent.netgroup("DEVUsers").members
    assert "(testhost1,ng9000,ldap.test)" in member
    assert "(-,ng9006,)" in member
    assert "(testhost5,ng9005,ldap.test)" in member

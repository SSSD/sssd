"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-3925", gh=6942)
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__lookup_group_without_sid(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Subdomain stays online if IPA group is missing SID
    :description: This test is to check a bug that made SSSD go offline when an expected attribute was missing.
        This happens during applying overrides on cached group during initgroups of trusted user. If the group
        does not have SID (it's GID is outside the sidgen range), SSSD goes offline.
    :setup:
        1. Create IPA external group "external-group" and add AD user "Administrator" as a member
        2. Create IPA posix group "posix-group" and add "external-group" as a member
        3. Clear SSSD cache and logs on IPA server
        4. Restart SSSD on IPA server
    :steps:
        1. Lookup AD administrator user
        2. Clear user cache
        3. Lookup AD administrator user
        4. Check logs using sssctl for domain status
    :expectedresults:
        1. User is found and is a member of 'posix-group'
        2. User cache expired
        3. User is found and is a member of 'posix-group'
        4. No messages indicating AD went offline
    :customerscenario: True
    """
    username = trusted.fqn("administrator")
    external = ipa.group("external-group").add(external=True).add_member(username)
    ipa.group("posix-group").add(gid=5001).add_member(external)

    ipa.sssd.clear(db=True, memcache=True, logs=True)
    ipa.sssd.restart()

    # Cache trusted user
    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert result.memberof("posix-group"), "User is not a member of 'posix-group'!"

    # Expire the user and resolve it again, this will trigger the affected code path
    ipa.sssctl.cache_expire(user=username)
    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert result.memberof("posix-group"), "User is not a member of 'posix-group'!"

    # Check that SSSD did not go offline
    status = ipa.sssctl.domain_status(trusted.domain, online=True)
    assert "online status: offline" not in status.stdout.lower(), "AD domain went offline!"
    assert "online status: online" in status.stdout.lower(), "AD domain was not online!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__aduser_membership_update_cache(ipa: IPA, trusted: GenericADProvider):
    """
    :title: User-cache update of the AD-user with multiple IPA-groups membership after expiring a user cache
    :description: ADuser's large number of external IPA groups membership does not get updated after expired cache
    :setup:
        1. Create 4000 IPA external group "external-group" and add a AD user as it's member
        2. Create 4000 IPA posix group "posix-group" and add "external-group" as a member
        3. Clear SSSD cache and logs on IPA server
        4. Restart SSSD on IPA server
    :steps:
        1. Lookup AD user
        2. Remove AD-user from one group
        3. Clear user cache of that user only
        4. Lookup AD user
    :expectedresults:
        1. User is found and is a member of 4000 groups
        2. AD-user is removed from a group
        3. User cache expired for that user only
        4. User is found and is not a member of removed group
    :customerscenario: True
    """
    trusted.user("Aduser").add()
    aduser = trusted.fqn("Aduser")
    for i in range(4000):
        external = ipa.group(f"external_group_{i}").add(external=True).add_member(aduser)
        ipa.group(f"posix_group_{i}").add().add_member(external)

    result = ipa.tools.id(aduser)
    assert result is not None, "User not found!"
    assert result.memberof("posix_group_4"), "User is not a member of 'posix-group4'!"

    ipa.group("posix_group_4").remove_member(ipa.group("external_group_4"))
    ipa.sssctl.cache_expire(user=aduser)
    time.sleep(10)
    result = ipa.tools.id(aduser)
    assert result is not None, "User not found!"
    assert not result.memberof("posix_group_4"), "User is not a member of 'posix-group4'!"

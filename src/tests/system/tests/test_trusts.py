"""
Identity of trusted users and groups.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-3925", gh=6942)
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_trusts__lookup_group_without_sid(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Subdomain goes offline if IPA group is missing SID
    :setup:
        1. Create IPA external group "external-group" and add AD user "Administrator" as a member
        2. Create IPA posix group "posix-group" and add "external-group" as a member
        3. Clear SSSD cache and logs on IPA server
        4. Restart SSSD on IPA server
    :steps:
        1. Resolve user "Administrator@addomain"
        2. Expire user "Administrator@addomain"
        3. Resolve user "Administrator@addomain"
        4. Run "sssctl domain-status addomain"
    :expectedresults:
        1. User is resolved and member of posix-group
        2. User is expired in SSSD cache
        3. User is resolved and member of posix-group
        4. The Active Directory domain is still online
    :customerscenario: True
    """
    username = trusted.fqn("administrator")
    external = ipa.group("external-group").add(external=True).add_member(username)
    ipa.group("posix-group").add(gid=5001).add_member(external)

    ipa.sssd.clear(db=True, memcache=True, logs=True)
    ipa.sssd.restart()

    # Cache trusted user
    result = ipa.tools.id(username)
    assert result is not None
    assert result.user.name == username
    assert result.memberof("posix-group")

    # Expire the user and resolve it again, this will trigger the affected code path
    ipa.sssctl.cache_expire(user=username)
    result = ipa.tools.id(username)
    assert result is not None
    assert result.user.name == username
    assert result.memberof("posix-group")

    # Check that SSSD did not go offline
    status = ipa.sssctl.domain_status(trusted.domain, online=True)
    assert "online status: offline" not in status.stdout.lower()
    assert "online status: online" in status.stdout.lower()

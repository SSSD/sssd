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


@pytest.mark.topology(KnownTopologyGroup.IPATrust)
@pytest.mark.parametrize("use_token_groups", ["true", "false"])
@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-77184")
def test_ipa_trusts__add_and_remove_external_group_membership(
    ipa: IPA, trusted: GenericADProvider, use_token_groups: str
):
    """
    :title: Add and remove and AD user to an IPA group
    :description: This test wil check if an AD user can be added and remove to an IPA group.
    :setup:
        1. Set 'ldap_use_tokengroups' option and inherit it to sub-domains
        2. Create IPA external group "external-group" and add AD user "Administrator" as a member
        3. Create IPA posix group "posix-group" and add "external-group" as a member
    :steps:
        1. Clear SSSD cache and lookup group memberships of  "Administrator"
        2. Remove "Administrator" from "external-group"
        3. Expire the cached user, wait 10s to expire the external group map
           cache and lookup group memberships of "Administrator"
    :expectedresults:
        1. User "Administrator" is a member of "posix-group"
        2. Command is successful
        3. User "Administrator" is a not a member of "posix-group"
    :customerscenario: True
    """
    ipa.sssd.dom(ipa.domain)["ldap_use_tokengroups"] = use_token_groups
    ipa.sssd.dom(ipa.domain)["subdomain_inherit"] = "ldap_use_tokengroups"
    ipa.sssd.config_apply()

    username = trusted.fqn("administrator")
    external = ipa.group("external-group").add(external=True).add_member(username)
    ipa.group("posix-group").add().add_member(external)

    ipa.sssd.clear(db=True, memcache=True, logs=False)
    ipa.sssd.restart()

    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert result.memberof("posix-group"), "User is not a member of 'posix-group'!"

    external.remove_member(username)

    ipa.sssctl.cache_expire(user=username)
    # required sleep to expire SSSD's external group map cache
    time.sleep(10)
    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert not result.memberof("posix-group"), "User is still a member of 'posix-group'!"

"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import time
import uuid

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


@pytest.mark.topology(KnownTopologyGroup.IPATrust)
@pytest.mark.ticket(jira="RHEL-109087")
@pytest.mark.importance("low")
def test_ipa_trusts__aduser_membership_after_HBAC(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Membership update of the AD-user after it's IPA-group is a member of a HBAC rule
    :description: ADuser's ipa-group membership should not be lost after its ipa-group is added to an HBAC rule.
    :setup:
        1. Create a trusted AD-user.
        2. Create an IPA external group and add the AD user as its member.
        3. Create an IPA posix group and add the ipa external group as a member.
    :steps:
        1. Lookup AD user and verify initial group membership.
        2. Create an HBAC rule for the all-host-category.
        3. Add the IPA-posix-group to that HBAC rule.
        4. Clear the cache for that user only.
        5. Lookup the AD user again.
    :expectedresults:
        1. The user is found and is a member of the POSIX group.
        2. The HBAC rule is created successfully.
        3. The group is added to the HBAC rule successfully.
        4. The user's cache is expired.
        5. The user is still found and is still a member of the POSIX group.
    :customerscenario: False
    """
    unique = str(uuid.uuid4())[:8]

    # Define dynamic names for test objects
    ad_user_name = f"aduser-{unique}"
    external_group_name = f"ipa_external_group_{unique}"
    posix_group_name = f"ipa_group_{unique}"
    hbac_rule = f"hbac-rule-{unique}"

    # --- Setup Phase ---
    trusted.user(ad_user_name).add()
    aduser_fqn = trusted.fqn(ad_user_name)

    # ipa.host.conn.exec(["ipa", "trust-find"])
    ipa.sssctl.cache_expire(everything=True)
    user_found = ipa.tools.id(aduser_fqn)
    assert user_found is not None, f"AD User '{aduser_fqn}' did not replicate to IPA server in time."

    external = ipa.group(external_group_name).add(external=True).add_member(aduser_fqn)
    posix_group = ipa.group(posix_group_name).add().add_member(external)

    # --- Verification Phase 1: Initial State ---
    # ipa.sssctl.cache_expire(everything=True)
    ipa.sssd.restart(clean=True)
    result = ipa.tools.id(aduser_fqn)
    assert result is not None, "User not found"
    assert result.memberof(posix_group.name), f"User lost membership in '{posix_group.name}' before HBAC update."

    # --- Drop these hbac actions, Once HBAC module in in testframework
    ipa.host.conn.exec(["ipa", "hbacrule-add", hbac_rule, "--hostcat=all"])
    ipa.host.conn.exec(["ipa", "hbacrule-add-user", hbac_rule, f"--groups={posix_group.name}"])

    ipa.sssctl.cache_expire(user=aduser_fqn)

    # --- Verification Phase 2: State After HBAC Update ---
    time.sleep(10)
    result = ipa.tools.id(aduser_fqn)
    assert result is not None, "User is not found"
    assert result.memberof(posix_group.name), f"User lost membership in '{posix_group.name}' after HBAC update."

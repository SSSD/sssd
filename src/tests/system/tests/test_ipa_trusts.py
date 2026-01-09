"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import time
import uuid

import pytest
from sssd_test_framework.roles.client import Client
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


@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-94545", gh=8048)
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__lookup_private_group_with_username_override(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Auto private group for IPA trusted user is resolved when 'login' override exists
    :description: When a 'name' ID user override exists for IPA AD trusted users, user resolution
        would fail as the auto private group could not be resolved.
    :setup:
        1. Create trusted user "user1"
        2. Clear SSSD cache and logs on IPA server
        3. Add 'login' override for user1@trusted.domain
    :steps:
        1. Clear user cache
        2. Lookup user private group for AD user with override name
        3. Lookup user private group with original group name
    :expectedresults:
        1. Cache is cleared
        2. Auto private group is resolved for override name
        3. New group name (overriden) is resolved and returned
    :customerscenario: True
    """

    # Add user to trusted domain
    trusted.user("user1").add()
    user1_fqn = trusted.fqn("user1")

    override_name = "testover"
    override_fqn = trusted.fqn("testover")

    ipa.sssd.restart()

    # Add username override
    ipa.user(user1_fqn).iduseroverride().add_override(
        "Default Trust View",
        login=override_name,
    )

    # Lookup auto private group with override name
    override_result = ipa.tools.getent.group(override_fqn)

    assert override_result is not None
    assert override_result.name == override_fqn

    # Lookup with the original group name is still working
    # but will return the object with the new name
    orig_result = ipa.tools.getent.group(user1_fqn)

    assert orig_result is not None
    assert orig_result.name == override_fqn


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__aduser_membership_update_cache(ipa: IPA, trusted: GenericADProvider):
    """
    :title: User-cache update of the AD-user with multiple IPA-groups membership after expiring a user cache
    :description: ADuser's large number of external IPA groups membership does not get updated after expired cache
    :setup:
        1. Create 10 IPA external group "external-group" and add a AD user as it's member
        2. Create 10 IPA posix group "posix-group" and add "external-group" as a member
        3. Clear SSSD cache and logs on IPA server
        4. Restart SSSD on IPA server
    :steps:
        1. Lookup AD user
        2. Remove AD-user from one group
        3. Clear user cache of that user only
        4. Lookup AD user
    :expectedresults:
        1. User is found and is a member of 12 groups
        2. AD-user is removed from a group
        3. User cache expired for that user only
        4. User is found and is not a member of removed group
    :customerscenario: True
    """
    trusted.user("Aduser").add()
    aduser = trusted.fqn("Aduser")
    for i in range(10):
        external = ipa.group(f"external_group_{i}").add(external=True).add_member(aduser)
        ipa.group(f"posix_group_{i}").add().add_member(external)

    result = ipa.tools.id(aduser)
    assert result is not None, "User not found!"
    assert len(result.groups) == 12, "Groups membership number is not 12!"
    assert result.memberof("posix_group_4"), "User is not a member of 'posix-group4'!"

    ipa.group("posix_group_4").remove_member(ipa.group("external_group_4"))
    ipa.sssctl.cache_expire(user=aduser)
    """
    Do NOT remove this 10s delay.
    There is an internal hardcoded timeout of 10s for the refresh of the external group data.
    So, if you remove the user from the external group, SSSD might see this change only after 10s.
    Since this is not user property, sssctl cache-expire has no effect on this internal timeout.
    """
    time.sleep(10)
    result = ipa.tools.id(aduser)
    assert result is not None, "User not found!"
    assert not result.memberof("posix_group_4"), "User is still a member of 'posix-group4'!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__change_view(client: Client, ipa: IPA, trusted: GenericADProvider):
    """
    :title: Change the view of a client
    :description: After changing the view of an IPA client and restarting SSSD
        on the client to switch to the new view cached users of a trusted
        domain with a user-private-group should still be resolvable
    :setup:
        1. Use Administrator user from trusted AD/Samba domain
        4. Restart SSSD on IPA client
    :steps:
        1. Lookup AD user
        2. Change the view of the client on the IPA server, apply it to the
           client and restart SSSD to switch to the new view without removing
           the cache
        3. Lookup AD user
    :expectedresults:
        1. User is found
        2. All commands are successful
        3. User is found
    :customerscenario: True
    """
    aduser = trusted.fqn("administrator")

    client.sssd.restart()

    result = client.tools.getent.passwd(aduser)
    assert result is not None, f"{aduser} not found!"

    ipa.idview("testview1").add(description="Test view")
    ipa.idview("testview1").apply(hosts=[f"{client.host.hostname}"])
    client.sssd.restart(clean=False)

    result = client.tools.getent.passwd(aduser)
    assert result is not None, f"{aduser} not found after view change!"

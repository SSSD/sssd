"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import time
import uuid

import pytest
from pytest_mh.conn import ProcessError
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
def test_ipa_trusts__aduser_membership_after_HBAC(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Membership update of the AD-user after it's IPA-group is a member of a HBAC rule
    :description: ADuser's ipa-group membership misses after ipa-group is added to a HBAC rule
    :setup:
        1. Create a trusted AD-user
        2. Create IPA external group and add a AD user as it's member
        3. Create IPA posix group and add ipa external group as a member
    :steps:
        1. Lookup AD user
        2. Create HBAC rule for all-host-category,
        3. Add IPA-posix-group in that HBAC rule
        4. Clear user cache of that user only
        5. Lookup AD user
    :expectedresults:
        1. User is found and is a member of ipa_group_A group
        2. HBAC rule created
        3. ipa_group_A group is added to HBAC rule
        4. User cache expired for that user only
        5. User is found and is a member of ipa_group_A group
    :customerscenario: True
    """
    unique_suffix = str(uuid.uuid4())[:8]
    trusted.user(f"aduser-{unique_suffix}").add()
    aduser = trusted.fqn(f"aduser-{unique_suffix}")
    external = ipa.group(f"ipa_external_group_{unique_suffix}").add(external=True).add_member(aduser)
    ipa_posix_group = ipa.group(f"ipa_group_{unique_suffix}").add().add_member(external)
    hbac_rule = f"hbac-rule-{unique_suffix}"

    try:
        result = ipa.tools.id(aduser)
        assert result is not None, "User not found!"
        assert result.memberof(f"{ipa_posix_group}"), "User is not a member of 'ipa_group_{unique_suffix}'!"

        ipa.host.conn.exec(["ipa", "hbacrule-add", hbac_rule, "--hostcat=all"])
        ipa.host.conn.exec(["ipa", "hbacrule-add-user", hbac_rule, f"--groups={ipa_posix_group}"])

        ipa.sssctl.cache_expire(user=aduser)
        success = False
        for _ in range(15):  # Poll for up to 30 seconds
            result = ipa.tools.id(aduser)
            if result and result.memberof(f"{ipa_posix_group}"):
                success = True
                break
            time.sleep(2)
        assert success, f"User lost membership in '{ipa_posix_group}' after HBAC update."

    finally:
        # --- Cleanup Phase ---
        # -- Remove this cleanup phase once hbac module available --
        # ipa.host.conn.exec(["ipa", "hbacrule-del", hbac_rule])
        for obj_name, obj_deleter_cmd in [
            (hbac_rule, ["ipa", "hbacrule-del", hbac_rule]),
        ]:
            try:
                if obj_deleter_cmd:
                    ipa.host.conn.exec(obj_deleter_cmd)
            except ProcessError:
                # This is expected if the test failed before object creation
                pass

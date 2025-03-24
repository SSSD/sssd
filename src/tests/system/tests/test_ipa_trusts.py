"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
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


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__authentication_with_default_settings(client: Client, trusted: GenericADProvider):
    """
    :title: Authenticate IPA and trusted AD users with default settings
    :setup:
        1. Create trusted user
        2. Start SSSD
    :steps:
        1. Authenticate user using their fully qualified name
        2. Authenticate user using the wrong password
    :expectedresults:
        1. Login is successful
        2. Login is unsuccessful
    :customerscenario: False
    """
    trusted_user = trusted.user("user1").add(password="Secret123").name
    trusted_user_fqn = f"{trusted_user}@{trusted.domain}"

    # Samba requires this parameter to authenticate
    if isinstance(trusted, Samba):
        client.sssd.domain["krb5_use_fast"] = "never"

    client.sssd.start(clean=True)

    assert client.auth.ssh.password(trusted_user_fqn, "Secret123"), f"User {trusted_user_fqn} failed login!"
    assert not client.auth.ssh.password(
        trusted_user_fqn, "bad_password"
    ), f"User {trusted_user_fqn} logged in with an incorrect password!"


@pytest.mark.importance("high")
@pytest.mark.ticket(jira="RHEL-4984", gh=7635)
@pytest.mark.topology(KnownTopologyGroup.IPATrust)
def test_ipa_trusts__authentication_with_default_domain_suffix_set(client: Client, trusted: GenericADProvider):
    """
    :title: Authenticate IPA and trusted AD users with default_domain_suffix set to AD
    :setup:
        1. Create trusted user
        2. Set 'default_domain_suffix' value to 'trusted_domain'
        3. Start SSSD
    :steps:
        1. Authenticate user using their fully qualified name
        2. Authenticate users using the wrong password
    :expectedresults:
        1. Logins are successful
        2. Logins are unsuccessful
    :customerscenario: True
    """
    trusted_user = trusted.user("user1").add(password="Secret123").name
    trusted_user_fqn = f"{trusted_user}@{trusted.domain}"

    # Samba requires this parameter to authenticate
    if isinstance(trusted, Samba):
        client.sssd.domain["krb5_use_fast"] = "never"

    client.sssd.section("sssd")["default_domain_suffix"] = trusted.domain
    client.sssd.start(clean=True)

    assert client.auth.ssh.password(trusted_user_fqn, "Secret123"), f"User {trusted_user_fqn} failed login!"
    assert not client.auth.ssh.password(
        trusted_user_fqn, "bad_password"
    ), f"User {trusted_user_fqn} logged in with an incorrect password!"

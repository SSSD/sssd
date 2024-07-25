"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider, GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-3925", gh=6942)
@pytest.mark.topology(KnownTopologyGroup.IPATrustAD)
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


@pytest.mark.importance("medium")
@pytest.mark.ticket(jira="RHEL-14752")
@pytest.mark.topology(KnownTopology.IPATrustIPA)
def test_ipa_trusts__ipa_master_lookup_trusted_user_and_group(ipa: IPA, trusted: IPA):
    """
    :title: Basic IPA-IPA Trust lookup on IPA server
    :setup:
        1. Restart SSSD and clear cache on IPA server
    :steps:
        1. Resolve trusted domain admin user
        2. Resolve trusted domain admins group
    :expectedresults:
        1. User is resolved
        2. Group is resolved
    :customerscenario: True
    """
    ipa.sssd.restart(clean=True)

    admin = trusted.admin_fqn
    id_user = ipa.tools.id(admin)

    admins = trusted.fqn("admins")
    getent_group = ipa.tools.getent.group(admins)

    assert id_user is not None, "Trusted admin user not found!"
    assert id_user.user.name == admin, "Username does not match!"

    assert getent_group is not None, f"No group {admins} found!"
    assert getent_group.name == admins, f"Group name does not match {admins}!"


@pytest.mark.importance("medium")
@pytest.mark.ticket(jira="RHEL-14752")
@pytest.mark.topology(KnownTopology.IPATrustIPA)
def test_ipa_trusts__lookup_trusted_user_and_group(client: Client, ipa: IPA, trusted: IPA):
    """
    :title: Basic IPA-IPA Trust lookup on IPA client
    :setup:
        1. Restart SSSD and clear cache on IPA client
    :steps:
        1. Resolve trusted admin user
        2. Resolve group "admins@trusteddomain"
    :expectedresults:
        1. User is resolved
        2. Group is resolved
    :customerscenario: True
    """
    client.sssd.restart(clean=True)

    admin = trusted.admin_fqn
    id_user = client.tools.id(admin)

    admins = trusted.fqn("admins")
    getent_group = client.tools.getent.group(admins)

    assert id_user is not None, "Trusted admin user not found!"
    assert id_user.user.name == admin, "Username does not match!"

    assert getent_group is not None, f"No group {admins} found!"
    assert getent_group.name == admins, f"Group name does not match {admins}!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyIPATrust)
def test_ipa_trusts__user_login(client: Client, trusted: GenericProvider):
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
    user1 = trusted.user("user1").add(password="Secret123").name
    user1_fqn = f"{user1}@{trusted.domain}"

    # Samba requires this parameter to authenticate
    if isinstance(trusted, Samba):
        client.sssd.domain["krb5_use_fast"] = "never"

    client.sssd.start(clean=True)

    assert client.auth.ssh.password(user1_fqn, "Secret123"), f"User {user1_fqn} failed login!"
    assert not client.auth.ssh.password(
        user1_fqn, "bad_password"
    ), f"User {user1_fqn} logged in with an incorrect password!"


@pytest.mark.importance("high")
@pytest.mark.ticket(jira="RHEL-4984", gh=7635)
@pytest.mark.topology(KnownTopologyGroup.AnyIPATrust)
def test_ipa_trusts__user_login_with_domain_suffix_set(client: Client, trusted: GenericProvider):
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
    user1 = trusted.user("user1").add(password="Secret123").name
    user1_fqn = f"{user1}@{trusted.domain}"

    # Samba requires this parameter to authenticate
    if isinstance(trusted, Samba):
        client.sssd.domain["krb5_use_fast"] = "never"

    client.sssd.section("sssd")["default_domain_suffix"] = trusted.domain
    client.sssd.start(clean=True)

    assert client.auth.ssh.password(user1_fqn, "Secret123"), f"User {user1_fqn} failed login!"
    assert not client.auth.ssh.password(
        user1_fqn, "bad_password"
    ), f"User {user1_fqn} logged in with an incorrect password!"

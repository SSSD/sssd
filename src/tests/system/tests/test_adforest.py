"""
SSSD AD Forest multi-domain test cases.

Ports coverage from the legacy IdM-CI / sssd-qe ``ad_forest`` suite
(lookup, auth, simple access, ad_access_filter, join other DC) and from
legacy multihost ``admultidomain`` (excluding multiforest).

:requirement: adforest
"""

from __future__ import annotations

import re
import time

import pytest
from sssd_test_framework.fixtures import (
    _ad_forest_block_servers,
    _ad_forest_configure_sssd,
    _ad_forest_rejoin_with_host_upn,
    _ad_forest_remove_linuxservers_ou,
    _ad_forest_remove_stale_computer,
)
from sssd_test_framework.roles.ad import AD, ADGroup, ADUser
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

ForestObjects = tuple[ADUser, ADUser, ADUser, ADGroup, ADGroup, ADGroup]


def _flatname(ad: AD) -> str:
    """NetBIOS-style short domain name used in DOMAIN\\user lookups."""
    return ad.domain.split(".")[0].upper()


def _wait_ad_object(ad: AD, dn: str, timeout: int = 60) -> None:
    """Wait until ``dn`` is visible on the object's home domain controller."""
    deadline = time.time() + timeout
    dn_ps = dn.replace("'", "''")
    while time.time() < deadline:
        result = ad.host.conn.run(f"Get-ADObject -Identity '{dn_ps}'", raise_on_error=False)
        if result.rc == 0 and result.stdout.strip():
            return
        time.sleep(5)
    raise TimeoutError(f"Timed out waiting for AD object {dn}")


def _wait_forest_gc(ad_root: AD, *objects: tuple[AD, str]) -> None:
    """Wait for cross-domain objects and allow GC sync (legacy ad_forest setup.sh)."""
    for domain, dn in objects:
        _wait_ad_object(domain, dn)
    time.sleep(90)


def _wait_client_getent_group(client: Client, name: str, timeout: int = 180) -> None:
    """Poll ``getent group`` until ``name`` resolves or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.tools.getent.group(name) is not None:
            return
        time.sleep(10)
    raise AssertionError(f"Timed out waiting for group {name} to resolve")


def _wait_client_lookup(client: Client, name: str, timeout: int = 180) -> None:
    """Poll ``id`` until ``name`` resolves or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client.tools.id(name) is not None:
            return
        time.sleep(10)
    raise AssertionError(f"Timed out waiting for {name} to resolve")


def _setup_forest_users_and_groups(ad: AD, ad_child: AD, ad_tree: AD) -> ForestObjects:
    """
    Create one user and one group per forest domain.

    Returns (root_user, child_user, tree_user, root_group, child_group, tree_group).
    """
    root_user = ad.user("forest-user1").add()
    child_user = ad_child.user("forest-child1").add()
    tree_user = ad_tree.user("forest-tree1").add()

    root_group = ad.group("forest-group1").add(scope="Universal").add_member(root_user)
    child_group = ad_child.group("forest-child-group1").add(scope="Universal").add_member(child_user)
    tree_group = ad_tree.group("forest-tree-group1").add(scope="Universal").add_member(tree_user)

    # Universal membership is GC-replicated; child/tree groups need time to appear
    # on a root-joined client (legacy ad_forest setup.sh sleeps 30s).
    _wait_forest_gc(
        ad,
        (ad_child, child_group.dn),
        (ad_child, child_user.dn),
        (ad_tree, tree_group.dn),
        (ad_tree, tree_user.dn),
    )

    return root_user, child_user, tree_user, root_group, child_group, tree_group


def _setup_forest_shared_group(ad: AD, root_user: ADUser, child_user: ADUser, tree_user: ADUser) -> ADGroup:
    """Universal group on the root with members from root, child and tree domains."""
    shared = ad.group("forest-shared").add(scope="Universal")
    for member in (root_user, child_user, tree_user):
        _wait_ad_object(member.role, member.dn)
        shared.add_members([member])
    _wait_ad_object(ad, shared.dn)
    time.sleep(90)
    return shared


def _rename_ad_group(group: ADGroup, new_name: str) -> None:
    """Rename an AD group on the directory server (CN + sAMAccountName)."""
    dn = group.dn.replace("'", "''")
    parent = group.path.replace("'", "''")
    group.role.host.conn.run(
        f"""
        Import-Module ActiveDirectory
        Rename-ADObject -Identity '{dn}' -NewName '{new_name}'
        Set-ADGroup -Identity 'cn={new_name},{parent}' -SamAccountName '{new_name}'
        """,
        raise_on_error=True,
    )


def _id_output(client: Client, name: str) -> str:
    """Return stripped stdout from ``id`` for ``name``."""
    result = client.host.conn.run(f"id {name}", raise_on_error=False)
    assert result.rc == 0, f"id failed for {name}: {result.stderr}"
    return result.stdout.strip()


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=[1002592, 1001318, 1033096, 969882])
def test_adforest__lookup_users_and_groups_from_all_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Lookup users and groups from root, child and tree domains
    :setup:
        1. Join forest root
        2. Create a user and group in each domain
        3. Configure SSSD with fully qualified names and start SSSD
    :steps:
        1. Resolve users from root, child and tree with id
        2. Resolve users with getent passwd
        3. Resolve groups with getent group and check membership
    :expectedresults:
        1. Each user is found and belongs to its domain group
        2. getent passwd returns each user
        3. getent group lists the expected member
    :customerscenario: True
    """
    root_user, child_user, tree_user, root_group, child_group, tree_group = _setup_forest_users_and_groups(
        ad, ad_child, ad_tree
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, group, domain_role in (
        (root_user, root_group, ad),
        (child_user, child_group, ad_child),
        (tree_user, tree_group, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        result = client.tools.id(name)
        assert result is not None, f"id failed for {name}"
        assert result.memberof(domain_role.fqn(group.name)) or result.memberof(
            group.name
        ), f"{name} missing group {group.name}"

        assert client.tools.getent.passwd(name) is not None, f"getent passwd failed for {name}"

        gname = domain_role.fqn(group.name)
        gresult = client.tools.getent.group(gname)
        assert gresult is not None, f"getent group failed for {gname}"
        assert any(user.name in m or name in m for m in gresult.members), f"{name} not in {gname}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[1059423, 1028057, 1002597])
def test_adforest__cross_domain_group_membership(client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD):
    """
    :title: Users appear in universal groups across forest domains
    :setup:
        1. Join forest root
        2. Create users in each domain and a universal group with all of them
        3. Start SSSD
    :steps:
        1. Resolve the shared group and each forest user
    :expectedresults:
        1. Shared group membership and user initgroups include cross-domain members
    :customerscenario: True
    """
    root_user, child_user, tree_user, _, _, _ = _setup_forest_users_and_groups(ad, ad_child, ad_tree)
    _setup_forest_shared_group(ad, root_user, child_user, tree_user)
    shared_name = ad.fqn("forest-shared")

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    # Allow GC / membership replication to settle
    time.sleep(5)

    gresult = client.tools.getent.group(shared_name)
    assert gresult is not None, f"getent group failed for {shared_name}"

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        result = client.tools.id(name)
        assert result is not None, f"id failed for {name}"
        assert result.memberof(shared_name) or result.memberof(
            "forest-shared"
        ), f"{name} missing shared group membership"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=969882)
def test_adforest__flatname_fully_qualified_format(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Resolve users and groups using DOMAIN\\\\name flat name format
    :setup:
        1. Join forest root
        2. Create a user and group in each domain
        3. Start SSSD
    :steps:
        1. getent passwd with NETBIOS\\\\user for each domain
        2. getent group with NETBIOS\\\\group for each domain
    :expectedresults:
        1. Each flat-name user resolves
        2. Each flat-name group resolves with the expected member
    :customerscenario: True
    """
    root_user, child_user, tree_user, root_group, child_group, tree_group = _setup_forest_users_and_groups(
        ad, ad_child, ad_tree
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, group, domain_role in (
        (root_user, root_group, ad),
        (child_user, child_group, ad_child),
        (tree_user, tree_group, ad_tree),
    ):
        flat_user = f"{_flatname(domain_role)}\\{user.name}"
        flat_group = f"{_flatname(domain_role)}\\{group.name}"

        assert client.tools.getent.passwd(flat_user) is not None, f"getent passwd failed for {flat_user}"
        gresult = client.tools.getent.group(flat_group)
        assert gresult is not None, f"getent group failed for {flat_group}"
        assert any(user.name in m for m in gresult.members), f"{user.name} not in {flat_group}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1053106)
def test_adforest__subdomains_use_fallback_homedir(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Subdomains apply fallback_homedir independently per domain
    :setup:
        1. Join forest root
        2. Create a user in each domain
        3. Configure fallback_homedir = /home/%d/%u and start SSSD
    :steps:
        1. getent passwd for each forest user and read home directory
    :expectedresults:
        1. Home directory is /home/<domain>/<user> for each domain
    :customerscenario: True
    """
    root_user = ad.user("forest-home-root").add()
    child_user = ad_child.user("forest-home-child").add()
    tree_user = ad_tree.user("forest-home-tree").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        result = client.tools.getent.passwd(name)
        assert result is not None, f"getent passwd failed for {name}"
        expected_home = f"/home/{domain_role.domain}/{user.name}"
        assert result.home == expected_home, f"Expected home {expected_home}, got {result.home}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
def test_adforest__authenticate_users_from_all_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Authenticate users from root, child and tree domains
    :setup:
        1. Join forest root
        2. Create a user in each domain
        3. Start SSSD
    :steps:
        1. Authenticate each forest user with su
    :expectedresults:
        1. Authentication succeeds for root, child and tree users
    :customerscenario: True
    """
    root_user = ad.user("forest-auth-root").add()
    child_user = ad_child.user("forest-auth-child").add()
    tree_user = ad_tree.user("forest-auth-tree").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        assert client.auth.su.password(name, "Secret123"), f"Authentication failed for {name}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1078840)
def test_adforest__change_password_for_users_from_all_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Change password for users from all forest domains
    :setup:
        1. Join forest root
        2. Create a user in each domain
        3. Start SSSD
    :steps:
        1. Change password for each user via passwd
        2. Authenticate with the new password
        3. Reset passwords on the DCs
    :expectedresults:
        1. Password change succeeds
        2. Login works with the new password
        3. Passwords are restored
    :customerscenario: True
    """
    users = (
        ad.user("forest-pw-root").add(),
        ad_child.user("forest-pw-child").add(),
        ad_tree.user("forest-pw-tree").add(),
    )
    domains = (ad, ad_child, ad_tree)
    new_password = "NewPass1_123"

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, domain_role in zip(users, domains):
        name = domain_role.fqn(user.name)
        assert client.auth.passwd.password(name, "Secret123", new_password), f"Password change failed for {name}"
        assert client.auth.su.password(name, new_password), f"Login with new password failed for {name}"
        user.reset("Secret123")


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[924404, 1079783])
def test_adforest__authenticate_with_enterprise_principals(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Authenticate users that have enterprise / alternate UPNs
    :setup:
        1. Join forest root
        2. Create users with alternate UserPrincipalName values
        3. Start SSSD
    :steps:
        1. Authenticate using the UPN form for each domain
    :expectedresults:
        1. Authentication succeeds for each enterprise principal
    :customerscenario: True
    """
    root_upn = f"ent-root@{ad.domain}"
    child_upn = f"ent-child@{ad_child.domain}"
    tree_upn = f"ent-tree@{ad_tree.domain}"

    ad.user("forest-ent-root").add(upn=root_upn)
    ad_child.user("forest-ent-child").add(upn=child_upn)
    ad_tree.user("forest-ent-tree").add(upn=tree_upn)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for upn in (root_upn, child_upn, tree_upn):
        assert client.auth.su.password(upn, "Secret123"), f"Enterprise principal login failed for {upn}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=991055)
def test_adforest__simple_allow_users_across_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Simple access provider allows listed users from all forest domains
    :setup:
        1. Join forest root
        2. Create allowed users in each domain and a denied root user
        3. Configure access_provider=simple with simple_allow_users
        4. Start SSSD
    :steps:
        1. Authenticate allowed root, child and tree users
        2. Authenticate the denied root user
    :expectedresults:
        1. Allowed users can log in
        2. Denied user cannot log in
    :customerscenario: True
    """
    root_user = ad.user("forest-sac-root").add()
    child_user = ad_child.user("forest-sac-child").add()
    tree_user = ad_tree.user("forest-sac-tree").add()
    denied = ad.user("forest-sac-denied").add()

    allow = ",".join(
        (
            ad.fqn(root_user.name),
            ad_child.fqn(child_user.name),
            ad_tree.fqn(tree_user.name),
        )
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "simple"
    client.sssd.dom(join_ad_root.domain)["simple_allow_users"] = allow
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        assert client.auth.su.password(name, "Secret123"), f"Allowed user {name} failed login"

    denied_name = ad.fqn(denied.name)
    assert not client.auth.su.password(denied_name, "Secret123"), f"Denied user {denied_name} was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=982619)
def test_adforest__simple_allow_and_deny_groups_across_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Simple access provider evaluates allow and deny groups across domains
    :setup:
        1. Join forest root
        2. Create users and groups in each domain
        3. Allow root/child/tree groups then deny child and tree groups
        4. Start SSSD
    :steps:
        1. With only allow groups, authenticate users from all domains
        2. Add deny groups for child and tree, restart SSSD
        3. Authenticate root, child and tree users
    :expectedresults:
        1. All group members can log in when only allow is set
        2. Configuration updates successfully
        3. Root user can log in; child and tree users are denied
    :customerscenario: True
    """
    root_user, child_user, tree_user, root_group, child_group, tree_group = _setup_forest_users_and_groups(
        ad, ad_child, ad_tree
    )

    allow_groups = ",".join(
        (
            ad.fqn(root_group.name),
            ad_child.fqn(child_group.name),
            ad_tree.fqn(tree_group.name),
        )
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "simple"
    client.sssd.dom(join_ad_root.domain)["simple_allow_groups"] = allow_groups
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        assert client.auth.su.password(name, "Secret123"), f"Allow-group login failed for {name}"

    deny_groups = ",".join((ad_child.fqn(child_group.name), ad_tree.fqn(tree_group.name)))
    client.sssd.dom(join_ad_root.domain)["simple_deny_groups"] = deny_groups
    client.sssd.config_apply()
    client.sssd.restart(clean=True)

    assert client.auth.su.password(ad.fqn(root_user.name), "Secret123"), "Root user should still be allowed"
    assert not client.auth.su.password(
        ad_child.fqn(child_user.name), "Secret123"
    ), "Child user should be denied by group"
    assert not client.auth.su.password(ad_tree.fqn(tree_user.name), "Secret123"), "Tree user should be denied by group"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1048102)
def test_adforest__simple_allow_users_with_flatname_format(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Simple allow users works with DOMAIN\\\\user full_name_format
    :setup:
        1. Join forest root
        2. Create users in each domain
        3. Configure full_name_format and simple_allow_users with flat names
        4. Start SSSD
    :steps:
        1. Authenticate allowed users from all domains
        2. Authenticate a non-listed root user
    :expectedresults:
        1. Allowed users can log in
        2. Non-listed user is denied
    :customerscenario: True
    """
    root_user = ad.user("forest-flat-root").add()
    child_user = ad_child.user("forest-flat-child").add()
    tree_user = ad_tree.user("forest-flat-tree").add()
    denied = ad.user("forest-flat-denied").add()

    allow = ",".join(
        (
            f"{_flatname(ad)}\\{root_user.name}",
            f"{_flatname(ad_child)}\\{child_user.name}",
            f"{_flatname(ad_tree)}\\{tree_user.name}",
        )
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "simple"
    client.sssd.dom(join_ad_root.domain)["full_name_format"] = r"%3$s\%1$s"
    client.sssd.dom(join_ad_root.domain)["simple_allow_users"] = allow
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        assert client.auth.su.password(name, "Secret123"), f"Flat-name allow failed for {name}"

    assert not client.auth.su.password(ad.fqn(denied.name), "Secret123"), "Denied flat-name user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
def test_adforest__ad_access_filter_allows_group_members(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: ad_access_filter permits only members of a root-domain group
    :setup:
        1. Join forest root
        2. Create allowed root user in a group and users in other domains
        3. Configure access_provider=ad with memberOf filter
        4. Start SSSD
    :steps:
        1. Authenticate the group member
        2. Authenticate a non-member root user and child/tree users
    :expectedresults:
        1. Group member can log in
        2. Non-members are denied
    :customerscenario: True
    """
    allowed = ad.user("forest-aaf-allowed").add()
    denied_root = ad.user("forest-aaf-denied").add()
    child_user = ad_child.user("forest-aaf-child").add()
    tree_user = ad_tree.user("forest-aaf-tree").add()
    group = ad.group("forest-aaf-group").add().add_member(allowed)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["ad_access_filter"] = f"(memberOf={group.dn})"
    client.sssd.start()

    assert client.auth.su.password(ad.fqn(allowed.name), "Secret123"), "Allowed group member failed login"
    assert not client.auth.su.password(ad.fqn(denied_root.name), "Secret123"), "Non-member root user was allowed"
    assert not client.auth.su.password(ad_child.fqn(child_user.name), "Secret123"), "Child user was allowed"
    assert not client.auth.su.password(ad_tree.fqn(tree_user.name), "Secret123"), "Tree user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__ad_access_filter_dom_syntax_for_tree_domain(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: ad_access_filter DOM: syntax limits access to a tree-domain group
    :setup:
        1. Join forest root
        2. Create tree users and a tree group; create root and child users
        3. Configure DOM:tree filter for the tree group
        4. Start SSSD
    :steps:
        1. Authenticate the tree group member
        2. Authenticate root, child and non-member tree users
    :expectedresults:
        1. Tree group member can log in
        2. Other users are denied
    :customerscenario: True
    """
    tree_allowed = ad_tree.user("forest-dom-tree").add()
    tree_denied = ad_tree.user("forest-dom-tree2").add()
    root_user = ad.user("forest-dom-root").add()
    child_user = ad_child.user("forest-dom-child").add()
    tree_group = ad_tree.group("forest-dom-group").add().add_member(tree_allowed)

    access_filter = f"DOM:{ad_tree.domain}:(memberOf={tree_group.dn})"

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["ad_access_filter"] = access_filter
    client.sssd.start()

    assert client.auth.su.password(ad_tree.fqn(tree_allowed.name), "Secret123"), "Tree member failed login"
    assert not client.auth.su.password(ad.fqn(root_user.name), "Secret123"), "Root user was allowed"
    assert not client.auth.su.password(ad_child.fqn(child_user.name), "Secret123"), "Child user was allowed"
    assert not client.auth.su.password(ad_tree.fqn(tree_denied.name), "Secret123"), "Non-member tree user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1032983)
def test_adforest__ad_access_filter_forest_syntax(client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD):
    """
    :title: ad_access_filter FOREST: syntax does not crash the backend
    :setup:
        1. Join forest root
        2. Create users and a root group
        3. Configure FOREST:realm memberOf filter
        4. Start SSSD
    :steps:
        1. Authenticate the root group member
        2. Authenticate child and tree users
    :expectedresults:
        1. Root group member can log in
        2. Child and tree users are denied and sssd_be does not crash
    :customerscenario: True
    """
    root_user = ad.user("forest-ff-root").add()
    child_user = ad_child.user("forest-ff-child").add()
    tree_user = ad_tree.user("forest-ff-tree").add()
    group = ad.group("forest-ff-group").add().add_member(root_user)

    access_filter = f"FOREST:{ad.realm}:(memberOf={group.dn})"

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["ad_access_filter"] = access_filter
    client.sssd.start()

    assert client.auth.su.password(ad.fqn(root_user.name), "Secret123"), "FOREST filter root login failed"
    assert not client.auth.su.password(ad_child.fqn(child_user.name), "Secret123"), "Child user was allowed"
    assert not client.auth.su.password(ad_tree.fqn(tree_user.name), "Secret123"), "Tree user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1033133)
def test_adforest__invalid_ad_access_filter_does_not_system_error(client: Client, join_ad_root: AD, ad: AD):
    """
    :title: Invalid ad_access_filter reports a bad search filter without system error
    :setup:
        1. Join forest root
        2. Create a user
        3. Configure an invalid ad_access_filter value
        4. Start SSSD
    :steps:
        1. Attempt to authenticate the user
        2. Inspect the domain log
    :expectedresults:
        1. Authentication fails
        2. Log contains a bad search filter message and no System error
    :customerscenario: False
    """
    user = ad.user("forest-badfilter").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["ad_access_filter"] = "group1"
    client.sssd.start()

    name = ad.fqn(user.name)
    assert not client.auth.su.password(name, "Secret123"), "Login unexpectedly succeeded with bad filter"

    log = client.fs.read(f"/var/log/sssd/sssd_{ad.domain}.log")
    assert "Bad search filter" in log or "bad search filter" in log.lower(), "Expected bad search filter in logs"
    assert "System error" not in log, "Unexpected System error in domain log"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__ad_access_provider_denies_expired_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: AD access provider denies expired accounts in all forest domains
    :setup:
        1. Join forest root
        2. Create and expire a user in each domain
        3. Configure access_provider=ad and start SSSD
    :steps:
        1. Attempt to authenticate each expired user
    :expectedresults:
        1. All expired users are denied
    :customerscenario: True
    """
    root_user = ad.user("forest-exp-root").add().expire()
    child_user = ad_child.user("forest-exp-child").add().expire()
    tree_user = ad_tree.user("forest-exp-tree").add().expire()
    for obj in (child_user, tree_user):
        _wait_ad_object(obj.role, obj.dn)
    time.sleep(90)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.start(clean=True)

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        if domain_role != ad:
            time.sleep(30)
        assert not client.auth.su.password(name, "Secret123"), f"Expired user {name} was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1708323)
def test_adforest__ad_enabled_domains_disables_removed_subdomains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Removing a subdomain from ad_enabled_domains disables that subdomain
    :setup:
        1. Join forest root
        2. Create a user in each domain
        3. Configure ad_enabled_domains with all three domains and start SSSD
    :steps:
        1. Resolve users from all domains
        2. Remove the tree domain from ad_enabled_domains and restart
        3. Resolve users again
        4. Restrict ad_enabled_domains to the root only and restart
        5. Resolve users again
    :expectedresults:
        1. All users resolve
        2. Configuration updates
        3. Root and child resolve; tree does not
        4. Configuration updates
        5. Only the root user resolves
    :customerscenario: True
    """
    root_user = ad.user("forest-aed-root").add()
    child_user = ad_child.user("forest-aed-child").add()
    tree_user = ad_tree.user("forest-aed-tree").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["ad_enabled_domains"] = f"{ad.domain}, {ad_child.domain}, {ad_tree.domain}"
    client.sssd.start()

    assert client.tools.id(ad.fqn(root_user.name)) is not None
    assert client.tools.id(ad_child.fqn(child_user.name)) is not None
    assert client.tools.id(ad_tree.fqn(tree_user.name)) is not None

    client.sssd.dom(join_ad_root.domain)["ad_enabled_domains"] = f"{ad.domain}, {ad_child.domain}"
    client.sssd.config_apply()
    client.sssd.restart(clean=True)

    assert client.tools.id(ad.fqn(root_user.name)) is not None
    assert client.tools.id(ad_child.fqn(child_user.name)) is not None
    assert client.tools.id(ad_tree.fqn(tree_user.name)) is None, "Tree user should be disabled"

    client.sssd.dom(join_ad_root.domain)["ad_enabled_domains"] = ad.domain
    client.sssd.config_apply()
    client.sssd.restart(clean=True)

    assert client.tools.id(ad.fqn(root_user.name)) is not None
    assert client.tools.id(ad_child.fqn(child_user.name)) is None, "Child user should be disabled"
    assert client.tools.id(ad_tree.fqn(tree_user.name)) is None, "Tree user should be disabled"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1227863)
def test_adforest__ignore_group_members_inherited_by_subdomains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: ignore_group_members with subdomain_inherit applies to subdomains
    :setup:
        1. Join forest root
        2. Create users and groups in each domain
        3. Start SSSD without ignore_group_members
    :steps:
        1. Confirm groups list their members
        2. Enable ignore_group_members and subdomain_inherit, restart
        3. Resolve the same groups again
    :expectedresults:
        1. Groups include members
        2. Configuration updates
        3. Groups resolve but members are not listed
    :customerscenario: True
    """
    root_user, child_user, tree_user, root_group, child_group, tree_group = _setup_forest_users_and_groups(
        ad, ad_child, ad_tree
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    for user, group, domain_role in (
        (root_user, root_group, ad),
        (child_user, child_group, ad_child),
        (tree_user, tree_group, ad_tree),
    ):
        gname = domain_role.fqn(group.name)
        _wait_client_getent_group(client, gname)
        gresult = client.tools.getent.group(gname)
        assert gresult is not None, f"getent group failed for {gname}"
        assert any(user.name in m for m in gresult.members), f"Expected member listing for {gname}"

    client.sssd.dom(join_ad_root.domain)["ignore_group_members"] = "True"
    client.sssd.dom(join_ad_root.domain)["subdomain_inherit"] = "ignore_group_members"
    client.sssd.config_apply()
    client.sssd.restart(clean=True)

    for group, domain_role in (
        (root_group, ad),
        (child_group, ad_child),
        (tree_group, ad_tree),
    ):
        gname = domain_role.fqn(group.name)
        gresult = client.tools.getent.group(gname)
        assert gresult is not None, f"getent group failed for {gname}"
        assert not gresult.members, f"Expected empty member list for {gname} with ignore_group_members"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[974150, 1263735, 1077328, 1090653, 1097323])
def test_adforest__lookup_and_auth_when_joined_to_child(
    client: Client, join_ad_child: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Lookup and authenticate forest users when joined to the child domain
    :setup:
        1. Join the child domain
        2. Create users in root, child and tree
        3. Import the child domain and start SSSD
    :steps:
        1. Resolve users from child, root and tree
        2. Authenticate the child-domain user
    :expectedresults:
        1. Users from the joined child and trusted domains resolve
        2. Authentication of the child user succeeds
    :customerscenario: True
    """
    root_user = ad.user("forest-cj-root").add()
    child_user = ad_child.user("forest-cj-child").add()
    tree_user = ad_tree.user("forest-cj-tree").add()

    _ad_forest_configure_sssd(client, join_ad_child, ad)
    client.sssd.dom(join_ad_child.domain)["debug_level"] = "0xFFF0"
    client.sssd.start()

    assert client.tools.id(ad_child.fqn(child_user.name)) is not None
    _wait_client_lookup(client, ad.fqn(root_user.name))
    _wait_client_lookup(client, ad_tree.fqn(tree_user.name))
    assert client.auth.su.password(ad_child.fqn(child_user.name), "Secret123"), "Child-domain authentication failed"

    log = client.fs.read(f"/var/log/sssd/sssd_{join_ad_child.domain}.log")
    assert f"_gc._tcp.Default-First-Site-Name._sites.{ad.domain}" in log, "Expected GC SRV lookup in domain log"
    assert (
        f"SRV resolution of service 'ldap'. Will use DNS discovery domain '{ad.domain}'" in log
    ), "Expected forest root DNS discovery in domain log"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[974150, 1077328, 1090653, 1097323])
def test_adforest__lookup_and_auth_when_joined_to_tree(
    client: Client, join_ad_tree: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Lookup and authenticate forest users when joined to the tree domain
    :setup:
        1. Join the tree domain
        2. Create users in root, child and tree
        3. Import the tree domain and start SSSD
    :steps:
        1. Resolve users from tree, root and child
        2. Authenticate the tree-domain user
    :expectedresults:
        1. Users from the joined tree and trusted domains resolve
        2. Authentication of the tree user succeeds
    :customerscenario: True
    """
    root_user = ad.user("forest-tj-root").add()
    child_user = ad_child.user("forest-tj-child").add()
    tree_user = ad_tree.user("forest-tj-tree").add()

    _ad_forest_configure_sssd(client, join_ad_tree, ad)
    client.sssd.dom(join_ad_tree.domain)["debug_level"] = "9"
    client.sssd.start()

    assert client.tools.id(ad_tree.fqn(tree_user.name)) is not None
    assert client.tools.id(ad.fqn(root_user.name)) is not None
    assert client.tools.id(ad_child.fqn(child_user.name)) is not None
    assert client.auth.su.password(ad_tree.fqn(tree_user.name), "Secret123"), "Tree-domain authentication failed"

    log = client.fs.read(f"/var/log/sssd/sssd_{join_ad_tree.domain}.log")
    assert f"_gc._tcp.Default-First-Site-Name._sites.{ad.domain}" in log, "Expected GC SRV lookup in domain log"
    assert (
        f"SRV resolution of service 'ldap'. Will use DNS discovery domain '{ad.domain}'" in log
    ), "Expected forest root DNS discovery in domain log"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1066096)
def test_adforest__posix_attributes_without_global_catalog(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: POSIX home and shell are read when ad_enable_gc is false
    :setup:
        1. Join forest root
        2. Create POSIX users with uid/gid/home/shell in each domain
        3. Configure ldap_id_mapping=False and ad_enable_gc=False
        4. Start SSSD
    :steps:
        1. getent passwd for each POSIX user
    :expectedresults:
        1. uid, gid, home and shell match the directory attributes
    :customerscenario: True
    """
    root_user = ad.user("forest-posix-root").add(
        uid=11100,
        gid=11100,
        home=f"/home2/{ad.domain}/forest-posix-root",
        shell="/bin/ksh",
    )
    child_user = ad_child.user("forest-posix-child").add(
        uid=12100,
        gid=12100,
        home=f"/home2/{ad_child.domain}/forest-posix-child",
        shell="/bin/ksh",
    )
    tree_user = ad_tree.user("forest-posix-tree").add(
        uid=13100,
        gid=13100,
        home=f"/home2/{ad_tree.domain}/forest-posix-tree",
        shell="/bin/ksh",
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["ldap_id_mapping"] = "False"
    client.sssd.dom(join_ad_root.domain)["ad_enable_gc"] = "False"
    client.sssd.start()

    for user, domain_role, uid in (
        (root_user, ad, 11100),
        (child_user, ad_child, 12100),
        (tree_user, ad_tree, 13100),
    ):
        name = domain_role.fqn(user.name)
        result = client.tools.getent.passwd(name)
        assert result is not None, f"getent passwd failed for {name}"
        assert result.uid == uid, f"Unexpected uid for {name}: {result.uid}"
        assert result.gid == uid, f"Unexpected gid for {name}: {result.gid}"
        assert result.home == f"/home2/{domain_role.domain}/{user.name}"
        assert result.shell == "/bin/ksh"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1523282)
def test_adforest__join_root_into_organizational_unit(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    :title: Join forest root placing the computer object in a custom OU
    :setup:
        1. Create an OU on the forest root
    :steps:
        1. Join the client to the root domain with computer-ou pointing at the OU
        2. Import the domain, start SSSD and resolve administrators from each domain
        3. Leave the domain on teardown path
    :expectedresults:
        1. Join succeeds
        2. Forest users/admins from root, child and tree resolve
        3. Leave succeeds
    :customerscenario: True
    """
    forest = (ad, ad_child, ad_tree)
    short = "client003"
    _ad_forest_remove_linuxservers_ou(ad)
    ou = ad.ou("linuxservers").add()

    old_hostname = client.host.conn.run("hostname").stdout.strip()
    client.fs.write("/etc/hostname", f"{short}.{ad.domain}\n")
    client.host.conn.run(f"hostname {short}.{ad.domain}", raise_on_error=False)

    for domain in forest:
        client.host.conn.exec(["realm", "leave", domain.domain], raise_on_error=False)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")
    _ad_forest_remove_stale_computer(forest, short)

    join = client.host.conn.exec(
        ["realm", "join", f"--computer-ou={ou.dn}", ad.domain],
        input=ad.host.adminpw,
        raise_on_error=False,
    )
    assert join.rc == 0, f"realm join into OU failed: {join.stderr}"

    try:
        client.sssd.import_domain(ad.domain, ad)
        client.sssd.dom(ad.domain)["use_fully_qualified_names"] = "True"
        client.sssd.start()

        assert client.tools.id(ad.fqn("Administrator")) is not None
        assert client.tools.id(ad_child.fqn("Administrator")) is not None
        assert client.tools.id(ad_tree.fqn("Administrator")) is not None
    finally:
        client.host.conn.exec(["realm", "leave", ad.domain], raise_on_error=False)
        _ad_forest_remove_stale_computer(forest, short)
        _ad_forest_remove_linuxservers_ou(ad)
        client.fs.write("/etc/hostname", f"{old_hostname}\n")
        client.host.conn.run(f"hostname {old_hostname}", raise_on_error=False)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2013297)
def test_adforest__ad_enabled_domains_when_joined_to_child(client: Client, join_ad_child: AD, ad: AD, ad_child: AD):
    """
    :title: ad_enabled_domains restricts the root when the client is joined to the child
    :setup:
        1. Join the child domain
        2. Create users in the root and child domains
        3. Start SSSD without ad_enabled_domains
    :steps:
        1. Resolve root and child users
        2. Set ad_enabled_domains to the child domain only and restart
        3. Resolve root and child users again
    :expectedresults:
        1. Both users resolve
        2. Configuration updates
        3. Child user resolves; root user does not
    :customerscenario: True
    """
    root_user = ad.user("forest-aed-cj-root").add()
    child_user = ad_child.user("forest-aed-cj-child").add()

    _ad_forest_configure_sssd(client, join_ad_child, ad)
    client.sssd.start()

    assert client.tools.getent.passwd(ad.fqn(root_user.name)) is not None
    assert client.tools.getent.passwd(ad_child.fqn(child_user.name)) is not None

    client.sssd.dom(join_ad_child.domain)["ad_enabled_domains"] = ad_child.domain
    client.sssd.config_apply()
    client.sssd.restart(clean=True)

    assert client.tools.getent.passwd(ad.fqn(root_user.name)) is None, "Root user should be disabled"
    assert client.tools.getent.passwd(ad_child.fqn(child_user.name)) is not None


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2018432)
def test_adforest__sssctl_domain_list_matches_forest(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: sssctl domain-list reports only the forest domains
    :setup:
        1. Join the forest root
        2. Start SSSD
    :steps:
        1. Run sssctl domain-list
    :expectedresults:
        1. Listed domains match root, child and tree (implicit_files ignored)
    :customerscenario: True
    """
    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    result = client.host.conn.exec(["sssctl", "domain-list"], raise_on_error=False)
    assert result.rc == 0, f"sssctl domain-list failed: {result.stderr}"

    listed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    listed.discard("implicit_files")

    expected = {ad.domain, ad_child.domain, ad_tree.domain}
    assert listed == expected, f"domain-list {listed} != forest domains {expected}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2167728)
def test_adforest__lookup_when_joined_to_child_without_krb5_domain_realm(
    client: Client, join_ad_child: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Forest lookups work when joined to child with empty krb5 domain_realm
    :setup:
        1. Join the child domain
        2. Create users in root, child and tree
        3. Remove domain_realm mappings for forest domains from /etc/krb5.conf
        4. Start SSSD
    :steps:
        1. Resolve users from root, child and tree
    :expectedresults:
        1. All three users resolve
    :customerscenario: True
    """
    root_user = ad.user("forest-krb5-root").add()
    child_user = ad_child.user("forest-krb5-child").add()
    tree_user = ad_tree.user("forest-krb5-tree").add()

    client.fs.backup("/etc/krb5.conf")
    try:
        krb5 = client.fs.read("/etc/krb5.conf")
        for domain_role in (ad, ad_child, ad_tree):
            domain = domain_role.domain
            realm = domain_role.realm
            # Drop both "domain = REALM" and ".domain = REALM" style mappings
            krb5 = re.sub(rf"(?m)^\.{re.escape(domain)}\s*=\s*{re.escape(realm)}\s*$", "", krb5)
            krb5 = re.sub(rf"(?m)^{re.escape(domain)}\s*=\s*{re.escape(realm)}\s*$", "", krb5)
            # Also drop capitalized legacy forms used in older suites
            krb5 = re.sub(
                rf"(?m)^\.{re.escape(domain)}\s*=\s*{re.escape(domain.capitalize())}\s*$",
                "",
                krb5,
            )
            krb5 = re.sub(
                rf"(?m)^{re.escape(domain)}\s*=\s*{re.escape(domain.capitalize())}\s*$",
                "",
                krb5,
            )
        client.fs.write("/etc/krb5.conf", krb5)

        _ad_forest_configure_sssd(client, join_ad_child, ad)
        client.sssd.start()

        assert client.tools.getent.passwd(ad_child.fqn(child_user.name)) is not None
        _wait_client_lookup(client, ad.fqn(root_user.name))
        _wait_client_lookup(client, ad_tree.fqn(tree_user.name))
        assert client.tools.getent.passwd(ad.fqn(root_user.name)) is not None
        assert client.tools.getent.passwd(ad_tree.fqn(tree_user.name)) is not None
    finally:
        client.fs.restore("/etc/krb5.conf")


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1913284, jira=["SSSD-3092", "RHEL-4974"])
@pytest.mark.require(
    lambda client: client.features.get("non-privileged", False),
    "SSSD was built without support for running under non-root",
)
def test_adforest__keytab_readable_when_joined_to_child_as_nonroot(
    client: Client, join_ad_child: AD, ad: AD, ad_child: AD
):
    """
    :title: Non-root SSSD can read the keytab when joined to the child domain
    :setup:
        1. Join the child domain
        2. Create users in the root and child domains
        3. Start SSSD as the unprivileged sssd user
    :steps:
        1. Resolve root and child users
        2. Inspect the child domain log for keytab permission errors
    :expectedresults:
        1. Both users resolve
        2. Keytab permission / suitable-principal errors are absent
    :customerscenario: True
    """
    root_user = ad.user("forest-nonroot-root").add()
    child_user = ad_child.user("forest-nonroot-child").add()

    _ad_forest_configure_sssd(client, join_ad_child, ad)
    client.sssd.start(service_user="sssd")

    assert client.tools.getent.passwd(ad.fqn(root_user.name)) is not None
    assert client.tools.getent.passwd(ad_child.fqn(child_user.name)) is not None

    log = client.fs.read(f"/var/log/sssd/sssd_{ad_child.domain}.log")
    assert "krb5_kt_start_seq_get failed: Permission denied" not in log
    assert "Failed to read keytab [FILE:/etc/krb5.keytab]: No suitable principal found in keytab" not in log


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1002591)
def test_adforest__enterprise_upn_cached_credentials_work_offline(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Enterprise UPN users authenticate with cached credentials when offline
    :setup:
        1. Join forest root
        2. Create enterprise UPN users in root, child and tree domains
        3. Configure cache_credentials and krb5_store_password_if_offline
        4. Authenticate all users online to populate the credential cache
    :steps:
        1. Block network to all forest DCs and restart SSSD offline
        2. Authenticate each enterprise UPN user
        3. Inspect the domain log for delayed online authentication entries
    :expectedresults:
        1. SSSD starts offline
        2. All enterprise UPN users authenticate successfully
        3. Domain log records delayed online authentication for each user
    :customerscenario: True
    """
    root_upn = f"ent-offline-root@{ad.domain}"
    child_upn = f"ent-offline-child@{ad_child.domain}"
    tree_upn = f"ent-offline-tree@{ad_tree.domain}"

    ad.user("ent-offline-root").add(upn=root_upn)
    ad_child.user("ent-offline-child").add(upn=child_upn)
    ad_tree.user("ent-offline-tree").add(upn=tree_upn)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["krb5_store_password_if_offline"] = "True"
    client.sssd.start()

    for upn in (root_upn, child_upn, tree_upn):
        assert client.auth.ssh.password(upn, "Secret123"), f"Online auth failed for {upn}"
        assert client.auth.su.password(upn, "Secret123"), f"Online su auth failed for {upn}"

    _ad_forest_block_servers(client, ad, ad_child, ad_tree)
    client.sssd.restart()

    for upn in (root_upn, child_upn, tree_upn):
        assert client.auth.su.password(upn, "Secret123"), f"Offline auth failed for {upn}"

    log = client.fs.read(client.sssd.logs.domain())
    for upn in (root_upn, child_upn, tree_upn):
        assert "delayed online authentication" in log, f"Missing delayed online auth log for {upn}"
        assert upn in log, f"UPN {upn} missing from delayed online auth log"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1038637)
def test_adforest__subdomain_list_not_fetched_when_sssd_starts_offline(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: SSSD skips subdomain list refresh when it starts offline
    :setup:
        1. Join forest root and create enterprise UPN users in all domains
        2. Configure cache_credentials and authenticate online
        3. Block network to all forest DCs
    :steps:
        1. Restart SSSD while offline
        2. Authenticate root, child and tree enterprise UPN users
        3. Inspect the domain log for subdomain refresh messages
    :expectedresults:
        1. SSSD restarts in offline mode
        2. All users authenticate with cached credentials
        3. Log shows refresh callback and offline subdomain skip message
    :customerscenario: True
    """
    root_upn = f"ent-sub-off-root@{ad.domain}"
    child_upn = f"ent-sub-off-child@{ad_child.domain}"
    tree_upn = f"ent-sub-off-tree@{ad_tree.domain}"

    ad.user("ent-sub-off-root").add(upn=root_upn)
    ad_child.user("ent-sub-off-child").add(upn=child_upn)
    ad_tree.user("ent-sub-off-tree").add(upn=tree_upn)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["krb5_store_password_if_offline"] = "True"
    client.sssd.dom(join_ad_root.domain)["debug_level"] = "0x0080"
    client.sssd.start()

    for upn in (root_upn, child_upn, tree_upn):
        assert client.auth.su.password(upn, "Secret123"), f"Online auth failed for {upn}"

    _ad_forest_block_servers(client, ad, ad_child, ad_tree)
    client.sssd.restart()
    time.sleep(5)

    for upn in (root_upn, child_upn, tree_upn):
        assert client.auth.su.password(upn, "Secret123"), f"Offline auth failed for {upn}"

    log = client.fs.read(client.sssd.logs.domain())
    assert "ad_subdomains_refresh_connect_done" in log
    assert "cannot get the subdomain list while offline" in log


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1200093)
def test_adforest__initgroups_by_nonexistent_upn_does_not_crash(client: Client, join_ad_root: AD, ad: AD):
    """
    :title: initgroups with a nonexistent UPN does not crash sssd_nss
    :setup:
        1. Join forest root and start SSSD
        2. Compile a helper that calls initgroups(upn, 0)
    :steps:
        1. Run the helper with a nonexistent UPN
        2. Inspect sssd_nss.log and verify sssd_nss is still running
    :expectedresults:
        1. Helper exits successfully
        2. No segfault is logged and sssd_nss remains alive
    :customerscenario: True
    """
    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start()

    c_src = (
        "#include <sys/types.h>\n"
        "#include <grp.h>\n"
        "#include <stdio.h>\n"
        "int main(int argc, char *argv[]) {\n"
        "    if (argc < 2) return 1;\n"
        "    initgroups(argv[1], 0);\n"
        "    return 0;\n"
        "}\n"
    )
    client.fs.write("/tmp/test_initgroups.c", c_src)
    client.host.conn.run("dnf install -y gcc", raise_on_error=False)
    compile = client.host.conn.run("gcc /tmp/test_initgroups.c -o /tmp/test_initgroups", raise_on_error=False)
    assert compile.rc == 0, f"gcc failed: {compile.stderr}"

    upn = f"nonexistent@{ad.domain}"
    result = client.host.conn.run(f"/tmp/test_initgroups '{upn}'", raise_on_error=False)
    assert result.rc == 0, f"initgroups helper failed with rc={result.rc}"

    nss_log = client.fs.read(client.sssd.logs.nss)
    assert "segfault" not in nss_log.lower(), "sssd_nss segfaulted on initgroups with nonexistent UPN"

    svc = client.host.conn.run("systemctl is-active sssd", raise_on_error=False)
    assert svc.stdout.strip() == "active", "sssd is not running after initgroups call"

    client.host.conn.run("rm -f /tmp/test_initgroups.c /tmp/test_initgroups", raise_on_error=False)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__group_rename_reflected_after_cache_invalidation(client: Client, join_ad_root: AD, ad: AD):
    """
    :title: Group rename is reflected after sss_cache invalidation
    :setup:
        1. Join forest root and create a user in a group
        2. Configure entry_cache_timeout and ldap_id_mapping=False
        3. Start SSSD and confirm membership in the old group name
    :steps:
        1. Rename the group on AD
        2. Run sss_cache -UG and wait for cache timeout
        3. Resolve the user again
    :expectedresults:
        1. Group is renamed on AD
        2. Cache is invalidated
        3. id shows the new group name and not the old one
    :customerscenario: False
    """
    user = ad.user("rename-user1").add(uid=20001, gid=20001)
    old_group = ad.group("old-rename-group").add(gid=20002).add_member(user)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["entry_cache_timeout"] = "20"
    client.sssd.dom(join_ad_root.domain)["ldap_id_mapping"] = "False"
    client.sssd.start()

    name = ad.fqn(user.name)
    result = client.tools.id(name)
    assert result is not None
    assert result.memberof(ad.fqn("old-rename-group")) or result.memberof("old-rename-group")

    _rename_ad_group(old_group, "new-rename-group")
    client.host.conn.exec(["sss_cache", "-g", "old-rename-group"])
    client.host.conn.exec(["sss_cache", "-u", user.name])
    time.sleep(20)

    result2 = client.tools.id(name)
    assert result2 is not None, "id failed after group rename"
    assert not (
        result2.memberof(ad.fqn("old-rename-group")) or result2.memberof("old-rename-group")
    ), "Old group name still visible after cache invalidation"
    assert result2.memberof(ad.fqn("new-rename-group")) or result2.memberof(
        "new-rename-group"
    ), "New group name not visible after cache invalidation"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__ad_access_filter_single_user_by_cn(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: ad_access_filter cn= allows only a single root-domain user
    :setup:
        1. Join forest root and create allowed and denied users in each domain
        2. Configure access_provider=ad with ad_access_filter=(cn=<user>)
    :steps:
        1. Authenticate the allowed root user
        2. Authenticate denied users from root, child and tree
    :expectedresults:
        1. Allowed user can log in
        2. All other users are denied
    :customerscenario: True
    """
    allowed = ad.user("forest-cn-allowed").add()
    denied_root = ad.user("forest-cn-denied").add()
    denied_child = ad_child.user("forest-cn-child").add()
    denied_tree = ad_tree.user("forest-cn-tree").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "ad"
    client.sssd.dom(join_ad_root.domain)["ad_access_filter"] = f"(cn={allowed.name})"
    client.sssd.start()

    assert client.auth.su.password(ad.fqn(allowed.name), "Secret123"), "Allowed user failed login"
    assert not client.auth.su.password(ad.fqn(denied_root.name), "Secret123"), "Denied root user was allowed"
    assert not client.auth.su.password(ad_child.fqn(denied_child.name), "Secret123"), "Child user was allowed"
    assert not client.auth.su.password(ad_tree.fqn(denied_tree.name), "Secret123"), "Tree user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__access_provider_defaults_to_ad_denies_expired_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Implicit AD access provider denies expired users in all forest domains
    :setup:
        1. Join forest root without setting access_provider explicitly
        2. Create and expire a user in each domain
    :steps:
        1. Attempt to authenticate each expired user
    :expectedresults:
        1. All expired users are denied
    :customerscenario: True
    """
    root_user = ad.user("forest-defexp-root").add().expire()
    child_user = ad_child.user("forest-defexp-child").add().expire()
    tree_user = ad_tree.user("forest-defexp-tree").add().expire()
    for obj in (child_user, tree_user):
        _wait_ad_object(obj.role, obj.dn)
    time.sleep(90)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.start(clean=True)

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        if domain_role != ad:
            time.sleep(30)
        assert not client.auth.su.password(name, "Secret123"), f"Expired user {name} was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=966557)
def test_adforest__enterprise_upn_with_two_explicit_ad_domains(client: Client, join_ad_root: AD, ad: AD, ad_child: AD):
    """
    :title: Enterprise UPN login works with two explicit AD domain sections
    :setup:
        1. Join forest root
        2. Create enterprise UPN users in root and child domains
        3. Import both domains into sssd.conf
    :steps:
        1. Authenticate each enterprise UPN user
    :expectedresults:
        1. Both users authenticate successfully
    :customerscenario: True
    """
    root_upn = f"ent-two-dom-root@{ad.domain}"
    child_upn = f"ent-two-dom-child@{ad_child.domain}"

    ad.user("ent-two-dom-root").add(upn=root_upn)
    ad_child.user("ent-two-dom-child").add(upn=child_upn)

    client.sssd.import_domain(ad.domain, ad)
    client.sssd.import_domain(ad_child.domain, ad_child)
    for domain_name in (ad.domain, ad_child.domain):
        dom = client.sssd.dom(domain_name)
        dom["use_fully_qualified_names"] = "True"
        dom["fallback_homedir"] = "/home/%d/%u"
        dom["cache_credentials"] = "True"
        dom["krb5_store_password_if_offline"] = "True"
        dom["access_provider"] = "ad"
    client.sssd.start()

    assert client.auth.su.password(root_upn, "Secret123"), "Root enterprise UPN login failed"
    assert client.auth.su.password(child_upn, "Secret123"), "Child enterprise UPN login failed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__simple_deny_users_across_domains(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Simple access provider deny_users blocks child and tree users
    :setup:
        1. Join forest root and create users in each domain
        2. Allow only the root user and deny child and tree users
    :steps:
        1. Authenticate root user
        2. Authenticate child and tree users
    :expectedresults:
        1. Root user can log in
        2. Child and tree users are denied
    :customerscenario: True
    """
    root_user = ad.user("forest-sdu-root").add()
    child_user = ad_child.user("forest-sdu-child").add()
    tree_user = ad_tree.user("forest-sdu-tree").add()

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "simple"
    client.sssd.dom(join_ad_root.domain)["simple_allow_users"] = ad.fqn(root_user.name)
    client.sssd.dom(join_ad_root.domain)["simple_deny_users"] = ",".join(
        (ad_child.fqn(child_user.name), ad_tree.fqn(tree_user.name))
    )
    client.sssd.start()

    assert client.auth.su.password(ad.fqn(root_user.name), "Secret123"), "Root user should be allowed"
    assert not client.auth.su.password(
        ad_child.fqn(child_user.name), "Secret123"
    ), "Child user should be denied by simple_deny_users"
    assert not client.auth.su.password(
        ad_tree.fqn(tree_user.name), "Secret123"
    ), "Tree user should be denied by simple_deny_users"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1125187)
def test_adforest__simple_allow_groups_with_flatname_format(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: Simple allow groups works with DOMAIN\\\\group flat name format
    :setup:
        1. Join forest root and create users and groups in each domain
        2. Configure full_name_format and simple_allow_groups with flat names
    :steps:
        1. Authenticate group members from all domains
        2. Authenticate a non-member root user
    :expectedresults:
        1. Group members can log in
        2. Non-member is denied
    :customerscenario: True
    """
    root_user, child_user, tree_user, root_group, child_group, tree_group = _setup_forest_users_and_groups(
        ad, ad_child, ad_tree
    )
    denied = ad.user("forest-flat-denied").add()

    allow_groups = ",".join(
        (
            f"{_flatname(ad)}\\{root_group.name}",
            f"{_flatname(ad_child)}\\{child_group.name}",
            f"{_flatname(ad_tree)}\\{tree_group.name}",
        )
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["access_provider"] = "simple"
    client.sssd.dom(join_ad_root.domain)["full_name_format"] = r"%3$s\%1$s"
    client.sssd.dom(join_ad_root.domain)["simple_allow_groups"] = allow_groups
    client.sssd.start()

    for user, domain_role in (
        (root_user, ad),
        (child_user, ad_child),
        (tree_user, ad_tree),
    ):
        name = domain_role.fqn(user.name)
        assert client.auth.su.password(name, "Secret123"), f"Flat-name group allow failed for {name}"

    assert not client.auth.su.password(ad.fqn(denied.name), "Secret123"), "Non-member user was allowed"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1033081)
def test_adforest__posix_attributes_detected_from_global_catalog(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: POSIX attributes are read from the global catalog for forest users
    :setup:
        1. Join forest root
        2. Create POSIX users in root, child and tree domains
        3. Configure ldap_id_mapping=False with default ad_enable_gc
    :steps:
        1. getent passwd for each POSIX user
    :expectedresults:
        1. uid, gid, home and shell match directory attributes for all domains
    :customerscenario: True
    """
    users = (
        (
            ad.user("forest-gc-posix-root").add(
                uid=11000,
                gid=11000,
                home=f"/home2/{ad.domain}/forest-gc-posix-root",
                shell="/bin/ksh",
            ),
            ad,
            11000,
        ),
        (
            ad_child.user("forest-gc-posix-chld").add(
                uid=12000,
                gid=12000,
                home=f"/home2/{ad_child.domain}/forest-gc-posix-chld",
                shell="/bin/ksh",
            ),
            ad_child,
            12000,
        ),
        (
            ad_tree.user("forest-gc-posix-tree").add(
                uid=13000,
                gid=13000,
                home=f"/home2/{ad_tree.domain}/forest-gc-posix-tree",
                shell="/bin/ksh",
            ),
            ad_tree,
            13000,
        ),
    )

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["ldap_id_mapping"] = "False"
    client.sssd.start()

    for user, domain_role, uid in users:
        name = domain_role.fqn(user.name)
        result = client.tools.getent.passwd(name)
        assert result is not None, f"getent passwd failed for {name}"
        assert result.uid == uid, f"Unexpected uid for {name}: {result.uid}"
        assert result.gid == uid, f"Unexpected gid for {name}: {result.gid}"
        assert result.home == f"/home2/{domain_role.domain}/{user.name}"
        assert result.shell == "/bin/ksh"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1072995)
def test_adforest__id_results_consistent_across_cache_refresh(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD
):
    """
    :title: id output stays consistent across cache refresh
    :setup:
        1. Join forest root and create users with cross-domain group memberships
        2. Configure a short entry_cache_timeout and start SSSD
    :steps:
        1. Run id for forest users and capture output
        2. Wait for cache timeout and run id again
    :expectedresults:
        1. id output is captured for forest users
        2. Group membership output is unchanged after cache refresh
    :customerscenario: True
    """
    root_user, child_user, tree_user, _, _, _ = _setup_forest_users_and_groups(ad, ad_child, ad_tree)
    _setup_forest_shared_group(ad, root_user, child_user, tree_user)

    _ad_forest_configure_sssd(client, join_ad_root)
    client.sssd.dom(join_ad_root.domain)["entry_cache_timeout"] = "20"
    client.sssd.start()

    snapshots = {
        ad.fqn(root_user.name): _id_output(client, ad.fqn(root_user.name)),
        ad_child.fqn(child_user.name): _id_output(client, ad_child.fqn(child_user.name)),
        ad_tree.fqn(tree_user.name): _id_output(client, ad_tree.fqn(tree_user.name)),
    }

    time.sleep(25)

    for name, before in snapshots.items():
        after = _id_output(client, name)
        assert after == before, f"id output changed for {name} after cache refresh"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.importance("medium")
def test_adforest__kdcinfo_files_exist_for_joined_and_parent_domain(
    client: Client, join_ad_child: AD, ad: AD, ad_child: AD
):
    """
    :title: kdcinfo files exist for the joined child and parent root domains
    :setup:
        1. Join the child domain and start SSSD
    :steps:
        1. List kdcinfo files under /var/lib/sss/pubconf
    :expectedresults:
        1. kdcinfo files exist for child and root realms
    :customerscenario: True
    """
    _ad_forest_configure_sssd(client, join_ad_child, ad)
    client.sssd.start()

    for realm in (ad_child.realm, ad.realm):
        path = f"/var/lib/sss/pubconf/kdcinfo.{realm}"
        assert client.fs.exists(path), f"Missing kdcinfo file for realm {realm}: {path}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize(
    "join_fixture,joined",
    [
        ("join_ad_root", "ad"),
        ("join_ad_child", "ad_child"),
        ("join_ad_tree", "ad_tree"),
    ],
)
@pytest.mark.importance("medium")
def test_adforest__kinit_with_host_keytab_across_join_domains(
    client: Client,
    ad: AD,
    ad_child: AD,
    ad_tree: AD,
    join_fixture: str,
    joined: str,
    request: pytest.FixtureRequest,
):
    """
    :title: kinit succeeds with host and machine account principals after forest join
    :setup:
        1. Join the parametrized forest domain and start SSSD
    :steps:
        1. kinit with the host principal from the keytab
        2. kinit with the machine account principal from the keytab
    :expectedresults:
        1. Host principal kinit succeeds
        2. Machine account principal kinit succeeds
    :customerscenario: True
    """
    domains = {"ad": ad, "ad_child": ad_child, "ad_tree": ad_tree}
    domain = domains[joined]
    join = request.getfixturevalue(join_fixture)

    _ad_forest_rejoin_with_host_upn(client, domain, (ad, ad_child, ad_tree))
    _ad_forest_configure_sssd(client, join, ad if joined != "ad" else None)
    client.sssd.start()

    hostname = client.host.conn.run("hostname -f").stdout.strip()
    short = hostname.split(".")[0].upper()
    realm = domain.realm

    host_kinit = client.host.conn.run(f"kinit -k host/{hostname}@{realm}", raise_on_error=False)
    assert host_kinit.rc == 0, f"host principal kinit failed: {host_kinit.stderr}"

    machine_kinit = client.host.conn.run(f"kinit -k '{short}$@{realm}'", raise_on_error=False)
    assert machine_kinit.rc == 0, f"machine account kinit failed: {machine_kinit.stderr}"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("joined_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1523282)
def test_adforest__join_subdomain_into_organizational_unit(
    client: Client, ad: AD, ad_child: AD, ad_tree: AD, joined_name: str
):
    """
    :title: Join child or tree domain placing the computer object in a custom OU
    :setup:
        1. Create an OU on the target subdomain
    :steps:
        1. Join the client to the subdomain with computer-ou pointing at the OU
        2. Start SSSD and resolve administrators from each forest domain
        3. Leave the domain on teardown
    :expectedresults:
        1. Join succeeds
        2. Forest admins from root, child and tree resolve
        3. Leave succeeds
    :customerscenario: True
    """
    domain = ad_child if joined_name == "child" else ad_tree
    short = "client033" if joined_name == "child" else "client022"
    forest = (ad, ad_child, ad_tree)
    _ad_forest_remove_linuxservers_ou(domain)
    ou = domain.ou("linuxservers").add()

    old_hostname = client.host.conn.run("hostname").stdout.strip()
    client.fs.write("/etc/hostname", f"{short}.{domain.domain}\n")
    client.host.conn.run(f"hostname {short}.{domain.domain}", raise_on_error=False)

    for forest_domain in forest:
        client.host.conn.exec(["realm", "leave", forest_domain.domain], raise_on_error=False)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")
    _ad_forest_remove_stale_computer(forest, short)

    join = client.host.conn.exec(
        ["realm", "join", f"--computer-ou={ou.dn}", domain.domain],
        input=domain.host.adminpw,
        raise_on_error=False,
    )
    assert join.rc == 0, f"realm join into OU failed: {join.stderr}"

    try:
        client.sssd.import_domain(domain.domain, domain)
        client.sssd.dom(domain.domain)["use_fully_qualified_names"] = "True"
        if domain.domain != ad.domain:
            client.sssd.dom(domain.domain)["ad_server"] = "_srv_"
        client.sssd.start()

        assert client.tools.id(ad.fqn("Administrator")) is not None
        assert client.tools.id(ad_child.fqn("Administrator")) is not None
        assert client.tools.id(ad_tree.fqn("Administrator")) is not None
    finally:
        client.host.conn.exec(["realm", "leave", domain.domain], raise_on_error=False)
        _ad_forest_remove_stale_computer(forest, short)
        _ad_forest_remove_linuxservers_ou(domain)
        client.fs.write("/etc/hostname", f"{old_hostname}\n")
        client.host.conn.run(f"hostname {old_hostname}", raise_on_error=False)

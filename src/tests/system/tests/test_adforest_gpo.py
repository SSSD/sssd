"""
SSSD AD Forest GPO HBAC multi-domain test cases.

Ports coverage from the legacy IdM-CI / sssd-qe ``ad_gpo_hbac_multidomain`` suite.
Client joins the forest root; GPOs are created on the root; users live in the
child or tree domain (parametrized).

:requirement: adforest gpo
"""

from __future__ import annotations

import pytest
from pytest_mh.conn import ProcessError
from sssd_test_framework.fixtures import _ad_forest_configure_sssd
from sssd_test_framework.roles.ad import AD, GPO
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


def _trusted(ad_child: AD, ad_tree: AD, trusted_name: str) -> AD:
    return ad_child if trusted_name == "child" else ad_tree


def _configure_gpo(client: Client, joined: AD, mode: str, **opts: str) -> None:
    _ad_forest_configure_sssd(client, joined)
    dom = client.sssd.dom(joined.domain)
    dom["access_provider"] = "ad"
    dom["ad_gpo_access_control"] = mode
    for key, value in opts.items():
        dom[key] = value


@pytest.fixture(autouse=True)
def scrub_orphan_gpo_links(join_ad_root: AD):
    """Drop stale domain/site GPO links left by earlier tests before each case runs."""
    join_ad_root.scrub_orphan_gpo_links()
    yield
    join_ad_root.scrub_orphan_gpo_links()


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__disabled_allows_all_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO disabled allows all trusted-domain users while joined to root
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a restrictive site GPO
        3. Configure ad_gpo_access_control=disabled and start SSSD
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Both users can log in via su
        2. Both users can log in via ssh
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "disabled")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.su.password(
            trusted.fqn(deny_user1.name), "Secret123"
        ), "Denied user failed login with GPO disabled!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.ssh.password(
            trusted.fqn(deny_user1.name), "Secret123"
        ), "Denied user failed login with GPO disabled!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__enforcing_allows_only_permitted_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO enforcing permits only listed trusted-domain users
    :setup:
        1. Join forest root and create 'user1', 'user2' and 'deny_user1' in the trusted domain
        2. Create group 'group' with 'user2' as member and link a site GPO
        3. Configure ad_gpo_access_control=enforcing and start SSSD
    :steps:
        1. Authenticate allowed user and group member via su
        2. Authenticate denied user via su
        3. Authenticate allowed user and group member via ssh
        4. Authenticate denied user via ssh
    :expectedresults:
        1. Allowed users succeed via su
        2. Denied user fails via su
        3. Allowed users succeed via ssh
        4. Denied user fails via ssh
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    user2 = trusted.user("user2").add()
    deny_user1 = trusted.user("deny_user1").add()
    group = trusted.group("group").add().add_member(user2)
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, group, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Allowed group member failed login!"
        assert not client.auth.su.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.ssh.password(trusted.fqn(user2.name), "Secret123"), "Allowed group member failed login!"
        assert not client.auth.ssh.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__enforcing_with_no_policy_allows_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO enforcing with no linked policy allows trusted-domain users
    :setup:
        1. Join forest root and create 'user' in the trusted domain
        2. Configure ad_gpo_access_control=enforcing with no GPO linked and start SSSD
    :steps:
        1. Authenticate the trusted-domain user via su
        2. Authenticate the trusted-domain user via ssh
    :expectedresults:
        1. Authentication succeeds via su
        2. Authentication succeeds via ssh
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user = trusted.user("user").add()

    _configure_gpo(client, join_ad_root, "enforcing")
    client.sssd.start()

    assert client.auth.su.password(trusted.fqn(user.name), "Secret123"), "User failed login!"
    assert client.auth.ssh.password(trusted.fqn(user.name), "Secret123"), "User failed login!"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__permissive_allows_all_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO permissive allows all trusted users while policy is linked
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a restrictive site GPO
        3. Configure ad_gpo_access_control=permissive and start SSSD
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Both users can log in via su
        2. Both users can log in via ssh
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "permissive")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.su.password(
            trusted.fqn(deny_user1.name), "Secret123"
        ), "Denied user failed login with GPO permissive!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.ssh.password(
            trusted.fqn(deny_user1.name), "Secret123"
        ), "Denied user failed login with GPO permissive!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__site_domain_and_ou_inheritance(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: Site, domain and OU GPO inheritance for trusted-domain users
    :setup:
        1. Join forest root and create 'user1', 'user2' and 'user3' in the trusted domain
        2. Link site, then domain, then OU policies
        3. Move the client computer into the OU for the OU policy case
    :steps:
        1. Authenticate with only the site policy via su
        2. Authenticate with only the site policy via ssh
        3. Link the domain policy and authenticate via su
        4. Link the domain policy and authenticate via ssh
        5. Move the computer to the OU, link the OU policy and authenticate via su
        6. Move the computer to the OU, link the OU policy and authenticate via ssh
    :expectedresults:
        1. Only the site user succeeds via su
        2. Only the site user succeeds via ssh
        3. Only the domain user succeeds via su
        4. Only the domain user succeeds via ssh
        5. Only the OU user succeeds via su
        6. Only the OU user succeeds via ssh
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    user2 = trusted.user("user2").add()
    user3 = trusted.user("user3").add()
    ou = ad.ou(f"gpo-forest-{trusted_name}").add()
    computer = client.host.hostname.split(".")[0]

    site_gpo: GPO | None = None
    domain_gpo: GPO | None = None
    ou_gpo: GPO | None = None
    try:
        site_gpo = (
            ad.gpo(f"forest inherit site {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user2],
                }
            )
            .link()
        )
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()
        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Site user failed login!"
        assert not client.auth.su.password(
            trusted.fqn(user2.name), "Secret123"
        ), "Domain user logged in under site GPO!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Site user failed login!"
        assert not client.auth.ssh.password(
            trusted.fqn(user2.name), "Secret123"
        ), "Domain user logged in under site GPO!"

        domain_gpo = (
            ad.gpo(f"forest inherit domain {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user1],
                }
            )
            .link(target=ad.naming_context)
        )
        client.sssd.restart(clean=True)
        assert client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Domain user failed login!"
        assert not client.auth.su.password(
            trusted.fqn(user1.name), "Secret123"
        ), "Site user logged in under domain GPO!"
        assert client.auth.ssh.password(trusted.fqn(user2.name), "Secret123"), "Domain user failed login!"
        assert not client.auth.ssh.password(
            trusted.fqn(user1.name), "Secret123"
        ), "Site user logged in under domain GPO!"

        ad.computer(computer).move(ou.dn)
        ou_gpo = (
            ad.gpo(f"forest inherit ou {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user3, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user2],
                }
            )
            .link(target=ou.dn)
        )
        client.sssd.restart(clean=True)
        assert client.auth.su.password(trusted.fqn(user3.name), "Secret123"), "OU user failed login!"
        assert not client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Domain user logged in under OU GPO!"
        assert client.auth.ssh.password(trusted.fqn(user3.name), "Secret123"), "OU user failed login!"
        assert not client.auth.ssh.password(
            trusted.fqn(user2.name), "Secret123"
        ), "Domain user logged in under OU GPO!"
    finally:
        try:
            ad.computer(computer).move(f"CN=Computers,{ad.naming_context}")
        except ProcessError:
            pass
        GPO.cleanup(site_gpo, domain_gpo, ou_gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
def test_adforest_gpo__map_interactive_and_remote_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO map options control su versus ssh for trusted-domain users
    :setup:
        1. Join forest root, create 'user1' in the trusted domain and link a site GPO
        2. Disable su then ssh GPO evaluation with map options
    :steps:
        1. With ad_gpo_map_interactive disabling su, try su and ssh
        2. With ad_gpo_map_remote_interactive disabling ssh, try ssh
    :expectedresults:
        1. su fails; ssh succeeds for the allowed user
        2. ssh fails for the allowed user
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_gpo_map_interactive="+my_pam_service, -su, -su-l")
        client.sssd.start()
        assert not client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "su should not be GPO-evaluated!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "ssh login failed!"

        client.sssd.config.remove_option(f"domain/{join_ad_root.domain}", "ad_gpo_map_interactive")
        client.sssd.dom(join_ad_root.domain)["ad_gpo_map_remote_interactive"] = "+my_pam_service, -sshd"
        client.sssd.config_apply()
        client.sssd.restart(clean=True)
        assert not client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "ssh should not be GPO-evaluated!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1177140)
def test_adforest_gpo__works_when_samba_client_log_level_is_high(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: Trusted-domain GPO works when Samba client log level is high
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a site GPO
        3. Write ``/etc/samba/smb.conf`` with ``log level = 10`` and start smb
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Allowed user succeeds and denied user fails via su
        2. Allowed user succeeds and denied user fails via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    workgroup = join_ad_root.domain.split(".")[0].upper()
    smb_conf = "\n".join(
        [
            "[global]",
            f"workgroup = {workgroup}",
            f"realm = {join_ad_root.realm}",
            "security = user",
            "kerberos method = system keytab",
            "log level = 10",
            "",
        ]
    )

    client.fs.backup("/etc/samba/smb.conf")
    try:
        client.fs.write("/etc/samba/smb.conf", smb_conf)
        client.svc.start("smb")

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.su.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
    finally:
        client.svc.stop("smb", raise_on_error=False)
        client.fs.restore("/etc/samba/smb.conf")
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1547234)
def test_adforest_gpo__honors_ad_site_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: ad_site still applies GPO evaluation for trusted-domain users
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a site GPO and set ad_site=Default-First-Site-Name
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Allowed user succeeds and denied user fails via su
        2. Allowed user succeeds and denied user fails via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_site="Default-First-Site-Name")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.su.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1695576)
def test_adforest_gpo__implicit_deny_without_applicable_policy(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: ad_gpo_implicit_deny denies trusted users when no GPO applies
    :setup:
        1. Join forest root, create 'user' in the trusted domain and link a site GPO
        2. Enable enforcing and ad_gpo_implicit_deny
    :steps:
        1. Authenticate with the site GPO linked via su
        2. Authenticate with the site GPO linked via ssh
        3. Unlink the GPO, restart SSSD and authenticate via su
        4. Unlink the GPO, restart SSSD and authenticate via ssh
    :expectedresults:
        1. Allowed user succeeds via su
        2. Allowed user succeeds via ssh
        3. User is denied once no GPO applies via su
        4. User is denied once no GPO applies via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user = trusted.user("user").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [],
            }
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_gpo_implicit_deny="True")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user.name), "Secret123"), "Allowed user failed login!"
        assert client.auth.ssh.password(trusted.fqn(user.name), "Secret123"), "Allowed user failed login!"

        gpo.unlink()
        client.sssd.restart(clean=True)
        assert not client.auth.su.password(trusted.fqn(user.name), "Secret123"), "User logged in with implicit deny!"
        assert not client.auth.ssh.password(trusted.fqn(user.name), "Secret123"), "User logged in with implicit deny!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1804005)
def test_adforest_gpo__link_order_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO link order selects which trusted-domain user is allowed
    :setup:
        1. Join forest root and create 'user1' and 'user2' in the trusted domain
        2. Link two domain GPOs with opposite allow/deny sets
    :steps:
        1. Authenticate with policy B at higher priority via su
        2. Authenticate with policy B at higher priority via ssh
        3. Reverse link order and authenticate via su
        4. Reverse link order and authenticate via ssh
    :expectedresults:
        1. Only user2 succeeds via su
        2. Only user2 succeeds via ssh
        3. Only user1 succeeds via su
        4. Only user1 succeeds via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    user2 = trusted.user("user2").add()
    target = ad.naming_context

    gpo_a: GPO | None = None
    gpo_b: GPO | None = None
    try:
        gpo_a = (
            ad.gpo(f"forest order a {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user2],
                }
            )
            .link(target=target)
        )
        gpo_b = (
            ad.gpo(f"forest order b {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user1],
                }
            )
            .link(target=target, order=1)
        )

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()
        assert client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Higher-priority user failed login!"
        assert not client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Lower-priority user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user2.name), "Secret123"), "Higher-priority user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Lower-priority user logged in!"

        gpo_a.unlink()
        gpo_b.unlink()
        gpo_a.link(target=target, order=1)
        gpo_b.link(target=target)
        client.sssd.restart(clean=True)
        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Higher-priority user failed login!"
        assert not client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Lower-priority user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Higher-priority user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(user2.name), "Secret123"), "Lower-priority user logged in!"
    finally:
        GPO.cleanup(gpo_a, gpo_b)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1855281)
def test_adforest_gpo__ignore_unreadable_policy_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: ad_gpo_ignore_unreadable skips unreadable GPOs for trusted users
    :setup:
        1. Join forest root and create 'user1' and 'user2' in the trusted domain
        2. Link a readable site GPO and an unreadable site GPO
        3. Configure ad_gpo_ignore_unreadable=True
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Allowed user succeeds and denied user fails via su
        2. Allowed user succeeds and denied user fails via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    user2 = trusted.user("user2").add()

    readable: GPO | None = None
    unreadable: GPO | None = None
    try:
        readable = (
            ad.gpo(f"forest readable {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user2],
                }
            )
            .link()
        )
        unreadable = (
            ad.gpo(f"forest unreadable {trusted_name}")
            .add()
            .link(order=1)
            .permissions("Authenticated Users", "None", "Group")
        )

        _configure_gpo(client, join_ad_root, "enforcing", ad_gpo_ignore_unreadable="True")
        client.sssd.start()
        assert client.auth.su.password(
            trusted.fqn(user1.name), "Secret123"
        ), "Allowed user failed after ignore_unreadable!"
        assert not client.auth.su.password(trusted.fqn(user2.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(
            trusted.fqn(user1.name), "Secret123"
        ), "Allowed user failed after ignore_unreadable!"
        assert not client.auth.ssh.password(trusted.fqn(user2.name), "Secret123"), "Denied user logged in!"
    finally:
        GPO.cleanup(readable, unreadable)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1316164)
def test_adforest_gpo__ignores_invalid_gpttmpl_keys_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: Invalid GptTmpl.inf keys are ignored for trusted-domain GPO evaluation
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a site GPO that also contains bogus Service General Setting keys
    :steps:
        1. Authenticate the allowed and denied trusted users via su
        2. Authenticate the allowed and denied trusted users via ssh
    :expectedresults:
        1. Allowed user succeeds and denied user fails via su
        2. Allowed user succeeds and denied user fails via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()

    gpo = (
        ad.gpo("policy invalid keys and values")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            },
            cfg={"Service General Setting": {"BITS": "2", "wuaserv": "2", "MpsSvc": "2"}},
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.su.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
    finally:
        GPO.cleanup(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=[1206092, 1204203])
def test_adforest_gpo__local_group_overlap_does_not_break_evaluation(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: Local /etc/group overlap does not crash GPO evaluation for trusted users
    :setup:
        1. Join forest root and create 'user1' and 'deny_user1' in the trusted domain
        2. Link a site GPO and add overlapping local group entries
    :steps:
        1. Authenticate allowed and denied trusted users via su
        2. Authenticate allowed and denied trusted users via ssh
    :expectedresults:
        1. Allowed user succeeds and denied user fails via su
        2. Allowed user succeeds and denied user fails via ssh
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user1 = trusted.user("user1").add()
    deny_user1 = trusted.user("deny_user1").add()
    gpo = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    client.fs.backup("/etc/group")
    try:
        client.fs.append("/etc/group", f"\ngpo_overlap:x:5100:{user1.name},{deny_user1.name}\n")

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        assert client.auth.su.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.su.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
        assert client.auth.ssh.password(trusted.fqn(user1.name), "Secret123"), "Allowed user failed login!"
        assert not client.auth.ssh.password(trusted.fqn(deny_user1.name), "Secret123"), "Denied user logged in!"
    finally:
        client.fs.restore("/etc/group")
        GPO.cleanup(gpo)

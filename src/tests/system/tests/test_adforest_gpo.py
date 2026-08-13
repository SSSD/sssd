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
from sssd_test_framework.roles.ad import AD, GPO, ADUser
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


def _fqn(user: ADUser, domain: AD) -> str:
    return f"{user.name}@{domain.domain}"


def _trusted(ad_child: AD, ad_tree: AD, trusted_name: str) -> AD:
    return ad_child if trusted_name == "child" else ad_tree


def _configure_gpo(client: Client, joined: AD, mode: str, **opts: str) -> None:
    client.sssd.import_domain(joined.domain, joined)
    dom = client.sssd.dom(joined.domain)
    dom["use_fully_qualified_names"] = "True"
    dom["fallback_homedir"] = "/home/%d/%u"
    dom["cache_credentials"] = "True"
    dom["access_provider"] = "ad"
    dom["ad_gpo_access_control"] = mode
    for key, value in opts.items():
        dom[key] = value


def _link_site_gpo(ad: AD, name: str, allow: list, deny: list) -> GPO:
    return (
        ad.gpo(name)
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [*allow, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": deny,
            }
        )
        .link()
    )


def _cleanup_gpos(*gpos: GPO | None) -> None:
    """Unlink and delete GPOs; ignore remote command failures if already removed."""
    for gpo in gpos:
        if gpo is None:
            continue
        try:
            gpo.unlink()
        except ProcessError:
            pass
        try:
            gpo.delete()
        except ProcessError:
            pass


def _restore_computer(ad: AD, computer: str) -> None:
    """Move the computer object back under CN=Computers if needed."""
    try:
        ad.computer(computer).move(f"CN=Computers,{ad.naming_context}")
    except ProcessError:
        pass


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__disabled_allows_all_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: GPO disabled allows all trusted-domain users while joined to root
    :setup:
        1. Join forest root and create allow/deny users in the trusted domain
        2. Link a restrictive site GPO
        3. Configure ad_gpo_access_control=disabled and start SSSD
    :steps:
        1. Authenticate allowed and denied trusted users
    :expectedresults:
        1. Both users can log in
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()
    gpo = _link_site_gpo(ad, f"forest disabled {trusted_name}", [allowed], [denied])

    try:
        _configure_gpo(client, join_ad_root, "disabled")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert auth.password(_fqn(denied, trusted), "Secret123"), "Denied user failed login with GPO disabled!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__enforcing_allows_only_permitted_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: GPO enforcing permits only listed trusted-domain users
    :setup:
        1. Join forest root and create allow/deny users and an allow group in the trusted domain
        2. Link a site GPO with allow and deny rights
        3. Configure ad_gpo_access_control=enforcing and start SSSD
    :steps:
        1. Authenticate allowed user and group member
        2. Authenticate denied user
    :expectedresults:
        1. Allowed users succeed
        2. Denied user fails
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    member = trusted.user("gpo-ok-g").add()
    denied = trusted.user("gpo-deny").add()
    group = trusted.group("gpo-ok-group").add().add_member(member)
    gpo = _link_site_gpo(ad, f"forest enforce {trusted_name}", [allowed, group], [denied])

    try:
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert auth.password(_fqn(member, trusted), "Secret123"), "Allowed group member failed login!"
        assert not auth.password(_fqn(denied, trusted), "Secret123"), "Denied user logged in!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__enforcing_with_no_policy_allows_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: GPO enforcing with no linked policy allows trusted-domain users
    :setup:
        1. Join forest root and create a trusted-domain user
        2. Configure ad_gpo_access_control=enforcing with no GPO linked and start SSSD
    :steps:
        1. Authenticate the trusted-domain user
    :expectedresults:
        1. Authentication succeeds
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user = trusted.user("gpo-nop").add()

    _configure_gpo(client, join_ad_root, "enforcing")
    client.sssd.start()

    assert client.auth.parametrize(method).password(_fqn(user, trusted), "Secret123"), "User failed login!"


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__permissive_allows_all_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: GPO permissive allows all trusted users while policy is linked
    :setup:
        1. Join forest root and create allow/deny users in the trusted domain
        2. Link a restrictive site GPO
        3. Configure ad_gpo_access_control=permissive and start SSSD
    :steps:
        1. Authenticate allowed and denied trusted users
    :expectedresults:
        1. Both users can log in
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()
    gpo = _link_site_gpo(ad, f"forest permissive {trusted_name}", [allowed], [denied])

    try:
        _configure_gpo(client, join_ad_root, "permissive")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert auth.password(_fqn(denied, trusted), "Secret123"), "Denied user failed login with GPO permissive!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("high")
def test_adforest_gpo__site_domain_and_ou_inheritance(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: Site, domain and OU GPO inheritance for trusted-domain users
    :setup:
        1. Join forest root and create site/domain/OU users in the trusted domain
        2. Link site, then domain, then OU policies
        3. Move the client computer into the OU for the OU policy case
    :steps:
        1. Authenticate with only the site policy
        2. Link the domain policy and authenticate again
        3. Move the computer to the OU, link the OU policy and authenticate again
    :expectedresults:
        1. Only the site user succeeds
        2. Only the domain user succeeds
        3. Only the OU user succeeds
    :customerscenario: False
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    site_user = trusted.user("gpo-site").add()
    domain_user = trusted.user("gpo-domain").add()
    ou_user = trusted.user("gpo-ou").add()
    ou = ad.ou(f"gpo-forest-{trusted_name}").add()
    computer = client.host.hostname.split(".")[0]
    auth = client.auth.parametrize(method)

    site_gpo: GPO | None = None
    domain_gpo: GPO | None = None
    ou_gpo: GPO | None = None
    try:
        site_gpo = _link_site_gpo(ad, f"forest inherit site {trusted_name}", [site_user], [domain_user])
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()
        assert auth.password(_fqn(site_user, trusted), "Secret123"), "Site user failed login!"
        assert not auth.password(_fqn(domain_user, trusted), "Secret123"), "Domain user logged in under site GPO!"

        domain_gpo = (
            ad.gpo(f"forest inherit domain {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [domain_user, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [site_user],
                }
            )
            .link(target=ad.naming_context)
        )
        client.sssd.restart(clean=True)
        assert auth.password(_fqn(domain_user, trusted), "Secret123"), "Domain user failed login!"
        assert not auth.password(_fqn(site_user, trusted), "Secret123"), "Site user logged in under domain GPO!"

        ad.computer(computer).move(ou.dn)
        ou_gpo = (
            ad.gpo(f"forest inherit ou {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [ou_user, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [domain_user],
                }
            )
            .link(target=ou.dn)
        )
        client.sssd.restart(clean=True)
        assert auth.password(_fqn(ou_user, trusted), "Secret123"), "OU user failed login!"
        assert not auth.password(_fqn(domain_user, trusted), "Secret123"), "Domain user logged in under OU GPO!"
    finally:
        _restore_computer(ad, computer)
        _cleanup_gpos(site_gpo, domain_gpo, ou_gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
def test_adforest_gpo__map_interactive_and_remote_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str
):
    """
    :title: GPO map options control su versus ssh for trusted-domain users
    :setup:
        1. Join forest root, create an allowed trusted user and link a site GPO
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
    allowed = trusted.user("gpo-ok").add()
    gpo = _link_site_gpo(ad, f"forest map {trusted_name}", [allowed], [])

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_gpo_map_interactive="+my_pam_service, -su")
        client.sssd.start()
        assert not client.auth.su.password(_fqn(allowed, trusted), "Secret123"), "su should not be GPO-evaluated!"
        assert client.auth.ssh.password(_fqn(allowed, trusted), "Secret123"), "ssh login failed!"

        client.sssd.config.remove_option(f"domain/{join_ad_root.domain}", "ad_gpo_map_interactive")
        client.sssd.dom(join_ad_root.domain)["ad_gpo_map_remote_interactive"] = "+my_pam_service, -sshd"
        client.sssd.config_apply()
        client.sssd.restart(clean=True)
        assert not client.auth.ssh.password(_fqn(allowed, trusted), "Secret123"), "ssh should not be GPO-evaluated!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1177140)
def test_adforest_gpo__works_when_samba_client_log_level_is_high(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: Trusted-domain GPO works when Samba client log level is high
    :setup:
        1. Join forest root and create allow/deny trusted users
        2. Link a site GPO
        3. Write ``/etc/samba/smb.conf`` with ``log level = 10`` and start smb
    :steps:
        1. Authenticate allowed and denied trusted users
    :expectedresults:
        1. Allowed user succeeds and denied user fails
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()
    gpo = _link_site_gpo(ad, f"forest smb-log {trusted_name}", [allowed], [denied])

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

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert not auth.password(_fqn(denied, trusted), "Secret123"), "Denied user logged in!"
    finally:
        client.svc.stop("smb", raise_on_error=False)
        client.fs.restore("/etc/samba/smb.conf")
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1547234)
def test_adforest_gpo__honors_ad_site_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: ad_site still applies GPO evaluation for trusted-domain users
    :setup:
        1. Join forest root and create allow/deny trusted users
        2. Link a site GPO and set ad_site=Default-First-Site-Name
    :steps:
        1. Authenticate allowed and denied trusted users
    :expectedresults:
        1. Allowed user succeeds and denied user fails
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()
    gpo = _link_site_gpo(ad, f"forest ad_site {trusted_name}", [allowed], [denied])

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_site="Default-First-Site-Name")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert not auth.password(_fqn(denied, trusted), "Secret123"), "Denied user logged in!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1695576)
def test_adforest_gpo__implicit_deny_without_applicable_policy(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: ad_gpo_implicit_deny denies trusted users when no GPO applies
    :setup:
        1. Join forest root, create a trusted user and link a site GPO
        2. Enable enforcing and ad_gpo_implicit_deny
    :steps:
        1. Authenticate with the site GPO linked
        2. Unlink the GPO, restart SSSD and authenticate again
    :expectedresults:
        1. Allowed user succeeds
        2. User is denied once no GPO applies
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    gpo = _link_site_gpo(ad, f"forest implicit {trusted_name}", [allowed], [])

    try:
        _configure_gpo(client, join_ad_root, "enforcing", ad_gpo_implicit_deny="True")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"

        gpo.unlink()
        client.sssd.restart(clean=True)
        assert not auth.password(_fqn(allowed, trusted), "Secret123"), "User logged in with implicit deny!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1804005)
def test_adforest_gpo__link_order_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: GPO link order selects which trusted-domain user is allowed
    :setup:
        1. Join forest root and create two trusted users
        2. Link two domain GPOs with opposite allow/deny sets
    :steps:
        1. Authenticate with policy B at higher priority
        2. Reverse link order and authenticate again
    :expectedresults:
        1. Only user B succeeds
        2. Only user A succeeds
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user_a = trusted.user("gpo-order-a").add()
    user_b = trusted.user("gpo-order-b").add()
    target = ad.naming_context
    auth = client.auth.parametrize(method)

    gpo_a: GPO | None = None
    gpo_b: GPO | None = None
    try:
        gpo_a = (
            ad.gpo(f"forest order a {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user_a, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user_b],
                }
            )
            .link(target=target)
        )
        gpo_b = (
            ad.gpo(f"forest order b {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user_b, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user_a],
                }
            )
            .link(target=target, order=1)
        )

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()
        assert auth.password(_fqn(user_b, trusted), "Secret123"), "Higher-priority user failed login!"
        assert not auth.password(_fqn(user_a, trusted), "Secret123"), "Lower-priority user logged in!"

        gpo_a.unlink()
        gpo_b.unlink()
        gpo_a.link(target=target, order=1)
        gpo_b.link(target=target)
        client.sssd.restart(clean=True)
        assert auth.password(_fqn(user_a, trusted), "Secret123"), "Higher-priority user failed login!"
        assert not auth.password(_fqn(user_b, trusted), "Secret123"), "Lower-priority user logged in!"
    finally:
        _cleanup_gpos(gpo_a, gpo_b)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1855281)
def test_adforest_gpo__ignore_unreadable_policy_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: ad_gpo_ignore_unreadable skips unreadable GPOs for trusted users
    :setup:
        1. Join forest root and create two trusted users
        2. Link a readable and an unreadable domain GPO
    :steps:
        1. Authenticate without ad_gpo_ignore_unreadable
        2. Enable ad_gpo_ignore_unreadable and authenticate again
    :expectedresults:
        1. Login fails while an unreadable GPO is present
        2. The readable GPO applies and the allowed user succeeds
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    user_a = trusted.user("gpo-unreadable-a").add()
    user_b = trusted.user("gpo-unreadable-b").add()
    target = ad.naming_context
    auth = client.auth.parametrize(method)

    readable: GPO | None = None
    unreadable: GPO | None = None
    try:
        readable = (
            ad.gpo(f"forest readable {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user_a, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user_b],
                }
            )
            .link(target=target)
        )
        unreadable = (
            ad.gpo(f"forest unreadable {trusted_name}")
            .add()
            .policy(
                {
                    "SeInteractiveLogonRight": [user_b, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [user_a],
                }
            )
            .link(target=target, order=1)
            .permissions("Authenticated Users", "None", "Group")
        )

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()
        assert not auth.password(_fqn(user_a, trusted), "Secret123"), "User logged in with unreadable GPO!"

        client.sssd.dom(join_ad_root.domain)["ad_gpo_ignore_unreadable"] = "True"
        client.sssd.config_apply()
        client.sssd.restart(clean=True)
        assert auth.password(_fqn(user_a, trusted), "Secret123"), "Allowed user failed after ignore_unreadable!"
        assert not auth.password(_fqn(user_b, trusted), "Secret123"), "Denied user logged in!"
    finally:
        _cleanup_gpos(readable, unreadable)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1316164)
def test_adforest_gpo__ignores_invalid_gpttmpl_keys_for_trusted_users(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: Invalid GptTmpl.inf keys are ignored for trusted-domain GPO evaluation
    :setup:
        1. Join forest root and create allow/deny trusted users
        2. Link a site GPO that also contains bogus Service General Setting keys
    :steps:
        1. Authenticate the allowed and denied trusted users
    :expectedresults:
        1. Allowed user succeeds and denied user fails
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()

    gpo = (
        ad.gpo(f"forest invalid keys {trusted_name}")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [allowed, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [denied],
            },
            cfg={"Service General Setting": {"BITS": "2", "wuaserv": "2", "MpsSvc": "2"}},
        )
        .link()
    )

    try:
        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert not auth.password(_fqn(denied, trusted), "Secret123"), "Denied user logged in!"
    finally:
        _cleanup_gpos(gpo)


@pytest.mark.topology(KnownTopology.ADForest)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("trusted_name", ["child", "tree"])
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=[1206092, 1204203])
def test_adforest_gpo__local_group_overlap_does_not_break_evaluation(
    client: Client, join_ad_root: AD, ad: AD, ad_child: AD, ad_tree: AD, trusted_name: str, method: str
):
    """
    :title: Local /etc/group overlap does not crash GPO evaluation for trusted users
    :setup:
        1. Join forest root and create allow/deny trusted users
        2. Link a site GPO and add overlapping local group entries
    :steps:
        1. Authenticate allowed and denied trusted users
    :expectedresults:
        1. Allowed user succeeds and denied user fails
    :customerscenario: True
    """
    trusted = _trusted(ad_child, ad_tree, trusted_name)
    allowed = trusted.user("gpo-ok").add()
    denied = trusted.user("gpo-deny").add()
    gpo = _link_site_gpo(ad, f"forest localgroup {trusted_name}", [allowed], [denied])

    client.fs.backup("/etc/group")
    try:
        client.fs.append("/etc/group", f"\ngpo_overlap:x:5100:{allowed.name},{denied.name}\n")

        _configure_gpo(client, join_ad_root, "enforcing")
        client.sssd.start()

        auth = client.auth.parametrize(method)
        assert auth.password(_fqn(allowed, trusted), "Secret123"), "Allowed user failed login!"
        assert not auth.password(_fqn(denied, trusted), "Secret123"), "Denied user logged in!"
    finally:
        client.fs.restore("/etc/group")
        _cleanup_gpos(gpo)

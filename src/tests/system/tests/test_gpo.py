"""
SSSD GPO tests

:requirement: IDM-SSSD-REQ: Group policy host based access control

The following features and parameters are not covered:
- ad_gpo_cache_timeout
- ad_gpo_map_remote_interactive
- ad_gpo_map_network
- ad_gpo_map_batch
- ad_gpo_map_service
- ad_gpo_map_permit
- ad_gpo_map_deny
"""

from __future__ import annotations

import pytest

from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__is_set_to_enforcing(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to enforcing
    :description:
        When ad_gpo_access_control is set to enforcing, user access is managed and enforced by the policy.
        Unlisted users are denied access.
    :setup:
        1. Create the following users; 'user', 'user1', 'user2', 'deny_user1', 'deny_user2'
        2. Create the following groups; 'group' with member 'user2' and 'deny_group' with member 'deny_user2'
        3. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' and 'deny_group' to SeDenyInteractiveLogonRight key
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Start SSSD
    :steps:
        1. Authenticate 'user1' and 'user2' with both su and ssh
        2. Authenticate 'user', 'deny_user' and 'deny_user1' with both su and ssh
    :expectedresults:
        1. User authentication is successful
        2. User authentication is unsuccessful
    :customerscenario: True
    """
    ad.user("user").add()
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()
    deny_user1 = ad.user("deny_user1").add()
    deny_user2 = ad.user("deny_user2").add()
    group = ad.group("group").add().add_members([user2])
    deny_group = ad.group("deny_group").add().add_members([deny_user2])

    ad.gpo("test policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1, deny_group],
        }
    ).link()

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.ssh.password(username="user1", password="Secret123")
    assert client.auth.su.password(username="user1", password="Secret123")
    assert client.auth.ssh.password(username="user2", password="Secret123")
    assert client.auth.su.password(username="user2", password="Secret123")
    assert not client.auth.ssh.password(username="user", password="Secret123")
    assert not client.auth.su.password(username="user", password="Secret123")
    assert not client.auth.ssh.password(username="deny_user1", password="Secret123")
    assert not client.auth.su.password(username="deny_user1", password="Secret123")
    assert not client.auth.ssh.password(username="deny_user2", password="Secret123")
    assert not client.auth.su.password(username="deny_user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__is_set_to_enforcing_with_no_policy(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to permissive
    :description:
        When ad_gpo_access_control is set to enforcing with no policy applied. It should
        permit all users to login.
    :setup:
        1. Create the following users; 'user', 'user1', 'deny_user1'
        2. Configure sssd.conf with 'ad_gpo_access_control' = 'permissive'
        3. Start SSSD
    :steps:
        1. Authenticate 'user', 'user1' and 'deny_user1' with both su and ssh
        2. Check logs to ensure that SSSD is in enforcing
    :expectedresults:
        1. All user authentication is successful
        2. SSSD is in enforcing
    :customerscenario: True
    """
    ad.user("user").add()
    ad.user("user1").add()
    ad.user("deny_user1").add()

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.ssh.password(username="user1", password="Secret123")
    assert client.auth.su.password(username="user1", password="Secret123")
    assert client.auth.ssh.password(username="user", password="Secret123")
    assert client.auth.su.password(username="user", password="Secret123")
    assert client.auth.ssh.password(username="deny_user1", password="Secret123")
    assert client.auth.su.password(username="deny_user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value enforcing" in log_str, f"Log file has wrong format: {log_str}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__is_set_to_permissive(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to permissive
    :description:
        When ad_gpo_access_control is set to permissive, all users are able to login despite what
        is configured in the policy. The rules are still processed and can be viewed in the logs.
    :setup:
        1. Create the following users; 'user', 'user1', 'deny_user1'
        2. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'permissive'
        5. Start SSSD
    :steps:
        1. Authenticate 'user', 'user1' and 'deny_user1' with both su and ssh
        2. Check logs to ensure that SSSD is in permissive
    :expectedresults:
        1. All user authentication is successful
        2. SSSD is in permissive
    :customerscenario: True
    """
    ad.user("user").add()
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("test policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "permissive"
    client.sssd.start()

    assert client.auth.ssh.password(username="user1", password="Secret123")
    assert client.auth.su.password(username="user1", password="Secret123")
    assert client.auth.ssh.password(username="user", password="Secret123")
    assert client.auth.su.password(username="user", password="Secret123")
    assert client.auth.ssh.password(username="deny_user1", password="Secret123")
    assert client.auth.su.password(username="deny_user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value permissive" in log_str, f"Log file has wrong format: {log_str}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__is_set_to_disabled(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to disabled
    :description:
        When ad_gpo_access_control is set to disabled, no policy processing should occur and be
        turned off entirely.
    :setup:
        1. Create the following users; 'user', 'user1', 'deny_user1'
        2. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
          SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key.
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'disabled'
        5. Start SSSD
    :steps:
        1. Authenticate 'user', 'user1' and 'deny_user1' with both su and ssh
        2. Check logs to ensure that SSSD is in disabled
    :expectedresults:
        1. All user authentication is successful
        2. SSSD is in disabled
    :customerscenario: True
    """
    ad.user("user").add()
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("test policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "disabled"
    client.sssd.start()

    assert client.auth.ssh.password(username="user1", password="Secret123")
    assert client.auth.su.password(username="user1", password="Secret123")
    assert client.auth.ssh.password(username="user", password="Secret123")
    assert client.auth.su.password(username="user", password="Secret123")
    assert client.auth.ssh.password(username="deny_user1", password="Secret123")
    assert client.auth.su.password(username="deny_user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value disabled" in log_str, f"Log file has wrong format: {log_str}"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1695576)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__implicit_deny_is_set_to_true(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to disabled
    :description:
        When ad_gpo_implicit_deny is set to true, the new default behavior is to deny access.
        If the user is not explicitly in the policy, the user is not allowed to login, so also
        applies when there is no policy.
    :setup:
        1. Create the following users; 'user', 'deny_user1'
        2. Create and link the GPO 'test policy' and only set SeInteractiveLogonRight to be empty,
           add 'deny_user1' to SeDenyInteractiveLogonRight key
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Start SSSD
    :steps:
        1. Authenticate 'user', and 'deny_user1'
        2. Configure sssd.conf with 'ad_gpo_implicit_deny' = 'True' and restart SSSD
        3. Authenticate 'user', and 'deny_user1'
        4. Unlink 'test policy" and restart SSSD
        5. Authenticate 'user', and 'deny_user1'
    :expectedresults:
        1. 'user' authentication is successful and 'deny_user1' is not
        2. SSSD is restarted and 'ad_gpo_implicit_deny' = 'True'
        3. Both users authentication is unsuccessful
        4. 'test policy' is unlinked
        5. Both users authentication is unsuccessful
    :customerscenario: True
    """
    ad.user("user").add()
    deny_user1 = ad.user("deny_user1").add()

    policy = (
        ad.gpo("test policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.ssh.password(username="user", password="Secret123")
    assert not client.auth.ssh.password(username="deny_user1", password="Secret123")

    client.sssd.domain["ad_gpo_implicit_deny"] = "True"
    client.sssd.restart()

    assert not client.auth.ssh.password(username="user", password="Secret123")
    assert not client.auth.su.password(username="deny_user1", password="Secret123")

    policy.unlink()
    client.sssd.restart()

    assert not client.auth.ssh.password(username="user", password="Secret123")
    assert not client.auth.su.password(username="deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__ou_over_domain_over_sites_inheritance(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control checking inheritance.
    :description:
        Policies can be applied to three locations, sites, domains and OUs. The order of which
        these are processed are, OUs, domains and lastly sites. Policies can be set to be enforced,
        which puts the policy at the top. The keys are not constructed and is replaced with the value of
        the policy with the highest priority.
    :setup:
        1. Create the following users; user, user1, user2
        2. Create test OU
        3. Create and link the 'site policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight and add 'user2', 'user3' to SeDenyInteractiveLogonRight key
        3. Create and link the 'domain policy' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user1', 'user3' to SeDenyInteractiveLogonRight key
        4. Create and link the 'ou policy' and add 'user3' and 'Domain Admins' to
           SeInteractiveLogonRight key and add 'user1', 'user2' to SeDenyInteractiveLogonRight key
        5. Move computer object to test OU
        6. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        7. Start SSSD
    :steps:
        1. Set 'Site policy' to enforce and authenticate 'user1', 'user2' and 'user3'
        2. Undo 'Site policy' enforce, authenticate 'user1', 'user2' and 'user3'
        3. Enforce 'domain policy', authenticate 'user1', 'user2' and 'user3'
        4. Enforce 'site policy', authenticate 'user1', 'user2' and 'user3'
    :expectedresults:
        1. Only 'user1' authentication is successful
        2. Only 'user3' authentication is successful
        3. Only 'user2' authentication is successful
        4. Only 'user1' authentication is successful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()
    user3 = ad.user("user3").add()
    ou = ad.ou("test").add().dn

    site_policy = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [user2, user3],
            }
        )
        .link(args=["-Enforced Yes"])
    )

    domain_policy = (
        ad.gpo("domain policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [user1, user3],
            }
        )
        .link(target=f"{ad.host.naming_context}")
    )

    ad.gpo("ou policy").add().policy(
        {
            "SeInteractiveLogonRight": [user3, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1, user2],
        }
    ).link(target=ou)

    ad.computer(client.host.hostname.split(".")[0]).move(ou)

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.su.password(username="user1", password="Secret123")
    assert not client.auth.su.password(username="user2", password="Secret123")
    assert not client.auth.su.password(username="user3", password="Secret123")

    site_policy.link("Set", args=["-Enforced No"])
    assert not client.auth.su.password(username="user1", password="Secret123")
    assert not client.auth.su.password(username="user2", password="Secret123")
    assert client.auth.su.password(username="user3", password="Secret123")

    domain_policy.link("Set", args=["-Enforced Yes"])
    assert not client.auth.su.password(username="user1", password="Secret123")
    assert client.auth.su.password(username="user2", password="Secret123")
    assert not client.auth.su.password(username="user3", password="Secret123")

    site_policy.link("Set", args=["-Enforced Yes"])
    assert client.auth.su.password(username="user1", password="Secret123")
    assert not client.auth.su.password(username="user2", password="Secret123")
    assert not client.auth.su.password(username="user3", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1804005)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__site_over_domain_over_ou_inheritance_using_gpo_link_order(
    client: Client, ad: AD, sssd_service_user: str
):
    """
    :title: Group policy object host base access control checking inheritance using GPO link order.
    :description:
        When a policy is applied to the 'same target', there is an additional level of inheritance, the
        order. This is automatically created as policies are linked ot the target and can be changed.
    :setup:
        1. Create the following users; user, user1, user2
        2. Create and link the 'site policy 1' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight and add 'user2', 'user3' to SeDenyInteractiveLogonRight key
        3. Create and link the 'site policy 2' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user1', 'user3' to SeDenyInteractiveLogonRight key with link order 2
        4. Create and link the 'site policy 3' and add 'user3' and 'Domain Admins' to
           SeInteractiveLogonRight key and add 'user1', 'user2' to SeDenyInteractiveLogonRight key with link order 3
        5. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        6. Start SSSD
    :steps:
        1. Authenticate 'user1', 'user2' and 'user3'
    :expectedresults:
        1. Only 'user1' authentication is successful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()
    user3 = ad.user("user3").add()

    ad.gpo("site policy 1").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2, user3],
        }
    ).link()

    ad.gpo("site policy 2").add().policy(
        {
            "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1, user3],
        }
    ).link(args=["-Order 2"])

    ad.gpo("site policy 3").add().policy(
        {
            "SeInteractiveLogonRight": [user3, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1, user3],
        }
    ).link(args=["-Order 3"])

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.ssh.password(username="user1", password="Secret123")
    assert not client.auth.ssh.password(username="user2", password="Secret123")
    assert not client.auth.ssh.password(username="user3", password="Secret123")


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__map_interactive_is_set(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access checking mapping interactive key values
    :description:
        Setting ad_gpo_map_interactive, changes the PAM service that is associated with the keys. The
        PAM service is su. The policy is configured with out the SSH keys and is tested, so only su work.
        Then update the parameter and add the ssh service, enabling SSH access, by using one key.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' SeDenyInteractiveLogonRight key
           Set blank values for SeRemoteInteractiveLogonRight and SeDenyRemoteInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and  with 'ad_gpo_implicit_deny' = 'True'
        4. Start SSSD
    :steps:
        1. Authenticate 'user1' with su
        2. Authenticate 'user1' with ssh
        3. Authenticate 'deny_user1' with su
        4. Authenticate 'deny_user1' with ssh
        5. Configure sssd.conf and set 'ad_gpo_map_interactive' = '+ssh' and restart
        6. Authenticate 'user1' with su and ssh
        7. Authenticate 'deny_user1' with su and ssh
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'user1' authentication is unsuccessful
        3. 'deny_user1' authentication with su is unsuccessful
        4. 'deny_user1' authentication with su ssh unsuccessful
        5. SSSD is configured with 'ad_gpo_map_interactive' = '+ssh' and is restarted
        6. 'user1' authentication is successful for both su and ssh
        7. 'deny_user1' authentication is unsuccessful for both su and ssh
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__works_in_offline_mode(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based works in offline mode.
    :description: Tests that gpo processing works when SSSD is offline
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        4. Start SSSD
    :steps:
        1. Authenticate 'user1' with ssh
        2. Authenticate 'deny_user1' with ssh
        3. Use iptables and block traffic to the ad server
        4. Authenticate 'user1' with ssh
        5. Authenticate 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is successful
        2  'deny_user1' authentication is unsuccessful
        3. Traffic is blocked and SSSD goes into offline mode
        4. 'user1' authentication is successful
        5. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1547234)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__honors_the_ad_site_parameter(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access control honors the ad_site parameter in the configuration.
    :description:
        The ad_site parameter use to break processing the GPO feature entirely. This ensures that setting
        the parameter doesn't break the feature. Also the site is auto-discovered, and the default site is
        'Default-First-Site-Name', when specifying a site
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with
            'ad_gpo_access_control' = 'enforcing'
        4. Create a new site and link the policy to site
        5. Start SSSD
    :steps:
        1. Authenticate 'user1' and 'deny_user1' with ssh
        2. Configure sssd.conf and add 'ad_site' = 'New-Site' and restart SSSD
        3. Authenticate 'user1' and 'deny_user1' with ssh
        4. Move the computer object to the new site
        5. Authenticate as 'user1' with ssh
        6. Authenticate as 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' and 'deny_user1' authentication is successful
        2. SSSD is configure with 'ad_site' = 'New-Site' and is restarted
        3. 'user1' and 'deny_user1' authentication is successful
        4. Computer object is moved to the new site.
        5. 'user1' authentication is successful
        6. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=905)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__only_needs_host_security_filters_and_permissions(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access control only needs host security filters and permissions.
    :description:
        GPOs have additional security filters for what objects can read the policy. The default value is
        'Authenticated Users', when tightening security, the most limited access is when the computer
        object has read access to the policy.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        4. Change the GPO permissions so the computer object is the only object that can read the policy
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1' with ssh
        2. Authenticate as 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is successful
        1. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1316164)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__ignores_invalid_and_unnecessary_keys_and_values(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access control ignores invalid and unnecessary keys and values.
    :description:
        The GPO security database can contain additional keys and keys with empty values for other
        applications. SSSD should only process the relevant keys and ignore the rest. When creating
        the policy bogus keys are added.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key,
           additionally add some empty keys and invalid values to the policy
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1' with ssh
        2. Authenticate as 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is successful
        1. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1855281)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__skips_unreadable_gpo_policies(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access control skips unreadable GPO policies.
    :description:
        When a policy cannot be read, the default behavior is to stop processing all policies,
        to air on the side of caution. Enabling 'ad_gpo_ignore_unreadable' will skip the unreadable
        policies and process the policies that are readable.
    :setup:
        1. Create the following users; 'user1', 'user2'
        2. Create and link the GPO 'test policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user2 to SeDenyInteractiveLogonRight key.
        3. Create and link the GPO 'domain policy' and add user2' and group 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user1' to SeDenyInteractiveLogonRight key and
           set the policy to be enforcing.
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Modify the permissions to the GPO 'domain policy' and make it unreadable
        6. Start SSSD
    :steps:
        1. Authenticate as 'user1' and 'user2'
        2. Configure sssd.conf with 'ad_gpo_ignore_unreadable' = 'True' and restart SSSD
        3. Authenticate as 'user1'
        4. Authenticate as 'user2'
    :expectedresults:
        1. 'user1' and 'user2' authentication is unsuccessful
        2. Configuration is updated with 'ad_gpo_ignore_unreadable' = 'True'
        3. 'user1' authentication is successful
        4. 'user2' authentication is unsuccessful
    :customerscenario: True
    """


@pytest.mark.skip
@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=2151450)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_gpo__works_when_auto_private_groups_is_set_true(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host based access control works when auto_private_groups is set to true.
    :description:
    :setup:
    :steps:
    :expectedresults:
    :customerscenario: True
    """


"""
Can we drop this test case?

# ad_gpo_008: bz 1177140 gpo_child fails when log is enbled in samba
rlPhaseStartTest "parent domain gpo child fails when log is enabled in smb bz1177140"
gplink "$AD_SERVER1_IP" "$AD_SERVER1_USER" "$AD_SERVER1_BINDPASS" "site_policy"

sssd_base_conf
echo "ad_gpo_access_control = enforcing" >> /etc/sssd/sssd.conf
backup_push /etc/samba/smb.conf

unindent <<<"
[global]
workgroup = $AD_SERVER1_SHORT_REALM
realm = $AD_SERVER1_REALM
security = user
kerberos method = system keytab
log level = 10
" > /etc/samba/smb.conf

# SELinux is preventing /usr/bin/nsupdate from search access on the directory net.
#ausearch -c 'nsupdate' --raw | audit2allow -M my-nsupdate
#semodule -X 300 -i my-nsupdate.pp
"""

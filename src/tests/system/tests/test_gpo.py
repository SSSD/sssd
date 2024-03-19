"""
SSSD GPO Tests

Switch user (su), and Remote (ssh) access is parameterized fixture for the tests. When SeRemoteInteractiveLogonRight is
omitted from the policy, which are most tests cases, the value from SeInteractiveLogonRight is then copied to
SeRemoteInteractiveLogonRight.

The following code will modify both SeInteractiveActiveLogonRight and SeRemoteInteractiveLogonRight.

.. code-block::
    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }

An administrative user or group always needs to be specified, to prevent administrative lock outs, for the tests
"Domain Admins" group is used.

The following GPO related  parameters are not tested
- ad_gpo_cache_timeout
- ad_gpo_map_network
- ad_gpo_map_batch
- ad_gpo_map_service
- ad_gpo_map_permit
- ad_gpo_map_deny


:requirement: Access Control
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__is_set_to_enforcing(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to enforcing and users are allowed
    :description:
        When ad_gpo_access_control is set to enforcing, user access is managed and enforced by the policy.
        Unlisted users are denied access.
    :setup:
        1. Create the following users; 'user', 'user1', 'user2', 'deny_user1', 'deny_user2'
        2. Create the following groups; 'group' with member 'user2', 'deny_group' with member 'deny_user2'
        3. Create and link the GPO 'site policy' and add 'user1', 'group' and 'Domain Admins' to
           SeInteractiveLogonRight key and 'deny_user1' and 'deny_group' to SeDenyInteractiveLogonRight key
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Start SSSD
    :steps:
        1. Authenticate as 'user'
        2. Authenticate as 'user1' and 'user2'
        3. Authenticate as 'deny_user1' and 'deny_user2'
    :expectedresults:
        1. User authentication is unsuccessful
        2. Users authentication are successful
        3. Users authentication are unsuccessful
    :customerscenario: True
    """
    ad.user("user").add()
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()
    deny_user1 = ad.user("deny_user1").add()
    deny_user2 = ad.user("deny_user2").add()
    group = ad.group("group").add().add_members([user2])
    deny_group = ad.group("deny_group").add().add_members([deny_user2])

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1, deny_group],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(username="user", password="Secret123")
    assert client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert client.auth.parametrize(method).password(username="user2", password="Secret123")
    assert not client.auth.parametrize(method).password(username="deny_user1", password="Secret123")
    assert not client.auth.parametrize(method).password(username="deny_user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__is_set_to_enforcing_with_no_policy(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to enforcing with no policy
    :description:
        When ad_gpo_access_control is set to enforcing with no policy applied. It should
        permit all users to login.
    :setup:
        1. Create the following user, 'user'
        2. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        3. Start SSSD
    :steps:
        1. Authenticate 'user'
        2. Check logs for gpo_access_check result
    :expectedresults:
        1. User authentication is successful
        2. Access check result is granted
    :customerscenario: True
    """
    ad.user("user").add()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__is_set_to_permissive_and_users_are_allowed(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to permissive
    :description:
        When ad_gpo_access_control is set to permissive, all users are able to login despite what
        is configured in the policy. The rules are still processed and can be viewed in the logs.
    :setup:
        1. Create the following user, 'user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key.
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'permissive'
        4. Start SSSD
    :steps:
        1. Authenticate 'user1'
        2. Check logs for ad_gpo_access_control value
        3. Check logs for gpo_access_check result
    :expectedresults:
        1. User authentication is successful
        2. ad_gpo_access_control is permissive
        3. Access check result is granted
    :customerscenario: True
    """
    user1 = ad.user("user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "permissive"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value permissive" in log_str
    assert "access_granted = 1" in log_str


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__is_set_to_permissive_and_users_are_denied(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to permissive
    :description:
        When ad_gpo_access_control is set to permissive, all users are able to login despite what
        is configured in the policy. The rules are still processed and can be viewed in the logs.
    :setup:
        1. Create the following user, 'deny_user1'
        2. Create and link the GPO 'site policy' and add group 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'permissive'
        4. Start SSSD
    :steps:
        1. Authenticate 'deny_user1'
        2. Check logs for ad_gpo_access_control value
        3. Check logs for gpo_access_check result
    :expectedresults:
        1. User authentication is successful
        2. ad_gpo_access_control is permissive
        3. Access check result is denied
    :customerscenario: True
    """
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "permissive"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="deny_user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value permissive" in log_str
    assert "access_denied = 1" in log_str


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__is_set_to_disabled_and_all_users_are_allowed(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to disabled and all users are allowed
    :description:
        When ad_gpo_access_control is set to disabled, no policy processing should occur and be
        turned off entirely.
    :setup:
        1. Create the following users; 'user', 'user1' and 'deny_user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key, and add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'disabled'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user', 'user1' and 'deny_user1'
        2. Check logs for ad_gpo_access_control value
    :expectedresults:
        1. All users authentication are successful
        2. ad_gpo_access_control is disabled
    :customerscenario: True
    """
    ad.user("user").add()
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "disabled"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user", password="Secret123")
    assert client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert client.auth.parametrize(method).password(username="deny_user1", password="Secret123")

    log_str = client.fs.read(client.sssd.logs.domain())
    assert "Option ad_gpo_access_control has value disabled" in log_str


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1695576)
def test_gpo__implicit_deny_is_set_to_true(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control is set to enforcing and implicit deny is true
    :description:
        When ad_gpo_implicit_deny is set to true, the new default behavior is to deny access for
        when there is no policy applied.
    :setup:
        1. Create the following users; 'user'
        2. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and 'ad_gpo_implicit_deny' = True
        3. Start SSSD
    :steps:
        1. Authenticate as 'user'
    :expectedresults:
        1. 'user' authentication is unsuccessful
    :customerscenario: True
    """
    ad.user("user").add()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_implicit_deny"] = "True"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(username="user", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__domain_and_sites_inheritance_when_site_is_enforcing(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control checking inheritance for sites enforced and domains
    :description:
        Policies can be applied to three locations, sites, domains and OUs. The order of which
        these are processed are, OUs, domains and lastly sites. Policies can be set to be enforced,
        which puts the policy at the top. The keys are not constructed and is replaced with the value of
        the policy with the highest priority.
    :setup:
        1. Create the following users; user1, user2
        2. Create and link the 'site policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight and add 'user2' to SeDenyInteractiveLogonRight key
        3. Create and link the 'domain policy' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user1' to SeDenyInteractiveLogonRight key
        4. Set 'site policy' to be enforcing
        5. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        6. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'user2'
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'user2' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()

    site_policy = (
        ad.gpo("site policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [user2],
            }
        )
        .link()
    )

    ad.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=f"{ad.host.naming_context}")

    site_policy.link("Set", args=["-Enforced Yes"])

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert not client.auth.parametrize(method).password(username="user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__domain_and_sites_inheritance(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control checking inheritance for sites and domains.
    :description:
        Policies can be applied to three locations, sites, domains and OUs. The order of which
        these are processed are, OUs, domains and lastly sites. Policies can be set to be enforced,
        which puts the policy at the top. The keys are not constructed and is replaced with the value of
        the policy with the highest priority.
    :setup:
        1. Create the following users; user1, user2
        2. Create and link the 'site policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight and add 'user2' to SeDenyInteractiveLogonRight key
        3. Create and link the 'domain policy' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user3' to SeDenyInteractiveLogonRight key
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'user2'
    :expectedresults:
        1. 'user1' authentication is unsuccessful
        2. 'user2' authentication is successful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link()

    ad.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=f"{ad.host.naming_context}")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert client.auth.parametrize(method).password(username="user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__ou_and_domain_inheritance(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control checking inheritance between ous and domains.
    :description:
        Policies can be applied to three locations, sites, domains and OUs. The order of which
        these are processed are, OUs, domains and lastly sites. Policies can be set to be enforced,
        which puts the policy at the top. The keys are not constructed and is replaced with the value of
        the policy with the highest priority.
    :setup:
        1. Create the following users; user1, user2
        2. Create test OU
        3. Create and link the 'domain policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user2' to SeDenyInteractiveLogonRight key
        4. Create and link the 'ou policy' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key and add 'user2' to SeDenyInteractiveLogonRight key
        5. Move computer object to test OU
        6. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        7. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'user2'
    :expectedresults:
        1. 'user1' authentication is unsuccessful
        2. 'user2' authentication is successful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()
    ou = ad.ou("test").add().dn

    ad.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link(target=f"{ad.host.naming_context}")

    ad.gpo("ou policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=ou)

    ad.computer(client.host.hostname.split(".")[0]).move(ou)

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert client.auth.parametrize(method).password(username="user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1804005)
def test_gpo__sites_inheritance_using_gpo_link_order(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host base access control checking inheritance using GPO link order.
    :description:
        When a policy is applied to the 'same target', there is an additional level of inheritance, the
        order. This is automatically created as policies are linked ot the target and can be changed.
    :setup:
        1. Create the following users; user, user1, user2
        2. Create and link the 'site policy 1' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight and add 'user2' to SeDenyInteractiveLogonRight key
        3. Create and link the 'site policy 2' and add 'user2' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'user1' to SeDenyInteractiveLogonRight key with link order 1
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'user2'
    :expectedresults:
        1. 'user1' authentication is unsuccessful
        2. 'user2' authentication is successful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    user2 = ad.user("user2").add()

    ad.gpo("site policy 1").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link()

    ad.gpo("site policy 2").add().policy(
        {
            "SeInteractiveLogonRight": [user2, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(args=["-Order 1"])

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert client.auth.parametrize(method).password(username="user2", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__map_interactive_disabling_login_su_and_su_l(client: Client, ad: AD):
    """
    :title: Group policy object host based access disabling logon, su, su-l GPO evaluation.
    :description:
        Setting ad_gpo_map_interactive, changes the evaluation of the PAM services specified, by default,
        this setting changes evaluates the following PAM services, login, su, su-l, gdm-fingerprint,
        gdm-password, gdm-smartcard, kdm, lightdm, lxdm, sddm, unity and xdm
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and
           'ad_gpo_map_interactive' = "-logon -su -su-l"
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1' with su
        2. Authenticate as 'user1' with ssh
        3. Authenticate as 'deny_user1' with su
        4. Authenticate as 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is unsuccessful
        2. 'user1' authentication is successful
        3. 'deny_user1' authentication is unsuccessful for su
        4. 'deny_user1' authentication is unsuccessful for ssh
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_map_interactive"] = "-logon, -su, -su-l"
    client.sssd.start()

    assert not client.auth.su.password("user1", password="Secret123")
    assert client.auth.ssh.password("user1", password="Secret123")
    assert not client.auth.su.password("deny_user1", password="Secret123")
    assert not client.auth.ssh.password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__map_remote_interactive_disabling_sshd(client: Client, ad: AD):
    """
    :title: Group policy object host based access disabling ssh and cockpit GPO evaluation.
    :description:
        Setting ad_gpo_map_remote_interactive, changes the evaluation of the PAM services specified, by default,
        this setting changes evaluates the following PAM services, sshd, cockpit
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and
           'ad_gpo_map_remote_interactive' = '-sshd'
        4. Start SSSD
    :steps:
        1. Authenticate 'user1' with su
        2. Authenticate 'user1' with ssh
        3. Authenticate 'deny_user1' with su
        4. Authenticate 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'user1' authentication is unsuccessful
        3. 'deny_user1' authentication is unsuccessful for su
        4. 'deny_user1' authentication is unsuccessful for ssh
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_map_remote_interactive"] = "-sshd"
    client.sssd.start()

    assert client.auth.su.password("user1", password="Secret123")
    assert not client.auth.ssh.password("user1", password="Secret123")
    assert not client.auth.su.password("deny_user1", password="Secret123")
    assert not client.auth.ssh.password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
def test_gpo__works_when_the_server_is_unreachable(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based works when the server is unreachable.
    :description: Tests that gpo processing works from the cache when the server is unreachable
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing', 'cache_credentials' = 'True'
           'krb5_store_password_if_offline' = 'True' and 'offline_credentials_expiration' = '0'
        4. Start SSSD
    :steps:
        1. Authenticate 'user1'
        2. Authenticate 'deny_user1'
        3. Use iptables and block traffic to the ad server
        4. Authenticate 'user1'
        5. Authenticate 'deny_user1'
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'deny_user1' authentication is unsuccessful
        3. Traffic is blocked and SSSD goes into offline mode
        4. 'user1' authentication is successful
        5. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", password="Secret123")
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123")

    client.firewall.outbound.drop_host(ad)
    client.sssd.bring_offline()

    assert client.auth.parametrize(method).password("user1", password="Secret123")
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1547234)
def test_gpo__honors_the_ad_site_parameter(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based access control honors the ad_site parameter in the configuration.
    :description:
        The ad_site parameter use to break processing the GPO feature entirely. This ensures that setting
        the parameter doesn't break the feature. Also the site is auto-discovered, and the default site is
        'Default-First-Site-Name', when specifying a site

        Note: The site name cannot contain spaces
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create new site
        3. Create the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
           and link policy to the new site
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and
           'ad_site' = "New-Site"
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1' with ssh
        2. Authenticate as 'deny_user1' with ssh
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()
    ad.site("New-Site").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link(target=f"cn=New-Site,cn=sites,cn=configuration,{ad.host.naming_context}")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_site"] = "New-Site"
    client.sssd.start()

    assert client.auth.ssh.password("user1", password="Secret123")
    assert not client.auth.ssh.password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=905)
def test_gpo__only_needs_host_security_filters_and_permissions(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based access control only needs host security filters and permissions.
    :description:
        GPOs have additional security filters for which objects can apply the policy. The default value is
        'Authenticated Users' group, when tightening security this may be changed. Commonly the computer
        object can only apply the policy.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        4. Add the permissions so the client has 'gpoapply' permissions,
           and set 'authenticated users' to 'gporead'
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'deny_user1'
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()
    computer = client.host.hostname.split(".")[0].upper()

    computer_policy = (
        ad.gpo("computer policy")
        .add()
        .policy(
            {
                "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user1],
            }
        )
        .link()
    )

    computer_policy.permissions(f"{computer}$", "GpoApply", "Computer")
    computer_policy.permissions("Authenticated Users", "GpoRead", "Group")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", password="Secret123")
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1316164)
def test_gpo__ignores_invalid_and_unnecessary_keys_and_values(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based access control ignores invalid and unnecessary keys and values.
    :description:
        The GPO security database can contain additional keys and keys with empty values for other
        applications. SSSD should only process the relevant keys and ignore the rest. When creating
        the policy bogus keys are added.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1' to SeDenyInteractiveLogonRight key,
           additionally add some empty keys and invalid values to the policy
        3. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'deny_user1'
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("policy invalid keys and values").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        },
        cfg={"Service General Setting": {"BITS": "2", "wuaserv": "2", "MpsSvc": "2"}},
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user1", password="Secret123")
    assert not client.auth.parametrize(method).password(username="deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=1855281)
def test_gpo__skips_unreadable_gpo_policies(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based access control skips unreadable GPO policies.
    :description:
        When a policy cannot be read, the default behavior is to stop processing all policies,
        to air on the side of caution. Enabling 'ad_gpo_ignore_unreadable' will skip the unreadable
        policies and process the policies that are readable.
    :setup:
        1. Create the following users; 'user1', 'deny_user1'
        2. Create and link the GPO 'site policy' and add 'user1', group and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1 to SeDenyInteractiveLogonRight key
        3. Create and link the GPO 'unreadable policy', and set the permissions for
           'Authenticated Users' to 'None'
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and
           'ad_gpo_ignore_unreadable' = 'True
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'deny_user1'
    :expectedresults:
        1. 'user1' authentication is successful
        2. 'deny_user1' authentication is unsuccessful
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    deny_user1 = ad.user("deny_user1").add()

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    ad.gpo("unreadable policy").add().link().permissions("Authenticated Users", "None", "Group")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_ignore_unreadable"] = "True"
    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", password="Secret123")
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(bz=2151450)
def test_gpo__works_when_auto_private_groups_is_set_true(client: Client, ad: AD, method: str):
    """
    :title: Group policy object host based access control works when auto_private_groups is set to true.
    :description:
        This tests for a bug where the primary group is not returned when the user is looked up.
    :setup:
        1. Create the following user 'user1'
        2. Create the following group 'group' and add 'user1' to the group
        3. Create and link the GPO 'site policy' and add 'user1', groups, 'group' and 'Domain Admins' to
           SeInteractiveLogonRight key.
        4. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing' and 'ldap_use_tokengroup' = 'False'
        5. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Id as 'user1'
    :expectedresults:
        1. 'user1' authentication is successful
        2. Primary group 'Domain Users' is listed
    :customerscenario: True
    """
    user1 = ad.user("user1").add()
    group = ad.group("group").add().add_members([user1])

    ad.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["auto_private_groups"] = "true"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user1", password="Secret123")

    result = client.tools.id("user1")
    assert result is not None, "id command for user1 failed"
    assert result.memberof("domain users")

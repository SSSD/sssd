"""
Access Control - Group Policy Objects (GPO) Tests

Switch user (su), and Remote (ssh) access is parameterized fixture for the tests. When SeRemoteInteractiveLogonRight is
omitted from the policy, which are most tests cases, the value from SeInteractiveLogonRight is then copied to
SeRemoteInteractiveLogonRight.

The following code will modify both SeInteractiveActiveLogonRight and SeRemoteInteractiveLogonRight.

.. code-block::
    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }
       )

An administrative user or group always needs to be specified, to prevent administrative lock outs, for the tests
"Domain Admins" group is used.

The following GPO related parameters are not tested
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
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.samba import Samba
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__is_set_to_enforcing(client: Client, provider: GenericADProvider, method: str):
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
        2. User authentications are successful
        3. User authentications are unsuccessful
    :customerscenario: True
    """
    provider.user("user").add()
    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()
    deny_user1 = provider.user("deny_user1").add()
    deny_user2 = provider.user("deny_user2").add()
    group = provider.group("group").add().add_members([user2])
    deny_group = provider.group("deny_group").add().add_members([deny_user2])

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, group, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1, deny_group],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(
        username="user", password="Secret123"
    ), "User absent from policy authenticated successfully!"

    assert client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert client.auth.parametrize(method).password(
        username="user2", password="Secret123"
    ), "Allowed group user authentication failed!"

    assert not client.auth.parametrize(method).password(
        username="deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"

    assert not client.auth.parametrize(method).password(
        username="deny_user2", password="Secret123"
    ), "Denied group user authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__is_set_to_enforcing_with_no_policy(client: Client, provider: GenericADProvider, method: str):
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
    provider.user("user").add()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(username="user", password="Secret123")


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__is_set_to_permissive_and_users_are_allowed(client: Client, provider: GenericADProvider, method: str):
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
    user1 = provider.user("user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "permissive"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "(Permissive) Allowed user authentication failed!"
    log_str = client.fs.read(client.sssd.logs.domain())

    assert (
        "Option ad_gpo_access_control has value permissive" in log_str
    ), "'Option ad_gpo_access_control has value permissive' not in logs!"

    assert "access_granted = 1" in log_str, "'access_granted = 1' not in logs!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__is_set_to_permissive_and_users_are_denied(client: Client, provider: GenericADProvider, method: str):
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
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "permissive"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        username="deny_user1", password="Secret123"
    ), "(Permissive) Denied user authentication failed!"

    log_str = client.fs.read(client.sssd.logs.domain())
    assert (
        "Option ad_gpo_access_control has value permissive" in log_str
    ), "'Option ad_gpo_access_control has value permissive' not in logs!"

    assert "access_granted = 0" in log_str, "'access_granted = 1' not in logs!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__is_set_to_disabled_and_all_users_are_allowed(client: Client, provider: GenericADProvider, method: str):
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
    provider.user("user").add()
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "disabled"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        username="user", password="Secret123"
    ), "(Disabled) User authentication failed!"

    assert client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "(Disabled) User authentication failed!"

    assert client.auth.parametrize(method).password(
        username="deny_user1", password="Secret123"
    ), "(Disabled) User authentication failed!"

    log_str = client.fs.read(client.sssd.logs.domain())
    assert (
        "Option ad_gpo_access_control has value disabled" in log_str
    ), "'Option ad_gpo_access_control has value disabled' not in logs!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(bz=1695576)
def test_gpo__implicit_deny_is_set_to_true(client: Client, provider: GenericADProvider, method: str):
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
    provider.user("user").add()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_implicit_deny"] = "True"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(
        username="user", password="Secret123"
    ), "User authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__domain_and_sites_inheritance_when_site_is_enforcing(
    client: Client, provider: GenericADProvider, method: str
):
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
    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link(enforced=True)

    provider.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=f"{provider.naming_context}")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "User authentication failed!"

    assert not client.auth.parametrize(method).password(
        username="user2", password="Secret123"
    ), "User authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__domain_and_sites_inheritance(client: Client, provider: GenericADProvider, method: str):
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
    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link()

    provider.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=f"{provider.naming_context}")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "Site user authenticated successfully!"

    assert client.auth.parametrize(method).password(
        username="user2", password="Secret123"
    ), "Domain user authentication failed!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__ou_and_domain_inheritance(client: Client, provider: AD, method: str):
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
    user1 = provider.user("user1").add()
    user2 = provider.user("user2").add()
    ou = provider.ou("test").add().dn

    provider.gpo("domain policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user2],
        }
    ).link(target=f"{provider.host.naming_context}")

    provider.gpo("ou policy").add().policy(
        {
            "SeInteractiveLogonRight": [user2, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [user1],
        }
    ).link(target=ou)

    provider.computer(client.host.hostname.split(".")[0]).move(ou)

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "Domain user authenticated successfully!"

    assert client.auth.parametrize(method).password(
        username="user2", password="Secret123"
    ), "OU user authentication failed!"


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
    ).link(order=1)

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert not client.auth.parametrize(method).password(
        username="user1", password="Secret123"
    ), "User authenticated successfully!"

    assert client.auth.parametrize(method).password(username="user2", password="Secret123"), "User failed login!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__map_interactive_disabling_login_su_and_su_l(client: Client, provider: GenericADProvider):
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
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_map_interactive"] = "-logon, -su, -su-l"
    client.sssd.start()

    assert not client.auth.su.password("user1", password="Secret123"), "Allowed user, authenticated SU successfully!"
    assert client.auth.ssh.password("user1", password="Secret123"), "Allowed user SSH authentication failed!"

    assert not client.auth.su.password(
        "deny_user1", password="Secret123"
    ), "Denied user, authenticated SU successfully!"

    assert not client.auth.ssh.password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated SSH successfully!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__map_remote_interactive_disabling_sshd(client: Client, provider: GenericADProvider):
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
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_gpo_map_remote_interactive"] = "-sshd"
    client.sssd.start()

    assert client.auth.su.password("user1", password="Secret123"), "Allowed user SU authentication failed!"
    assert not client.auth.ssh.password("user1", password="Secret123"), "Allowed user, authenticated SSH successfully!"

    assert not client.auth.su.password(
        "deny_user1", password="Secret123"
    ), "Denied user, authenticated SU successfully!"

    assert not client.auth.ssh.password(
        "deny_user1", password="Secret123"
    ), "Denied user, authenticated SSH successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_gpo__works_when_the_server_is_unreachable(client: Client, provider: GenericADProvider, method: str):
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
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"

    client.firewall.outbound.drop_host(provider)
    client.sssd.bring_offline()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(bz=1547234)
def test_gpo__honors_the_ad_site_parameter(client: Client, provider: GenericADProvider, method: str):
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
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()
    provider.site("New-Site").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link(target=f"cn=New-Site,cn=sites,cn=configuration,{provider.naming_context}")

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["ad_site"] = "New-Site"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"


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

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(bz=1316164)
def test_gpo__ignores_invalid_and_unnecessary_keys_and_values(
    client: Client, provider: GenericADProvider, method: str
):
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
    user1 = provider.user("user1").add()
    deny_user1 = provider.user("deny_user1").add()

    provider.gpo("policy invalid keys and values").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        },
        cfg={"Service General Setting": {"BITS": "2", "wuaserv": "2", "MpsSvc": "2"}},
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"


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

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    assert not client.auth.parametrize(method).password(
        "deny_user1", password="Secret123"
    ), "Denied user authenticated successfully!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(bz=2151450)
def test_gpo__finds_all_groups_when_auto_private_groups_is_set_true(
    client: Client, provider: GenericADProvider, method: str
):
    """
    :title: Primary group is missing from users when auto_private_groups are enabled
    :description:
        This tests for a bug where the primary group is not returned when the user is looked up.
    :setup:
        1. Create the following user 'user1'
        2. Create and link the GPO 'site policy' and add 'user1' and 'Domain Admins' to SeInteractiveLogonRight key.
        3. Configure sssd.conf with 'ad_gpo_access_control = enforcing', 'ldap_use_tokengroups = false' and
           'auto_private_groups = true'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Lookup user
    :expectedresults:
        1. Authentication is successful
        2. User found and primary group 'Domain Users' is listed
    :customerscenario: True
    """
    user1 = provider.user("user1").add()

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["auto_private_groups"] = "true"
    client.sssd.domain["ldap_use_tokengroups"] = "false"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"

    result = client.tools.id("user1")
    assert result is not None, "User not found!"
    assert result.memberof("domain users"), "User missing from group 'domain users'!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.parametrize("auto_private_groups", ["true", "false", "hybrid"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(gh=7452)
def test_gpo__works_when_auto_private_group_is_used_with_posix_accounts(
    client: Client, provider: GenericADProvider, method: str, auto_private_groups: str
):
    """
    :title: GPO evaluation fails when auto_private_groups used with posix accounts
    :setup:
        1. Create the following user 'user1' and 'deny_user1' with uids and gids
        2. Create and link the GPO 'site policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1 to SeDenyInteractiveLogonRight key'
        3. Configure sssd.conf with 'ad_gpo_access_control = enforcing',
           'auto_private_groups = parameter' and 'ldap_id_mapping = false'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'deny_user1'
    :expectedresults:
        1. Authentication is successful
        2. Authenticated user is unsuccessful
    :customerscenario: True
    """
    user1 = provider.user("user1").add(uid=10000, gid=10000)
    deny_user1 = provider.user("deny_user1").add(uid=10001, gid=10001)

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["auto_private_groups"] = auto_private_groups
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123"), "Denied user logged in!"


@pytest.mark.importance("critical")
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(gh=7591)
def test_gpo__ldap_user_name_attribute_mapping(client: Client, provider: GenericADProvider, method: str):
    """
    :title: GPO evaluation fails when the LDAP attribute "name" is used instead of default sAMAccountName attribute
    :description: The name attribute is not populated in Samba, limiting the test to AD
    :setup:
        1. Create the following user 'user1' and 'deny_user1' with uids and gids
        2. Create and link the GPO 'site policy' and add 'user1' and 'Domain Admins' to
           SeInteractiveLogonRight key. Add 'deny_user1 to SeDenyInteractiveLogonRight key'
        3. Configure sssd.conf with 'ad_gpo_access_control = enforcing',
           'auto_private_groups = false', 'ldap_user_name = name' and 'ldap_id_mapping = false'
        4. Start SSSD
    :steps:
        1. Authenticate as 'user1'
        2. Authenticate as 'deny_user1'
    :expectedresults:
        1. Authentication is successful
        2. Authenticated user is unsuccessful
    :customerscenario: True
    """
    user1 = provider.user("user1").add(uid=10000, gid=10000)
    deny_user1 = provider.user("deny_user1").add(uid=10001, gid=10001)

    provider.gpo("site policy").add().policy(
        {
            "SeInteractiveLogonRight": [user1, provider.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user1],
        }
    ).link()

    if isinstance(provider, Samba):
        client.sssd.domain["ldap_user_name"] = "givenName"
    if isinstance(provider, AD):
        client.sssd.domain["ldap_user_name"] = "name"

    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.domain["auto_private_groups"] = "false"
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.start()

    assert client.auth.parametrize(method).password(
        "user1", password="Secret123"
    ), "Allowed user authentication failed!"
    assert not client.auth.parametrize(method).password("deny_user1", password="Secret123"), "Denied user logged in!"

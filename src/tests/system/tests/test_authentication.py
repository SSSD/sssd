"""
SSSD Authentication Tests

Tests pertaining to the authentication mechanisms and security policies.

:requirement: authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

intg
====

multihost
=========
# test_password_policy.py
?:test_0001_changeuserpass
?:test_0002_newpassnotmatch
?:test_0003_smallnewpass
?:test_0004_wrongcurrentpass

# test_login_attr.py
?:test_0001_login_by_samaccountname
?:test_0002_login_by_userprincipalname
?:test_0003_login_sssd_domain
?:test_0004_login_sssd_domain_fqn
?:test_0005_login_sssd_domain_uppercase
"""


@pytest.mark.sanity
@pytest.mark.parametrize("username", [("user", True), ("user%", False), ("user_", False)])
def test_authentication__username_characters_combinations_are_valid(username: str):
    """
    :title: Checking valid username character combinations
    # intg/test_ldap.py - test_regression_ticket2163
    """
    pass


def test_authentication__user_is_forced_to_change_expired_password():
    """
    :title: User is prompted and forced to change an expired password
    TODO: framework, user objects in some provider roles need to have this feature added
    TODO: This test exist in test_ldap.py and are current not generic
    """
    pass


def test_authentication__user_password_confirmation_does_not_match():
    """
    :title: User is prompted and the password confirmation contains a typo
    TODO: This test exist in test_ldap.py and are current not generic
    """


def test_authentication__user_enters_wrong_current_password():
    """
    :title: User enters the wrong current password
    TODO: This test exist in test_ldap.py and are current not generic
    """


def test_authentication__user_is_locked_after_failed_login_attempts():
    """
    :title: User is locked after a number of failed login attempts
    TODO: framework, adding a password policy feature to set the number of attempts before lockout
    """
    pass


def test_authentication__user_changed_password_meets_complexity_requirements():
    """
    :title: User password change works when a complexity password policy is present
    TODO: framework, ability to enable password policy complexity
    TODO: suggestion, provider.policy(complex=True | None = False)
    """
    pass


def test_authentication__user_can_login_using_ssh_keys_stored_in_the_directory():
    """
    :title: User can authenticate with no password using the public key attribute
    TODO: framework, some providers do not have the ability to add the public key to the user (easy)
    """
    pass


def test_authentication__with_a_different_auth_provider():
    """
    :title: Authenticate the user using a different provider
    TODO: suggestion, create sssd.common.config with id using local users and krb for auth
    """
    pass


def test_authentication__multiple_sssd_domains_are_configured():
    """
    :title: Authenticate user(s) when more than one SSSD domain is configured
    TODO: create sssd.common.config with two domains, ldap.test and samba.test?
    """
    pass


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__with_default_settings(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Authenticate user with correct password
        2. Authenticate user with incorrect password
    :expectedresults:
        1. Authentication is successful
        2. Authentication is unsuccessful
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"
    assert not client.auth.parametrize(method).password(
        "user1", "NOTSecret123"
    ), "User logged in with an invalid password!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__default_settings_when_the_provider_is_offline(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Authenticate with default settings when the provider is offline
    :setup:
        1. Create user
        2. Configure SSSD with "cache_credentials = true" and "krb5_store_password_if_offline = true" and
        "offline_credentials_expiration = 0"
        3 Start SSSD
    :steps:
        1. Authenticate user with correct password
        2. Offline user authentication with correct password
        3. Offline user authentication with incorrect password
    :expectedresults:
        1. User authentication is successful
        2. User authentication is successful
        3. User authentication is unsuccessful
    :customerscenario: False
    """
    user = "user1"
    correct = "Secret123"
    wrong = "Wrong123"
    provider.user(user).add(password=correct)

    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(user, correct), "User failed login!"

    client.firewall.outbound.reject_host(provider)

    # There might be active connections that are not terminated by creating firewall rule.
    # We need to terminate it by forcing SSSD offline.
    client.sssd.bring_offline()

    assert client.auth.parametrize(method).password(user, correct), "User failed login!"
    assert not client.auth.parametrize(method).password(user, wrong), "User logged in with an incorrect password!"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=7174)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__using_the_users_email_address(client: Client, ad: AD, method: str, sssd_service_user: str):
    """
    :title: Login using the user's email address
    :description:
        Testing the feature to login using an email address instead of the userid. The username used,
        must match one of the user's LDAP attribute values, "EmailAddress". The login should be
        case-insensitive and permit special characters.
    :setup:
        1. Add AD users with different email addresses
        2. Start SSSD
    :steps:
        1. Authenticate users using their email address and in different cases
    :expectedresults:
        1. Authentication is successful using the email address and is case-insensitive
    :customerscenario: False
    """
    ad.user("user-1").add(password="Secret123", email=f"user-1@{ad.host.domain}")
    ad.user("user-2").add(password="Secret123", email="user-2@alias-domain.com")
    ad.user("user_3").add(password="Secret123", email="user_3@alias-domain.com")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(
        f"user-1@{ad.host.domain}", "Secret123"
    ), f"User user-1@{ad.host.domain} failed login!"
    assert client.auth.parametrize(method).password(
        "user-2@alias-domain.com", "Secret123"
    ), "User user-2@alias-domain.com failed login!"
    assert client.auth.parametrize(method).password(
        "uSEr_3@alias-dOMain.com", "Secret123"
    ), "User uSEr_3@alias-dOMain.com failed login!"

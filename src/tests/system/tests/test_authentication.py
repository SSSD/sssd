"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


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
    if method == "ssh" and "ssh" not in client.sssd.sssd["services"]:
        client.sssd.sssd["services"] = "nss, pam, ssh"
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
def test_authentication__password_change_on_login(
    client: Client, provider: GenericProvider, sssd_service_user: str, method: str
):
    """
    :title: User must change their password during the login prompt
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Authenticate as user
        2. Expire the user password
        3. Authenticate as user
        4. Authenticate user with old password
    :expectedresults:
        1. User is authenticated
        2. User password is expired
        3. User is forced to change password and login is successful
        4. User is not authenticated
    :customerscenario: True
    """
    old_pass = "Secret123"
    new_pass = "Password123"

    user = provider.user("user1").add(password=old_pass)
    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.ssh.password(user.name, old_pass), "User failed to authenticate!"
    user.password_change_at_logon()

    # 389ds 'Must change password' needs to be triggered by an administrative password reset first.
    if isinstance(provider, LDAP):
        user.modify(password=old_pass)

    assert client.auth.parametrize(method).password_expired(user.name, old_pass, new_pass), "Password change failed!"

    assert client.auth.parametrize(method).password(user.name, new_pass), "User login failed!"
    assert not client.auth.parametrize(method).password(user.name, old_pass), "Login with old password passed!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("critical")
def test_authentication__password_change_does_not_meet_complexity_requirements(
    client: Client, provider: GenericProvider, method: str
):
    """
    :title: Password change on login when the new passwords do not meet the complexity requirements
    :setup:
        1. Create user
        2. Enable password complexity
        3. Start SSSD
    :steps:
        1. Login as user
        2. Prompt, enter password that does not meet complexity requirements
    :expectedresults:
        1. User logins and is prompted to change password
        2. Password change fails
    :customerscenario: True
    """
    user = provider.user("user1").add(password="Secret123").password_change_at_logon()
    provider.password.complexity(enable=True)

    # 389ds 'Must change password' needs to be triggered by an administrative password reset first.
    if isinstance(provider, LDAP):
        user.modify(password="Secret123")

    client.sssd.start()

    # rc == 1, is specific to failing complexity constraints
    assert (
        client.auth.parametrize(method).password_expired_with_output(user.name, "Secret123", "red_32")[0] == 1
    ), "Password change should not pass!"


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
    if method == "ssh" and "ssh" not in client.sssd.sssd["services"]:
        client.sssd.sssd["services"] = "nss, pam, ssh"
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


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize(
    "home_key",
    ["user", "uid", "fqn", "domain", "first_char", "upn", "default", "lowercase", "substring", "literal%"],
)
@pytest.mark.importance("medium")
def test_authentication__with_overriding_home_directory(client: Client, provider: GenericProvider, home_key: str):
    """
    :title: Override the user's home directory
    :description:
        For simplicity, the home directory is set to '/home/user1' because some providers homedirs are different.
    :setup:
        1. Create user and set home directory to '/home/user1'
        2. Configure SSSD with 'override_homedir' home_key value and restart SSSD
        3. Get entry for 'user1'
    :steps:
        1. Login as 'user1' and check working directory
    :expectedresults:
        1. Login is successful and working directory matches the expected value
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123", home="/home/user1")
    client.sssd.common.mkhomedir()
    client.sssd.start()

    user = client.tools.getent.passwd("user1")
    assert user is not None

    home_map: dict[str, list[str]] = {
        "user": ["/home/%u", f"/home/{user.name}"],
        "uid": ["/home/%U", f"/home/{user.uid}"],
        "fqn": ["/home/%f", f"/home/{user.name}@{client.sssd.default_domain}"],
        "domain": ["/home/%d/%u", f"/home/{client.sssd.default_domain}/{user.name}"],
        "first_char": ["/home/%l", f"/home/{str(user.name)[0]}"],
        "upn": ["/home/%P", f"/home/{user.name}@{provider.domain.upper()}"],
        "default": ["%o", f"{user.home}"],
        "lowercase": ["%h", f"{str(user.home).lower()}"],
        "substring": ["%H/%u", f"/home/homedir/{user.name}"],
        "literal%": ["/home/%%/%u", f"/home/%/{user.name}"],
    }

    if home_key == "upn" and isinstance(provider, LDAP):
        pytest.skip("Skipping provider, userPrincipal attribute is not set!")

    if home_key == "domain":
        client.fs.mkdir_p(f"/home/{client.sssd.default_domain}")

    home_fmt, home_exp = home_map[home_key]
    client.sssd.domain["homedir_substring"] = "/home/homedir"
    client.sssd.domain["override_homedir"] = home_fmt
    client.sssd.restart(clean=True)

    with client.ssh("user1", "Secret123") as ssh:
        result = ssh.run("pwd").stdout
        assert result is not None, "Getting path failed!"
        assert result == home_exp, f"Current path {result} is not {home_exp}!"

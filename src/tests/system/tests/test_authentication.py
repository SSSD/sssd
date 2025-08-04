"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

from inspect import cleandoc

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
def test_authentication__user_login(client: Client, provider: GenericProvider, method: str, sssd_service_user: str):
    """
    :title: Authenticate with default settings
    :setup:
        1. Create user
        2. Start SSSD
    :steps:
        1. Login as user
        2. Login as user with bad password
    :expectedresults:
        1. User can log in
        2. User cannot log in
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
@pytest.mark.importance("critical")
def test_authentication__user_login_then_changes_password(
    client: Client,
    provider: GenericProvider,
):
    """
    :title: User issues a password change after login
    :setup:
        1. Create user 'user'
        2. Start SSSD
    :steps:
        1. Login as user
        2. Issue password change and enter a bad confirmation password
        3. Issue password change and enter a good confirmation password
        4. Login with old password
        5. Login with new password
    :expectedresults:
        1. User is authenticated
        2. Password change is unsuccessful
        3. Password change is successful
        4. User cannot log in
        5. User can log in
    :customerscenario: True
    """
    old_password = "Secret123"
    invalid_password = "secret"
    new_password = "New_Secret123"

    provider.user("user1").add(password=old_password)

    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", old_password, new_password, retyped=invalid_password
    ), "Password should not have been able to be changed!"
    assert client.auth.passwd.password("user1", old_password, new_password), "'user1' password change failed!"

    assert not client.auth.ssh.password("user1", old_password), "'user1' shouldn't have been able to log in!"
    assert client.auth.ssh.password("user1", new_password), "'user1' failed to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.importance("critical")
def test_authentication__user_login_then_changes_password_with_complexity_requirement(
    client: Client,
    provider: GenericProvider,
):
    """
    :title: User issues a password change after login with password policy complexity enabled
    :setup:
        1. Create user 'user'
        2. Enable password complexity requirements
        3. Start SSSD
    :steps:
        1. Login as user
        2. Issue password change as user with password that does not meet complexity requirements
        3. Issue password change as user with password meeting complexity requirements and logout
        4. Login with old password
        5. Login with new password
    :expectedresults:
        1. User is authenticated
        2. Password change is unsuccessful
        3. Password change is successful
        4. User cannot log in
        5. User can log in
    :customerscenario: True
    """
    old_password = "Secret123"
    invalid_password = "secret"
    new_password = "Secret123**%%"

    provider.user("user1").add(password=old_password)
    provider.password_policy.complexity(enable=True)

    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", old_password, invalid_password
    ), "Password should not have been able to be changed!"

    assert client.auth.passwd.password("user1", old_password, new_password), "'user1' password change failed!"
    assert not client.auth.ssh.password("user1", old_password), "'user1' shouldn't have been able to log in!"
    assert client.auth.ssh.password("user1", new_password), "'user1' failed to log in!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__user_is_forced_to_change_expired_password_before_login(
    client: Client, provider: GenericProvider, sssd_service_user: str, method: str
):
    """
    :title: User must change their password during the login prompt
    :setup:
        1. Create user and expire their password
        2. Start SSSD
    :steps:
        1. Login as user and user forced to change password
        2. Enter the current password, new password and then wrong password during confirmation
        3. Login as user and user forced to change password
        4. Enter the current password and the same new password
        5. Login with the new password
        6. Login with the old password
    :expectedresults:
        1. User is authenticated, user is forced to change its password
        2. User is not able to change its password
        3. User is authenticated, user is forced to change its password
        4. Password change succeeds
        5. User can log in
        6. User cannot log in
    :customerscenario: True
    """
    old_pass = "Secret123"
    new_pass = "Password123"

    user = provider.user("user1").add(password=old_pass)
    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.ssh.password(user.name, old_pass), "User failed to authenticate!"
    user.password_change_at_logon(password=old_pass)

    assert client.auth.parametrize(method).password_expired(user.name, old_pass, new_pass), "Password change failed!"

    assert client.auth.parametrize(method).password(user.name, new_pass), "User login failed!"
    assert not client.auth.parametrize(method).password(user.name, old_pass), "Login with old password passed!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__user_login_when_the_provider_is_offline(
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
        1. Login as user
        2. Offline, login as user
        3. Offline, login as user with bad password
    :expectedresults:
        1. User can log in
        2. User can log in
        3. User cannot log in
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
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "home_key",
    ["user", "uid", "fqn", "domain", "first_char", "upn", "default", "lowercase", "substring", "literal%"],
)
@pytest.mark.importance("medium")
def test_authentication__user_login_with_overriding_home_directory(
    client: Client, provider: GenericProvider, home_key: str
):
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


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("medium")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__user_login_with_modified_PAM_stack_provider_is_offline(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Authenticate with modified PAM when the provider is offline
    :setup:
        1. Create user
        2. Configure SSSD with "cache_credentials = true" and "krb5_store_password_if_offline = true" and
            "offline_credentials_expiration = 0"
        3. Back up /etc/pam.d/system-auth and /etc/pam.d/password-auth files
        3. Modify PAM configuration files /etc/pam.d/system-auth, and /etc/pam.d/password-auth so that pam_sss.so
           is using the 'use_first_pass' option and allow another PAM module ask for the password.
        4 Start SSSD
    :steps:
        1. Login as user
        2. Offline, login as user
        3. Offline, login as user with bad password
    :expectedresults:
        1. User can log in
        2. User can log in
        3. User cannot log in
    :customerscenario: True
    """
    user = "user1"
    correct = "Secret123"
    wrong = "Wrong123"
    provider.user(user).add(password=correct)
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"
    client.host.conn.exec(["authselect", "apply-changes", "--backup=mybackup"])
    custom_pam_stack = """
    auth		required	pam_env.so
    auth		sufficient	pam_unix.so try_first_pass likeauth nullok
    auth		required	pam_sss.so forward_pass use_first_pass
    account		sufficient	pam_unix.so
    account		required	pam_sss.so forward_pass
    password	sufficient	pam_unix.so sha512 shadow
    password	required	pam_krb5.so minimum_uid=1000
    session		required	pam_limits.so
    session		required	pam_mkhomedir.so umask=0077
    session		required	pam_env.so
    session		required	pam_unix.so
    session		optional	pam_sss.so forward_pass\n
    """
    client.fs.write("/etc/pam.d/system-auth", cleandoc(custom_pam_stack))
    client.fs.write("/etc/pam.d/password-auth", cleandoc(custom_pam_stack))

    client.sssd.start(service_user=sssd_service_user)

    try:

        assert client.auth.parametrize(method).password(user, correct), "User failed login!"

        client.firewall.outbound.reject_host(provider)

        # There might be active connections that are not terminated by creating firewall rule.
        # We need to terminate it by forcing SSSD offline.
        client.sssd.bring_offline()

        assert client.auth.parametrize(method).password(user, correct), "User failed login!"
        assert not client.auth.parametrize(method).password(user, wrong), "User logged in with an incorrect password!"

    finally:
        client.host.conn.exec(["authselect", "backup-restore", "mybackup"])

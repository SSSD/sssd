"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

import re
import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.kdc import KDC
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
    :title: Offline user login
    :setup:
        1. Create user
        2. Configure SSSD with "cache_credentials" and "krb5_store_password_if_offline" to true,
            "offline_credentials_expiration = 0"
        3. Start SSSD
        4. Login as user to cache user credentials
    :steps:
        1. Block outbound traffic and bring SSSD offline
        2. Login as user with an invalid password
        3. Login as user with the correct password
    :expectedresults:
        1. SSSD is offline
        2. User cannot login with the wrong password
        3. User can login with the correct password
    :customerscenario: True
    """
    provider.user("user1").add()
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"

    client.sssd.start(service_user=sssd_service_user)
    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"

    client.firewall.outbound.reject_host(provider)
    # There might be active connections that are not terminated by creating firewall rule.
    client.sssd.bring_offline()

    assert not client.auth.parametrize(method).password(
        "user1", "BadPassword"
    ), "User logged in with an incorrect password!"
    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize("method", ["ssh", "su"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("medium")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__user_login_when_the_provider_is_offline_and_pam_sss_uses_first_pass(
    client: Client, provider: GenericProvider, method: str, sssd_service_user: str
):
    """
    :title: Offline user login the pam_sss.so module uses the 'use_first_pass' option
    :setup:
        1. Create user
        2. Configure SSSD with "cache_credentials" and "krb5_store_password_if_offline" to true,
            "offline_credentials_expiration = 0"
        3. Select sssd authselect profile and modify pam entries in system-auth and password-auth
            that pam_sss.so is using the 'use_first_pass' option
        4. Start SSSD
        5. Login as user to cache user credentials
    :steps:
        1. Assert that the 'use_first_pass' option is enabled in both pam files
        2. Block outbound traffic and bring SSSD offline
        3. Login as user with an invalid password
        4. Login as user with the correct password
    :expectedresults:
        1. PAM configuration contains 'use_first_pass' option
        2. SSSD is offline
        3. User cannot login with the wrong password
        4. User can login with the correct password
    :customerscenario: True
    """
    provider.user("user1").add()
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.domain["krb5_store_password_if_offline"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "0"

    # This is a temporary workaround until this framework is extended. This method is already called in
    # client.sssd.start(). It is explicitly called here to back up the configuration before it is modified.
    client.authselect.select("sssd")

    pam_auth = client.host.conn.run("cat /etc/pam.d/system-auth").stdout
    pam_auth = re.sub(
        r"(auth\s+sufficient\s+pam_sss\.so forward_pass)",
        r"auth        sufficient      pam_unix.so try_first_pass likeauth nullok\n\1 use_first_pass",
        pam_auth,
    )
    client.fs.write("/etc/pam.d/system-auth", pam_auth)
    client.fs.write("/etc/pam.d/password-auth", pam_auth)

    client.sssd.start(service_user=sssd_service_user)

    assert "use_first_pass" in client.fs.read(
        "/etc/pam.d/system-auth"
    ), "use_first_pass option is not present in 'system-auth'!"
    assert "use_first_pass" in client.fs.read(
        "/etc/pam.d/password-auth"
    ), "use_first_pass option is not present in 'password-auth'!"

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    assert not client.auth.parametrize(method).password(
        "user1", "BadPassword"
    ), "User logged in with an incorrect password!"
    assert client.auth.parametrize(method).password("user1", "Secret123"), "User failed login!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.topology(KnownTopology.Samba)
@pytest.mark.topology(KnownTopology.AD)
def test_disable_an2ln(client: Client, provider: GenericProvider):
    """
    :title: Check localauth plugin config file (IPA/AD version)
    :setup:
        1. Create user
    :steps:
        1. Login as user
        2. Run klist
        3. Read localauth plugin config file
    :expectedresults:
        1. User can log in
        2. Kerberos TGT is available
        3. localauth plugin config file is present and has expected content
    :customerscenario: False
    """
    provider.user("tuser").add()

    pattern = (
        r"\[plugins\]\n localauth = {\n  disable = an2ln\n"
        "  module = sssd:/.*/sssd/modules/sssd_krb5_localauth_plugin.so\n }"
    )

    client.fs.rm("/var/lib/sss/pubconf/krb5.include.d/localauth_plugin")
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            result = krb.klist()
            assert f"krbtgt/{provider.realm}@{provider.realm}" in result.stdout

    try:
        out = client.fs.read("/var/lib/sss/pubconf/krb5.include.d/localauth_plugin")
    except Exception as e:
        assert False, f"Reading plugin config file caused exception: {e}"

    assert re.match(pattern, out), "Content of plugin config file does not match"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ensure_localauth_plugin_is_not_configured(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: Check localauth plugin config file (LDAP with Kerberos version)
    :setup:
        1. Create user in LDAP and KDC
        2. Setup SSSD to use Kerberos authentication
    :steps:
        1. Login as user
        2. Run klist
        3. Read localauth plugin config file
    :expectedresults:
        1. User can log in
        2. Kerberos TGT is available
        3. localauth plugin config file is not present
    :customerscenario: False
    """
    provider.user("tuser").add()
    kdc.principal("tuser").add()

    client.sssd.common.krb5_auth(kdc)

    client.fs.rm("/var/lib/sss/pubconf/krb5.include.d/localauth_plugin")
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            result = krb.klist()
            assert f"krbtgt/{kdc.realm}@{kdc.realm}" in result.stdout

    with pytest.raises(Exception):
        client.fs.read("/var/lib/sss/pubconf/krb5.include.d/localauth_plugin")


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.parametrize(
    "prompting_section",
    ["prompting/password", "prompting/password/su-l"],
    ids=["global_prompt", "service_prompt"],
)
def test_authentication__custom_password_prompt_is_shown_at_login(
    client: Client, provider: GenericProvider, prompting_section: str
):
    """
    :title: Custom password prompt text is shown at login
    :description:
        'su -' uses the 'su-l' PAM service, so the per-service case targets
        '[prompting/password/su-l]', not '[prompting/password/su]'.
    :setup:
        1. Create user
        2. Set a custom 'password_prompt', either globally or for the 'su -' PAM service ('su-l')
        3. Start SSSD
    :steps:
        1. Authenticate as the user via 'su -'
    :expectedresults:
        1. The custom prompt text is shown and authentication succeeds
    :customerscenario: True
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.section(prompting_section)["password_prompt"] = "My custom prompt"
    client.sssd.start()

    result = client.host.conn.run("su - user1 -c 'su - user1 -c whoami'", input="Secret123")
    assert "My custom prompt" in result.stderr, "Custom password prompt was not shown!"
    assert "user1" in result.stdout, "'user1' failed to log in!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_credentials_expiration_within_window(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline auth succeeds within credential expiration window
    :description:
        When offline_credentials_expiration is set to 1 day and the clock is
        advanced 23 hours, cached credentials should still be valid.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True, offline_credentials_expiration=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Skew clock forward 23 hours
        4. Authenticate user with cached credentials
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Clock skewed
        4. Login succeeds (within 1-day expiration window)
    :customerscenario: False
    """
    client.chrony.require()

    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    with client.chrony.time_skew(23 * 3600):
        assert client.auth.ssh.password("user1", "Secret123"), (
            "Offline auth should succeed within credential expiration window"
        )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_credentials_expiration_past_window(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline auth fails after credential expiration window
    :description:
        When offline_credentials_expiration is set to 1 day and the clock is
        advanced 25 hours, cached credentials should be expired and auth should fail.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True, offline_credentials_expiration=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Skew clock forward 25 hours
        4. Authenticate user with cached credentials
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Clock skewed
        4. Login fails (past 1-day expiration window)
    :customerscenario: False
    """
    client.chrony.require()

    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    with client.chrony.time_skew(25 * 3600):
        assert not client.auth.ssh.password("user1", "Secret123"), (
            "Offline auth should fail after credential expiration"
        )


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_credentials_expiration_recovery_after_online(
    client: Client, provider: GenericProvider
):
    """
    :title: Auth succeeds after server comes back online even with expired cached credentials
    :description:
        After cached credentials expire offline, the user should be able to
        authenticate once the server is reachable again (fresh online auth).
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True, offline_credentials_expiration=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Skew clock forward 25 hours (past expiration)
        4. Verify auth fails offline
        5. Restore clock and unblock server
        6. Restart SSSD to go online
        7. Authenticate user
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Clock skewed
        4. Login fails (expired)
        5. Server reachable
        6. SSSD online
        7. Login succeeds (fresh online auth)
    :customerscenario: False
    """
    client.chrony.require()

    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_credentials_expiration"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    with client.chrony.time_skew(25 * 3600):
        assert not client.auth.ssh.password("user1", "Secret123"), (
            "Offline auth should fail after credential expiration"
        )

    client.firewall.outbound.accept_host(provider)
    client.sssd.restart(clean=False)

    assert client.auth.ssh.password("user1", "Secret123"), (
        "Auth should succeed after server comes back online"
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_failed_login_counter_increments_and_lockout(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline failed login counter increments and locks out user at threshold
    :description:
        With offline_failed_login_attempts set, each wrong password offline increments
        the failedLoginAttempts counter in the cache. After reaching the threshold,
        even the correct password is rejected.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True,
           offline_failed_login_attempts=3, offline_failed_login_delay=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt login with wrong password 3 times
        4. Attempt login with correct password
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. All 3 attempts fail
        4. Login fails (user locked out after reaching threshold)
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_failed_login_attempts"] = "3"
    client.sssd.pam["offline_failed_login_delay"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    for i in range(3):
        assert not client.auth.ssh.password("user1", "wrongpassword"), (
            f"Wrong password attempt {i + 1} should fail"
        )

    assert not client.auth.ssh.password("user1", "Secret123"), (
        "Correct password should be rejected after reaching offline_failed_login_attempts threshold"
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_failed_login_counter_resets_on_online_auth(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline failed login counter resets after successful online authentication
    :description:
        After failed offline login attempts, bringing the server back online and
        authenticating successfully should reset the failedLoginAttempts counter to 0.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True,
           offline_failed_login_attempts=4, offline_failed_login_delay=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt login with wrong password twice
        4. Unblock server and restart SSSD
        5. Authenticate with correct password (online)
        6. Verify failedLoginAttempts is 0 in cache
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Both attempts fail
        4. SSSD is online
        5. Login succeeds
        6. Counter is reset to 0
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_failed_login_attempts"] = "4"
    client.sssd.pam["offline_failed_login_delay"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    assert not client.auth.ssh.password("user1", "wrongpassword"), "Wrong password should fail"
    assert not client.auth.ssh.password("user1", "wrongpassword"), "Wrong password should fail"

    client.firewall.outbound.accept_host(provider)
    client.sssd.restart(clean=False)

    assert client.auth.ssh.password("user1", "Secret123"), "Online auth should succeed"

    domain = client.sssd.default_domain
    result = client.ldb.search(
        f"/var/lib/sss/db/cache_{domain}.ldb",
        f"cn={domain},cn=sysdb",
        filter=f"name=user1@{domain}",
    )
    for dn, attrs in result.items():
        if "failedLoginAttempts" in attrs:
            assert attrs["failedLoginAttempts"] == ["0"], (
                f"failedLoginAttempts should be 0 after online auth, got {attrs['failedLoginAttempts']}"
            )


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_failed_login_counter_does_not_exceed_threshold(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline failed login counter does not increment beyond the threshold
    :description:
        After reaching offline_failed_login_attempts threshold, further wrong
        password attempts should not increment the counter beyond the configured limit.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True,
           offline_failed_login_attempts=3, offline_failed_login_delay=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt login with wrong password 5 times (exceeding threshold of 3)
        4. Verify failedLoginAttempts is 3 (not 5) in cache
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. All attempts fail
        4. Counter capped at threshold value
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_failed_login_attempts"] = "3"
    client.sssd.pam["offline_failed_login_delay"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    for i in range(5):
        assert not client.auth.ssh.password("user1", "wrongpassword"), (
            f"Wrong password attempt {i + 1} should fail"
        )

    domain = client.sssd.default_domain
    result = client.ldb.search(
        f"/var/lib/sss/db/cache_{domain}.ldb",
        f"cn={domain},cn=sysdb",
        filter=f"name=user1@{domain}",
    )
    for dn, attrs in result.items():
        if "failedLoginAttempts" in attrs:
            assert attrs["failedLoginAttempts"] == ["3"], (
                f"failedLoginAttempts should be capped at 3, got {attrs['failedLoginAttempts']}"
            )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_failed_login_delay_lockout_and_recovery(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline auth denied during login delay, succeeds after delay expires
    :description:
        After reaching offline_failed_login_attempts threshold, auth is denied
        for offline_failed_login_delay minutes. After the delay, auth succeeds again.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True,
           offline_failed_login_attempts=3, offline_failed_login_delay=1
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt wrong password 3 times (reach threshold)
        4. Attempt correct password (should be locked out)
        5. Wait for offline_failed_login_delay to expire (65 seconds)
        6. Authenticate with correct password
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. All fail
        4. Login fails (locked out)
        5. Delay expired
        6. Login succeeds
    :customerscenario: True
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_failed_login_attempts"] = "3"
    client.sssd.pam["offline_failed_login_delay"] = "1"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    for i in range(3):
        assert not client.auth.ssh.password("user1", "wrongpassword"), (
            f"Wrong password attempt {i + 1} should fail"
        )

    assert not client.auth.ssh.password("user1", "Secret123"), (
        "Correct password should be rejected during lockout"
    )

    time.sleep(65)

    assert client.auth.ssh.password("user1", "Secret123"), (
        "Login should succeed after offline_failed_login_delay expires"
    )


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_failed_login_delay_zero_permanent_denial(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline failed login delay of 0 permanently denies auth until online
    :description:
        When offline_failed_login_delay=0, the user is permanently locked out
        offline after reaching the failed login threshold. Only online auth recovers.
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True,
           offline_failed_login_attempts=3, offline_failed_login_delay=0
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt wrong password 3 times
        4. Wait 30 seconds
        5. Attempt correct password (should still be denied)
        6. Unblock server and restart SSSD
        7. Authenticate online
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. All fail
        4. Time passes
        5. Login fails (permanently denied offline)
        6. SSSD online
        7. Login succeeds
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.pam["offline_failed_login_attempts"] = "3"
    client.sssd.pam["offline_failed_login_delay"] = "0"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    for i in range(3):
        assert not client.auth.ssh.password("user1", "wrongpassword"), (
            f"Wrong password attempt {i + 1} should fail"
        )

    time.sleep(30)

    assert not client.auth.ssh.password("user1", "Secret123"), (
        "Login should be permanently denied offline when delay=0"
    )

    client.firewall.outbound.accept_host(provider)
    client.sssd.restart(clean=False)

    assert client.auth.ssh.password("user1", "Secret123"), (
        "Login should succeed after going back online"
    )


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1361563)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_password_change_shows_offline_message(
    client: Client, provider: GenericProvider
):
    """
    :title: Password change while offline shows "System is offline" message
    :description:
        When the user attempts a password change while SSSD is offline,
        the operation should fail with "System is offline, password change not possible".
    :setup:
        1. Create user with password Secret123
        2. Start SSSD
    :steps:
        1. Authenticate user
        2. Block server and bring SSSD offline
        3. Attempt password change via passwd
        4. Check output for offline message
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Password change fails
        4. Output contains "System is offline, password change not possible"
    :customerscenario: True
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    result = client.host.conn.run(
        "expect -c \"spawn passwd user1; expect eof\"",
        raise_on_error=False,
    )

    assert "System is offline, password change not possible" in result.stdout or \
        "System is offline, password change not possible" in result.stderr, (
        "Offline password change should show 'System is offline' message"
    )


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=875738)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_auth_failure_no_system_error(
    client: Client, provider: GenericProvider
):
    """
    :title: Offline auth failure does not produce "System error" in logs
    :description:
        When a user fails offline authentication with a wrong password, SSSD
        should report proper authentication failure, not "System error".
    :setup:
        1. Create user with password Secret123
        2. Configure SSSD with cache_credentials=True
        3. Start SSSD
    :steps:
        1. Authenticate user to cache credentials
        2. Block server and bring SSSD offline
        3. Attempt login with wrong password
        4. Check PAM log for "System error"
    :expectedresults:
        1. Login succeeds
        2. SSSD is offline
        3. Login fails
        4. "System error" is NOT in PAM log
    :customerscenario: True
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.start()

    assert client.auth.ssh.password("user1", "Secret123"), "Initial login should succeed"

    client.firewall.outbound.reject_host(provider)
    client.sssd.bring_offline()

    assert not client.auth.ssh.password("user1", "wrongpassword"), "Wrong password should fail"

    log = client.fs.read(client.sssd.logs.pam)
    assert "System error" not in log, (
        "'System error' should not appear in PAM log for offline auth failure"
    )


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1499658)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_authentication__offline_cache_injection_protection(
    client: Client, provider: GenericProvider
):
    """
    :title: Unsanitized input in cache lookup does not leak cached passwords
    :description:
        SSSD must sanitize user input when searching the local cache database.
        A crafted username with LDAP filter injection characters should not
        return other users' cached password hashes.
    :setup:
        1. Create user "victim" with password Secret123
        2. Configure SSSD with cache_credentials=True
        3. Start SSSD
    :steps:
        1. Authenticate victim to cache credentials
        2. Attempt getent passwd with injection string
    :expectedresults:
        1. Login succeeds
        2. Injection lookup returns no results (exit code 2)
    :customerscenario: True
    """
    provider.user("victim").add(password="Secret123")
    client.sssd.domain["cache_credentials"] = "True"
    client.sssd.start()

    assert client.auth.ssh.password("victim", "Secret123"), "Initial login should succeed"

    result = client.host.conn.run(
        "getent passwd 'xxx)(&(name=victim@ldap)(cachedPassword=$6$*))(xxx=xxx@xxx'",
        raise_on_error=False,
    )
    assert result.rc == 2, (
        f"Injection lookup should return no results (exit code 2), got exit code {result.rc}"
    )

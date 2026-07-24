"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

import re
import textwrap
from inspect import cleandoc

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.roles.samba import Samba
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


@pytest.mark.importance("medium")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.ALLDC)
def test_authentication__pam_sss_domains_skips_non_matching_krb5_domains(
    client: Client, samba: Samba, ipa: IPA, kdc: KDC
):
    """
    :title: pam_sss.so 'domains' authenticates only against the listed Kerberos realm domain
    :description:
        Local users may authenticate via Kerberos against one of several configured realms
        (Samba, IPA, or a standalone KDC). The same username exists in every realm with a
        different password; each PAM 'domains=' line ignores the other realms and only tries
        its listed domain.
    :setup:
        1. Add a local user and create 'user1' in the Samba, IPA, and KDC realms with
           different passwords
        2. Configure three SSSD domains (samba, ipa, krb5) with id_provider=proxy/files and
           auth_provider=krb5 using each provider's realm
        3. Replace 'su-l' with three 'sufficient' pam_sss.so lines, each limited by 'domains='
    :steps:
        1. Authenticate as the local user via 'su -' using the KDC password
        2. Change the IPA principal's password to match the KDC password and authenticate again
    :expectedresults:
        1. Authentication succeeds via 'domains=krb5'; Samba and IPA users exist but are
           ignored by that PAM line
        2. Authentication succeeds via 'domains=ipa', since that line is tried first and now
           matches too
    :customerscenario: True
    """
    client.local.user("user1").add(password="LocalSecret123")
    samba.user("user1").add(password="SambaSecret123")
    ipa.user("user1").add(password="IPASecret123")
    kdc.principal("user1").add(password="KDCSecret123")

    client.sssd.fs.write(
        "/etc/krb5.conf",
        textwrap.dedent(f"""
            [libdefaults]
            default_realm = {kdc.realm}
            dns_lookup_realm = false
            dns_lookup_kdc = false
            ticket_lifetime = 24h
            renew_lifetime = 7d
            forwardable = yes

            [realms]
            {samba.realm} = {{
              kdc = {samba.host.hostname}
            }}
            {ipa.realm} = {{
              kdc = {ipa.host.hostname}
            }}
            {kdc.realm} = {{
              kdc = {kdc.host.hostname}:88
              admin_server = {kdc.host.hostname}:749
            }}
            """).lstrip(),
        user="root",
        group="root",
        mode="0644",
    )

    for name, role in (("samba", samba), ("ipa", ipa), ("krb5", kdc)):
        client.sssd.dom(name).update(
            enabled="true",
            id_provider="proxy",
            proxy_lib_name="files",
            auth_provider="krb5",
            krb5_realm=role.realm,
            krb5_server=role.host.hostname,
        )
    client.sssd.sssd["domains"] = "samba, ipa, krb5"
    client.sssd.default_domain = "krb5"
    client.sssd.start()

    client.fs.backup("/etc/pam.d/su-l")
    client.fs.write(
        "/etc/pam.d/su-l",
        cleandoc("""
            auth        required    pam_env.so
            auth        sufficient  pam_sss.so forward_pass domains=samba
            auth        sufficient  pam_sss.so forward_pass domains=ipa
            auth        sufficient  pam_sss.so forward_pass domains=krb5
            auth        required    pam_deny.so
            account     required    pam_sss.so
            password    required    pam_sss.so
            session     required    pam_sss.so
            """),
    )

    assert client.auth.su.password(
        "user1", "KDCSecret123"
    ), "Authentication should succeed via the matching 'domains=krb5' line!"

    # IPA always forces an immediate password-expiration on an administrative password reset,
    # even if 'password-expiration' is passed in the same call, so it must be pushed back out
    # in a separate modification.
    ipa.user("user1").modify(password="KDCSecret123")
    ipa.user("user1").modify(password_expiration="20380101120000Z")

    assert client.auth.su.password(
        "user1", "KDCSecret123"
    ), "Authentication should also succeed via the earlier 'domains=ipa' line once its password matches!"

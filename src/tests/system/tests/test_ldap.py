"""
SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.ticket(bz=[795044, 1695574])
@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_ldap__password_change(client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str, sssd_service_user: str):
    """
    :title: Change password with "ldap_pwmodify_mode" set to @modify_mode
    :setup:
        1. Add user to LDAP, set his password
        2. Allow user to change his password
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Authenticate user with old password
        2. Change password of user to new password
        3. Authenticate user with new password
        4. Authenticate user with old password
    :expectedresults:
        1. User is authenticated
        2. Password is changed successfully
        3. User is authenticated
        4. User is not authenticated
    :customerscenario: True
    """
    user = "user1"
    old_pass = "Secret123"
    new_pass = "New_password123"

    ldap.user(user).add(password=old_pass)
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = use_ppolicy
    client.sssd.start()

    assert client.auth.ssh.password(user, old_pass), "Authentication with old correct password failed"

    assert client.auth.passwd.password(user, old_pass, new_pass), "Password change was not successful"

    assert client.auth.ssh.password(user, new_pass), "Authentication with new correct password failed"
    assert not client.auth.ssh.password(user, old_pass), "Authentication with old incorrect password did not fail"


@pytest.mark.ticket(bz=[795044, 1695574])
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__password_change_new_passwords_do_not_match(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str
):
    """
    :title: Change password with "ldap_pwmodify_mode" set to @modify_mode, but retyped password do not match
    :setup:
        1. Add user to LDAP, set his password
        2. Allow user to change his password
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Change password to new password, but retyped password is different
    :expectedresults:
        1. Password change is not successful
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = use_ppolicy
    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", "Secret123", "Red123", "Hat000"
    ), "Password changed successfully, which is not expected"


@pytest.mark.ticket(bz=[795044, 1695574, 1795220])
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__password_change_new_password_does_not_meet_complexity_requirements(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str
):
    """
    :title: Change password to lower-case letters, password check fail
    :setup:
        1. Add user to LDAP, set his password
        2. Allow user to change his password
        3. Set "passwordCheckSyntax" to "on"
        4. Set "ldap_pwmodify_mode"
        5. Start SSSD
    :steps:
        1. Change password to new password, but all letters are lower-case
        2. Check logs
    :expectedresults:
        1. Password change failed
        2. Password change failure is logged
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')
    ldap.ldap.modify("cn=config", replace={"passwordCheckSyntax": "on"})

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = use_ppolicy
    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", "Secret123", "red_32"
    ), "Password changed successfully, which is not expected"

    assert (
        "pam_sss(passwd:chauthtok): User info message: Password change failed."
        in client.host.ssh.run("journalctl").stdout
    )


@pytest.mark.ticket(bz=[1695574, 1795220])
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__password_change_failed_current_password(client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str):
    """
    :title: Password change failed because an incorrect password was used
    :setup:
        1. Add user to LDAP, set his password
        2. Allow user to change his password
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Change password to new password, but enter wrong password
    :expectedresults:
        1. Password change is not successful
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = use_ppolicy
    client.sssd.start()

    assert not client.auth.passwd.password("user1", "wrong123", "Newpass123"), "Password change did not fail"


@pytest.mark.ticket(bz=[1067476, 1065534])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__authenticate_user_with_whitespace_prefix_in_userid(client: Client, ldap: LDAP):
    """
    :title: user with a whitespace at beginning is able to login and "id"
    :setup:
        1. Add users " space1" and "user1" to LDAP
        2. Set uids and passwords to users
        3. Clear memcache, logs and db
        4. Start SSSD
    :steps:
        1. Fetch user " space1" information using 'id'
        2. Login user " space1" via ssh
        3. Login user "space1" via ssh
        4. Fetch "user1" user information using 'id'
        5. Fetch " user1" user information using 'id'
    :expectedresults:
        1. " space1" is fetched and has correct id
        2. " space1" is able to login
        3. "space1" is not able to login
        4. "user1" is fetched and has correct id
        5. " user1" is not fetched
    :customerscenario: True
    """
    ldap.user(" space1").add(uid=10011, password="Secret123")
    ldap.user("user1").add(uid=10012, password="Secret123")
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    result = client.tools.id(" space1")
    assert result is not None, "User ' space1' was not found"
    assert result.user.id == 10011, "User ' space1' has wrong id"

    assert client.auth.ssh.password(" space1", "Secret123"), "Authentication for user ' space1' failed"
    assert not client.auth.ssh.password("space1", "Secret123"), "Authentication for user 'space1' did not fail"

    result = client.tools.id("user1")
    assert result is not None, "User 'user1' was not found"
    assert result.user.id == 10012, "User 'user1' has wrong id"

    result = client.tools.id(" user1")
    assert result is None, "User ' user1' was found, not expected"


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=1507035)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_ldap__change_password_when_ldap_pwd_policy_is_set_shadow(client: Client, ldap: LDAP, method: str):
    """
    :title: Change password with shadow ldap password policy
    :setup:
        1. Allow user to change its own password in LDAP
        2. Create LDAP user "tuser" with shadowLastChange = 0
        3. Set ldap_pwd_policy to "shadow"
        4. Set ldap_chpass_update_last_change to "True"
        5. Start SSSD
    :steps:
        1. Authenticate as "tuser" with old password
        2. Autheticate as "tuser" with new password
    :expectedresults:
        1. Password was expired and new password was expected and provided
        2. Authentication with new password was successful
    :customerscenario: True
    """
    ldap.aci.add('(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)')
    ldap.user("tuser").add(
        uid=999011, gid=999011, shadowMin=0, shadowMax=99999, shadowWarning=7, shadowLastChange=0, password="Secret123"
    )

    client.sssd.domain["ldap_pwd_policy"] = "shadow"
    client.sssd.domain["ldap_chpass_update_last_change"] = "True"
    client.sssd.start()

    # Password is expired, change it
    assert client.auth.parametrize(method).password_expired("tuser", "Secret123", "Redhat@321")

    # Authenticate with new password
    assert client.auth.parametrize(method).password("tuser", "Redhat@321")


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1928648)
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__network_timeout_parameters_shown_in_logs(client: Client, ldap: LDAP):
    """
    :title: Each timeout setting is properly logged in logs
    :setup:
        1. Add user
        2. Start SSSD
    :steps:
        1. Check that "Setting 6 seconds timeout [ldap_network_timeout] for connecting" is in logs
        2. Fetch information about user
        3. Block LDAP traffic
        4. Connect user over SSH
        5. Logs should contain following timeout parameters
             - ldap_opt_timeout
             - ldap_search_timeout
             - ldap_network_timeout
             - dns_resolver_timeout
    :expectedresults:
        1. Timeout setting is stored in logs
        2. User is found
        3. LDAP traffic is blocked
        4. User is unable to connect
        5. The timeout parameters are in the logs
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    client.sssd.start()

    log = client.fs.read(f"/var/log/sssd/sssd_{client.sssd.default_domain}.log")
    assert "Setting 6 seconds timeout [ldap_network_timeout] for connecting" in log

    assert client.tools.id("user1") is not None

    client.firewall.outbound.drop_host(ldap)

    with pytest.raises(Exception):
        client.ssh("user1", "Secret123").connect()

    log = client.fs.read(f"/var/log/sssd/sssd_{client.sssd.default_domain}.log")
    for timeout in ["ldap_opt_timeout", "ldap_search_timeout", "ldap_network_timeout", "dns_resolver_timeout"]:
        assert timeout in log, f"Value '{timeout}' not found in logs"


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__authenticate_user_with_empty_ldap_search_base(client: Client, ldap: LDAP):
    """
    :title: Without ldapsearch base specified in sssd conf and rootDSE exists
    :setup:
        1. With sssd config set enumerate = True.
        2. Set sssd config nss part with filter_groups and filter_users to root.
        3. Add test user with password and make sure it can authenticate.
    :steps:
        1. Without ldap_search_base set when user authenticates certain logs
            should appear in sssd domain logs.
        2. Now set ldap_search_base in sssd config try with user authentication ,
            in sssd domain logs sdap_set_config_options_with_rootdse should not appear.
    :expectedresults:
        1. Certain logs should appear in sssd domain logs
        2. In sssd domain logs sdap_set_config_options_with_rootdse should not appear.
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    client.sssd.dom("test")["enumerate"] = "true"
    client.sssd.config["nss"] = {
        "filter_groups": "root",
        "filter_users": "root",
    }

    ou_users = ldap.ou("users").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    assert client.auth.ssh.password(user.name, "Secret123")
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    for doc in [
        f"Setting option [ldap_search_base] to [{base}]",
        f"Setting option [ldap_user_search_base] to [{base}]",
        f"Setting option [ldap_group_search_base] to [{base}]",
        f"Setting option [ldap_netgroup_search_base] to [{base}]",
    ]:
        assert doc in str(log)
    client.sssd.dom("test")["ldap_search_base"] = ldap.ldap.naming_context

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    assert client.auth.ssh.password("puser1", "Secret123")
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    assert "sdap_set_config_options_with_rootdse" not in log


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "user_search_base, search_base",
    [
        ("ldap_user_search_base", "ou=People,dc=ldap,dc=test"),
        ("ldap_group_search_base", "ou=Groups,dc=ldap,dc=test"),
        ("ldap_netgroup_search_base", "ou=Netgroup,dc=ldap,dc=test"),
    ],
)
def test_ldap__authenticate_user_with_search_base_set(client: Client, ldap: LDAP, user_search_base, search_base):
    """
    :title: Without ldapsearch base and with ldap user search base specified
    :setup:
        1. With sssd config set enumerate = True.
        2. Set sssd config nss part with filter_groups and filter_users to root.
        3. Add test user with password and make sure it can authenticate.
    :steps:
        1. Set user_search_base to sssd config.
        2. Set ldap_group_search_base to sssd config.
        3. Set ldap_netgroup_search_base to sssd config.
        4. With each search base there will be different logs generated in sssd domain logs.
    :expectedresults:
        1. User_search_base should be set to sssd config.
        2. Ldap_group_search_base should be set to sssd config.
        3. Ldap_netgroup_search_base should be set to sssd config.
        4. There will be different logs generated in sssd domain logs.
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    client.sssd.dom("test")["enumerate"] = "true"
    client.sssd.dom("test")[user_search_base] = search_base
    client.sssd.config["nss"] = {
        "filter_groups": "root",
        "filter_users": "root",
    }

    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None
    assert result.name == user.name

    assert client.auth.ssh.password(user.name, "Secret123")
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    match user_search_base:
        case "ldap_user_search_base":
            for doc in [
                "Got rootdse",
                f"Setting option [ldap_search_base] to [{base}]",
                f"Setting option [ldap_group_search_base] to [{base}]",
                f"Setting option [ldap_netgroup_search_base] to [{base}]",
            ]:
                assert doc in str(log)
        case "ldap_group_search_base":
            for doc in [
                "Got rootdse",
                f"Setting option [ldap_search_base] to [{base}]",
                f"Setting option [ldap_user_search_base] to [{base}]",
                f"Setting option [ldap_netgroup_search_base] to [{base}]",
            ]:
                assert doc in str(log)
        case "ldap_netgroup_search_base":
            for doc in [
                "Got rootdse",
                f"Setting option [ldap_search_base] to [{base}]",
                f"Setting option [ldap_user_search_base] to [{base}]",
                f"Setting option [ldap_group_search_base] to [{base}]",
            ]:
                assert doc in str(log)


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__lookup_user_default_naming_context_and_no_search_base(client: Client, ldap: LDAP):
    """
    :title: Without ldapsearch base and default namingContexts
    :setup:
        1. With sssd config set enumerate = True.
        2. Set sssd config nss part with filter_groups and filter_users to root.
        3. Add test user with password and make sure it can authenticate.
    :steps:
        1. Sssd without ldapsearch base and default namingContexts.
        2. Sssd should generate some logs when try to authenticate with users.
    :expectedresults:
        1. Sssd should work without ldapsearch base and default namingContexts.
        2. Sssd should generate some logs when try to authenticate with users.
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    client.sssd.dom("test")["enumerate"] = "true"
    client.sssd.config["nss"] = {
        "filter_groups": "root",
        "filter_users": "root",
    }

    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None
    assert result.name == user.name
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    assert "Got rootdse" in log
    assert "Using value from [defaultNamingContext] as naming context" in log
    assert f"Setting option [ldap_search_base] to [{base}]" in log


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("user_search_base", ["dc=ldap,dc=test", "dc=shanks,dc=com"])
def test_ldap__lookup_user_multiple_naming_contexts_and_no_search_base(client: Client, ldap: LDAP, user_search_base):
    """
    :title: Without ldapsearch base and multiple namingContexts
    :setup:
        1. With sssd config set enumerate = True.
        2. Set sssd config nss part with filter_groups and filter_users to root.
        3. Add test user with password and make sure it can authenticate.
    :steps:
        1. Sssd with user_search_base "dc=ldap,dc=test"
        2. Sssd with user_search_base "dc=shanks,dc=com"
        3. With both the cases sssd authentication should work when we configure it with ldap_search_base,
            ldap_user_search_base, ldap_group_search_base.
    :expectedresults:
        1. Sssd should be configured user_search_base "dc=ldap,dc=test"
        2. Sssd should be configured user_search_base "dc=shanks,dc=com"
        3. User authentication should be success with both the cases.
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.dom("test")["enumerate"] = "true"
    client.sssd.dom("test")["ldap_search_base"] = user_search_base
    client.sssd.dom("test")["ldap_user_search_base"] = f"ou=People,{base}"
    client.sssd.dom("test")["ldap_group_search_base"] = f"ou=Groups,{base}"
    client.sssd.config["nss"] = {
        "filter_groups": "root",
        "filter_users": "root",
    }

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None
    assert result.name == user.name
    assert client.auth.ssh.password(user.name, "Secret123")

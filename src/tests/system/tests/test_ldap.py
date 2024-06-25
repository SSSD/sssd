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
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.skipif(
    bool(lambda client, sssd_service_user: ((sssd_service_user != "root") and not client.features["non-privileged"])),
    reason="SSSD was built without support for running under non-root",
)
@pytest.mark.skipif(
    bool(lambda client: not client.features["ldap_use_ppolicy"]),
    reason="SSSD is missing support for ldap_use_ppolicy.",
)
def test_ldap__password_change_using_ppolicy(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str, sssd_service_user: str
):
    """
    :title: Password change using ppolicy
    :description: PPolicy overlay is the latest implementation of IETF password policy for LDAP.
    This extends the password policy for the LDAP server and is configured in SSSD using
    'ldap_use_ppolicy'.

    Two password modification modes are tested, Extended Operation (exop), the default and then
    LDAP (ldapmodify), set by 'ldap_pwmodify_mode' parameter.
    :note: This feature is introduced in SSSD 2.10.0
    :setup:
        1. Add a user to LDAP
        2. Configure the LDAP ACI to permit user password changes
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Authenticate as user
        2. Change the password of user
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

    assert client.auth.ssh.password(user, old_pass), "Login with old password failed!"

    assert client.auth.passwd.password(user, old_pass, new_pass), "Password change failed!"

    assert client.auth.ssh.password(user, new_pass), "User login failed!"
    assert not client.auth.ssh.password(user, old_pass), "Login with old password passed!"


@pytest.mark.ticket(bz=[795044, 1695574])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.skipif(
    bool(lambda client: not client.features["ldap_use_ppolicy"]),
    reason="SSSD is missing support for ldap_use_ppolicy.",
)
def test_ldap__password_change_new_passwords_do_not_match_using_ppolicy(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str
):
    """
    :title: Password change when the new passwords do not match
    :setup:
        1. Add user to LDAP
        2. Configure the LDAP ACI to permit user password changes
        3. set "ldap_pwmodify_mode"
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
    ), "Password should not have been able to be changed!"


@pytest.mark.ticket(bz=[795044, 1695574, 1795220])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.skipif(
    bool(lambda client: not client.features["ldap_use_ppolicy"]),
    reason="SSSD is missing support for ldap_use_ppolicy.",
)
def test_ldap__password_change_new_password_does_not_meet_complexity_requirements_using_ppolicy(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str
):
    """
    :title: Password change when the new passwords do not meet the complexity requirements using ppolicy
    :setup:
        1. Add a user to LDAP
        2. Configure the LDAP ACI to permit user password changes
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
    ), "Password should not have been able to be changed!"

    assert (
        "pam_sss(passwd:chauthtok): User info message: Password change failed."
        in client.host.ssh.run("journalctl").stdout
    )


@pytest.mark.ticket(bz=[1695574, 1795220])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.skipif(
    bool(lambda client: not client.features["ldap_use_ppolicy"]),
    reason="SSSD is missing support for ldap_use_ppolicy.",
)
def test_ldap__password_change_with_invalid_current_password_using_ppolicy(
    client: Client, ldap: LDAP, modify_mode: str, use_ppolicy: str
):
    """
    :title: Password change fails with invalid current password
    :setup:
        1. Add a user to LDAP, set his password
        2. Configure the LDAP ACI to permit user password changes
        3. Set "ldap_pwmodify_mode"
        4. Start SSSD
    :steps:
        1. Attempt to change the password but enter the incorrect password
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
        "user1", "wrong123", "Newpass123"
    ), "Password should not have been able to be changed!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=[1067476, 1065534])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__authenticate_user_with_whitespace_prefix_in_userid(client: Client, ldap: LDAP):
    """
    :title: Authenticate with a user containing a blank space in the userid
    :description: This can only be tested on LDAP because most directories have
    constraints on the values, protecting the integrity of the data. This scenario
    is most likely created migrating and, or upgrading old databases.
    :setup:
        1. Add users " space1" and "user1"
        2. Start SSSD
    :steps:
        1. Lookup user " space1"
        2. Login user " space1"
        3. Login user "space1"
        4. Lookup "user1" user
        5. Lookup " user1" user
    :expectedresults:
        1. " space1" is found and has correct id
        2. " space1" is able to log in
        3. "space1" is not able to log in
        4. "user1" is found and has correct id
        5. " user1" is not found
    :customerscenario: True
    """
    ldap.user(" space1").add(uid=10011, password="Secret123")
    ldap.user("user1").add(uid=10012, password="Secret123")
    client.sssd.start()

    result = client.tools.id(" space1")
    assert result is not None, "User ' space1' was not found"
    assert result.user.id == 10011, "User ' space1' has wrong id"

    assert client.auth.ssh.password(" space1", "Secret123"), "User ' space1' login failed!"
    assert not client.auth.ssh.password("space1", "Secret123"), "User 'space1' login should have failed!"

    result = client.tools.id("user1")
    assert result is not None, "User 'user1' not found!"
    assert result.user.id == 10012, "User 'user1' has the wrong uid!"

    result = client.tools.id(" user1")
    assert result is None, "User ' user1' should not be found!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1507035)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("method", ["su", "ssh"])
def test_ldap__change_password_when_ldap_pwd_policy_is_set_to_shadow(client: Client, ldap: LDAP, method: str):
    """
    :title: Change password with shadow ldap password policy is set to shadow
    :description: Changing a password when the password policy is managed by the shadowAccount objectclass.
    :setup:
        1. Configure the LDAP ACI to permit user password changes
        2. Create user with shadowLastChange = 0, shadowMin = 0, shadowMax = 99999 and shadowWarning = 7
        3. Set "ldap_pwd_policy = shadow"
        4. Set "ldap_chpass_update_last_change = True"
        5. Start SSSD
    :steps:
        1. Authenticate as "tuser" with old password
        2. Authenticate as "tuser" with new password
    :expectedresults:
        1. The password is expired, and the user is forced to change their password
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

    assert client.auth.parametrize(method).password_expired(
        "tuser", "Secret123", "Redhat@321"
    ), "Password change failed!"
    assert client.auth.parametrize(method).password("tuser", "Redhat@321"), "User 'tuser' login failed!"

    log = client.fs.read(f"/var/log/sssd/sssd_{client.sssd.default_domain}.log")
    for timeout in ["ldap_opt_timeout", "ldap_search_timeout", "ldap_network_timeout", "dns_resolver_timeout"]:
        assert timeout in log, f"Value '{timeout}' not found in logs"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__search_base_is_discovered_and_defaults_to_root_dse(client: Client, ldap: LDAP):
    """
    :title: Search base is discovered and defaults to the directories root DSE
    :setup:
        1. Create OU
        2. Create user, and put the user object in the new OU
        3. Start SSSD
    :steps:
        1. Authenticate as user and check the logs
        2. Add "ldap_search_base" to the configuration and cleanly restart SSSD
        3. Authenticate as user and check the logs
    :expectedresults:
        1. User authentication is successful, and logs contain messages discovering root DSE
        2. SSSD is configured and cleanly restarted
        3. User authentication is successful, and logs contain no messages searching root DSE
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    ou_users = ldap.ou("users").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

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
        assert doc in str(log), f"String '{doc}' not found in logs!"
    client.sssd.dom("test")["ldap_search_base"] = ldap.ldap.naming_context

    client.sssd.stop()
    client.sssd.clear()
    client.sssd.start()

    assert client.auth.ssh.password("puser1", "Secret123"), "User 'puser1' login failed!"
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    assert "sdap_set_config_options_with_rootdse" not in log, "sdap_set_config_options_with_rootdse found in logs!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize(
    "user_search_base, search_base",
    [
        ("ldap_user_search_base", "ou=People,dc=ldap,dc=test"),
        ("ldap_group_search_base", "ou=Groups,dc=ldap,dc=test"),
        ("ldap_netgroup_search_base", "ou=Netgroup,dc=ldap,dc=test"),
    ],
)
def test_ldap__search_base_is_discovered_and_defaults_to_root_dse_users_groups_and_netgroups(
    client: Client, ldap: LDAP, user_search_base, search_base
):
    """
    :title: Search base is discovered and defaults to the directories root DSE for users, groups and netgroups
    :setup:
        1. Create People OU
        2. Create user, and put the user object in the new OU
        3. Configure SSSD with "user_search_base" and start SSSD
    :steps:
        1. Lookup user and authenticate as user and check the logs
    :expectedresults:
        1. User authentication is successful, and logs contain messages setting ldap_x_search_base to the root DSE
    :customerscenario: False
    """
    base = ldap.ldap.naming_context
    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.dom("test")[user_search_base] = search_base
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
                assert doc in str(log), f"String '{doc}' not found in logs!"
        case "ldap_group_search_base":
            for doc in [
                "Got rootdse",
                f"Setting option [ldap_search_base] to [{base}]",
                f"Setting option [ldap_user_search_base] to [{base}]",
                f"Setting option [ldap_netgroup_search_base] to [{base}]",
            ]:
                assert doc in str(log), f"String '{doc}' not found in logs!"
        case "ldap_netgroup_search_base":
            for doc in [
                "Got rootdse",
                f"Setting option [ldap_search_base] to [{base}]",
                f"Setting option [ldap_user_search_base] to [{base}]",
                f"Setting option [ldap_group_search_base] to [{base}]",
            ]:
                assert doc in str(log), f"String '{doc}, not found in logs!"


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__lookup_user_with_search_bases(client: Client, ldap: LDAP):
    """
    :title: Looking up with no search base configured
    :setup:
        1. Create People OU
        2. Create user and put the user object into the OU
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Look at logs
    :expectedresults:
        1. User is found
        2. Strings pertaining to rootdse search base discovery are found
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None, "User not found!"
    assert result.name == user.name, "Username is not correct!"
    time.sleep(3)

    log = client.fs.read(client.sssd.logs.domain())
    assert "Got rootdse" in log, "Unable to find rootDSE!"
    assert "Using value from [defaultNamingContext] as naming context" in log, "Unable to find naming context!"
    assert f"Setting option [ldap_search_base] to [{base}]" in log, "Unable to set ldap_search_base!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("user_search_base", ["dc=ldap,dc=test", "dc=shanks,dc=com"])
def test_ldap__lookup_and_authenticate_as_user_with_different_object_search_bases(
    client: Client, ldap: LDAP, user_search_base
):
    """
    :title: Looking up and authenticating as a user when the default, user and group search bases are different
    :setup:
        1. Create People OU
        2. Create user and put the user object into the new OU
        3. Configure "ldap_search_base", "ldap_user|group_search_base" and start SSSD
    :steps:
        1. Lookup and authenticate as user
    :expectedresults:
        1. User lookup and authentication are successful
    :customerscenario: False
    """
    base = ldap.ldap.naming_context

    ou_users = ldap.ou("People").add()
    user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")

    client.sssd.dom("test")["ldap_search_base"] = user_search_base
    client.sssd.dom("test")["ldap_user_search_base"] = f"ou=People,{base}"
    client.sssd.dom("test")["ldap_group_search_base"] = f"ou=Groups,{base}"

    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None, "User is not found!"
    assert result.name == user.name, "Username is not correct!"
    assert client.auth.ssh.password(user.name, "Secret123"), "User login failed!"

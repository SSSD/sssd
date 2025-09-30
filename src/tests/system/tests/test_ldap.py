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


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.importance("critical")
def test_ldap__ppolicy_user_login_then_changes_password(client: Client, ldap: LDAP, modify_mode: str):
    """
    :title: User issues a password change after login against ppolicy overlay
    :description:
        Password Policy (ppolicy) is a loadable module that enables password policies in LDAP.
        The feature offers two methods to update the password, external operation (exop) or
        LDAP modify.

        The 'test_authentication__change_password' test is a generic provider test that already
         covers  LDAP. This test is an edited copy that only tests LDAP with the ppolicy overlay.
    :setup:
        1. Create user 'user'
        2. Configure SSSD with 'ldap_pwmodify_mode = exop | ldap_modify | exop_force' and 'ldap_user_ppolicy = true
        3. Start SSSD
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

    ldap.user("user1").add(password=old_password)
    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = "True"

    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", old_password, new_password, retyped=invalid_password
    ), "Password should not have been able to be changed!"
    assert client.auth.passwd.password("user1", old_password, new_password), "'user1' password change failed!"

    assert not client.auth.ssh.password("user1", old_password), "'user1' shouldn't have been able to log in!"
    assert client.auth.ssh.password("user1", new_password), "'user1' failed to log in!"


@pytest.mark.ticket(bz=[795044, 1695574, 1795220])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__ppolicy_user_login_then_changes_password_complexity_requirement(
    client: Client,
    ldap: LDAP,
    modify_mode: str,
):
    """
    :title: User issues a password change after login with password policy complexity enabled against ppolicy overlay
    :description:
        Password Policy (ppolicy) is a loadable module that enables password policies in LDAP.
        The feature offers two methods to update the password, external operation (exop) or
        LDAP modify.

        The 'test_authentication__change_password_with_complexity_requirement' test is a generic
        provider test that already covers  LDAP. This test is an edited copy that only tests LDAP
        with theppolicy overlay.
    :setup:
        1. Add a user to LDAP
        2. Enable password complexity requirements
        3. Configure SSSD with 'ldap_pwmodify_mode = exop | ldap_modify | exop_force' and 'ldap_user_ppolicy = true
        4. Start SSSD
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

    ldap.user("user1").add(password=old_password)
    ldap.password_policy.complexity(enable=True)

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = "True"
    client.sssd.start()

    assert not client.auth.passwd.password(
        "user1", old_password, invalid_password
    ), "Password should not have been able to be changed!"

    assert client.auth.passwd.password("user1", old_password, new_password), "'user1' password change failed!"
    assert not client.auth.ssh.password("user1", old_password), "'user1' shouldn't have been able to log in!"
    assert client.auth.ssh.password("user1", new_password), "'user1' failed to log in!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=[1067476, 1065534])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__user_login_with_whitespace_prefix_in_userid(client: Client, ldap: LDAP):
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
def test_ldap__shadow_policy_user_login_then_changes_password(client: Client, ldap: LDAP, method: str):
    """
    :title: Change password with shadow ldap password policy is set to shadow
    :description: Changing a password when the password policy is managed by the shadowAccount objectclass.
    :setup:
        1. Create user with shadowLastChange = 0, shadowMin = 0, shadowMax = 99999 and shadowWarning = 7
        2. Set "ldap_pwd_policy = shadow" and "ldap_chpass_update_last_change = True"
        3. Start SSSD
    :steps:
        1. Authenticate as "tuser" with old password
        2. Authenticate as "tuser" with new password
    :expectedresults:
        1. The password is expired, and the user is forced to change their password
        2. Authentication with new password was successful
    :customerscenario: True
    """
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


@pytest.mark.ticket(jira="RHEL-55993")
@pytest.mark.importance("critical")
@pytest.mark.parametrize(
    "modify_mode, expected, err_msg",
    [("exop", 3, "Expected login failure"), ("exop_force", 3, "Expected password change request")],
)
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__user_cannot_login_when_no_remaining_grace_logins(
    client: Client, ldap: LDAP, modify_mode: str, expected: int, err_msg: str
):
    """
    :title: Password change when no grace logins left
    :description: Typically the LDAP extended operation to change a password
    requires an authenticated bind, even if the data send with the extended
    operation contains the old password. If the old password is expired and
    there are no grace logins left an authenticated bind is not possible anymore
    and as a result it is not possible for the user to change their password.
    With 'exop' SSSD will not try to ask the user for new credentials while with
    'exop_force' SSSD will ask for new credentials and will try to run the password
    change extended operation.
    :setup:
        1. Set "passwordMaxAge" to "1"
        2. Set "passwordGraceLimit" to "0"
        3. Add a user to LDAP
        4. Wait until the password is expired
        5. Set "ldap_pwmodify_mode"
        6. Start SSSD
    :steps:
        1. Authenticate as the user with 'exop_force' set
        2. Authenticate as the user with 'exop' set
    :expectedresults:
        1. With 'exop_force' expect a request to change the password
        2. With 'exop' expect just a failed login
    :customerscenario: False
    """
    ldap.ldap.modify("cn=config", replace={"passwordMaxAge": "1", "passwordGraceLimit": "0"})
    ldap.user("user1").add(password="Secret123").password_change_at_logon(password="Secret123")

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.start()

    rc, _, _, _ = client.auth.ssh.password_with_output("user1", "Secret123")
    assert rc == expected, err_msg


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__empty_attribute(client: Client, ldap: LDAP):
    """
    :title: SSSD fails to store users if any of the requested attribute is empty
    :setup:
        1. Disable Syntax Checking
        2. Add a User
        3. Make home attribute of user empty
        4. Add Groups
        5. Start SSSD
    :steps:
        1. User exists
        2. Groups are resolved
        3. User should be able to log in
    :expectedresults:
        1. Id look up should success
        2. Group look up should success
        3. User log in should success
    :customerscenario: True
    """
    ldap.ldap.modify("cn=config", replace={"nsslapd-syntaxcheck": "off"})
    user = ldap.user("emp_user").add(password="Secret123")
    user.modify(home="")

    ldap.group("Group_1").add().add_member(member=user)
    ldap.group("Group_2").add().add_member(member=user)

    client.sssd.start()

    assert client.tools.id("emp_user") is not None
    for grp in ["Group_1", "Group_2"]:
        assert client.tools.getent.group(grp) is not None
    assert client.auth.ssh.password(user.name, "Secret123"), "User login failed!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=785908)
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__limit_search_base_group(client: Client, provider: LDAP):
    """
    :title: SSSD limits search base to 'ldap_search_base' DN for groups
    :setup:
        1. Create two ous
        2. Netgroups are created in different ous
        3. Members from different ous are added to netgroup
    :steps:
        1. Lookup netgroup with members from different ous
        2. Set "ldap_search_base" to ou1 in the configuration and cleanly restart SSSD
        3. Lookup netgroup with members from different ous
    :expectedresults:
        1. Netgroup exists and it contains members from both ous
        2. SSSD is configured and cleanly restarted
        3. Netgroup exists and it contains members only from ou1 in ldap_search_base
    :customerscenario: True
    """
    ou1 = provider.ou("OU1").add()
    ou2 = provider.ou("OU2").add()

    ou1_grp1 = provider.netgroup("ou1_grp1", basedn=ou1).add()
    ou1_grp1.add_member(host="h1", user="ou1_usr1", domain="ldap.test")

    ou2_grp1 = provider.netgroup("ou2_grp1", basedn=ou2).add()
    ou2_grp1.add_member(host="h2", user="ou2_usr1", domain="ldap.test")

    ou2_grp2 = provider.netgroup("ou2_grp2", basedn=ou2).add()
    ou2_grp2.add_member(ng=ou2_grp1)

    ou1_grp2 = provider.netgroup("ou1_grp2", basedn=ou1).add()
    ou1_grp2.add_member(ng=ou2_grp2)
    ou1_grp2.add_member(ng=ou1_grp1)

    client.sssd.start()
    result = client.tools.getent.netgroup("ou1_grp2")
    assert result is not None and result.name == "ou1_grp2", "Netgroup ou1_grp2 was not found!"
    assert len(result.members) == 2
    assert "(h1,ou1_usr1,ldap.test)" in result.members, "Member of ou1 'h1, ou1_usr1' is missing from 'ou1_grp2'."
    assert "(h2,ou2_usr1,ldap.test)" in result.members, "Member of ou2 'h2, ou2_usr1' is missing from 'ou1_grp2'."

    client.sssd.dom("test")["ldap_search_base"] = "ou=OU1,dc=ldap,dc=test"
    client.sssd.restart(clean=True)

    result = client.tools.getent.netgroup("ou1_grp2")
    assert result is not None and result.name == "ou1_grp2", "Netgroup ou1_grp2 was not found!"
    assert len(result.members) == 1
    assert "(h1,ou1_usr1,ldap.test)" in result.members, "Member of ou1 'h1, ou1_usr1' is missing from 'ou1_grp2'."
    assert (
        "(h2,ou2_usr1,ldap.test)" not in result.members
    ), "'ou1_grp2' members did not match the expected ones when search base is limited."


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__enumeration_and_group_with_hash_in_name(client: Client, ldap: LDAP):
    """
    :title: getent shows groups with '#' in the name
    :setup:
        1. Create group with # in the name
        2. Create group without # in the name
        3. Enable enumeration
    :steps:
        1. Wait for enumeration to complete
        2. check output of `getent group -s sss`
    :expectedresults:
        1. Enumeration task finishes
        2. Both groups are in the `getent` output
    :customerscenario: False
    """
    group1 = ldap.group("my#group").add()
    group2 = ldap.group("my_group").add()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.domain["enumerate"] = "True"
    client.sssd.domain["ldap_enumeration_refresh_offset"] = "1"
    client.sssd.restart()

    timeout = time.time() + 60
    logfile = "/var/log/sssd/sssd_test.log"
    while True:
        log = client.fs.read(logfile)
        if "[enum_groups_done]" in log:
            break
        assert timeout > time.time(), "Timeout while waiting for enumeration to finish"
        time.sleep(1)
    result = client.host.conn.exec(["getent", "group", "-s", "sss"])

    assert group1.name in result.stdout, f"{group1.name} is not in getent output"
    assert group2.name in result.stdout, f"{group2.name} is not in getent output"


@pytest.mark.ticket(bz=1902280)
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__reset_cached_timestamps_to_reflect_changes(client: Client, ldap: LDAP):
    """
    :title: SSSCTL cache-expire to also reset cached timestamp
    :setup:
        1. Add users and groups to LDAP
        2. Configure and start SSSD
    :steps:
        1. Lookup group
        2. Lookup group after clearing the cache with sssctl
    :expectedresults:
        1. User is found
        2. User is not found
    :customerscenario: True
    """
    u = ldap.user("user1").add()
    ldap.group("group1", rfc2307bis=True).add().add_member(u)

    client.sssd.domain["ldap_schema"] = "rfc2307bis"
    client.sssd.domain["ldap_group_member"] = "member"

    client.sssd.start()

    res = client.tools.getent.group("group1")
    assert res is not None, "Group should exist"
    assert "user1" in res.members, "User should be in group"

    ldap.group("group1", rfc2307bis=True).remove_member(ldap.user("user1"))
    client.sssctl.cache_expire(everything=True)

    res = client.tools.getent.group("group1")
    assert res is not None, "Group should still exist"
    assert "user1" not in res.members, "User should be removed from group"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_override_homedir(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "override_homedir" option
    :description:
        This test checks that the 'override_homedir' option in the [nss]
        section of sssd.conf correctly overrides the home directory for
        all users.
    :setup:
        1. Create three users in LDAP with different homeDirectory attributes.
        2. Configure SSSD with 'override_homedir = /home/B'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify that the home directory for each user is '/home/B'.
    :expectedresults:
        1. All users are found.
        2. Each user's home directory is overridden to '/home/B'.
    :customerscenario: True
    """
    ldap.user("user_with_homedir_A").add(home="/home/A")
    ldap.user("user_with_homedir_B").add(home="/home/B")
    ldap.user("user_with_empty_homedir").add(home="")

    client.sssd.nss["override_homedir"] = "/home/B"
    client.sssd.start()

    for user in ["user_with_homedir_A", "user_with_homedir_B", "user_with_empty_homedir"]:
        result = client.tools.getent.passwd(user)
        assert result is not None, f"User '{user}' not found"
        assert result.home == "/home/B", f"User '{user}' has incorrect home directory"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_fallback_homedir(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "fallback_homedir" option
    :description:
        This test checks that the 'fallback_homedir' option in the [nss]
        section of sssd.conf provides a home directory only when the user
        entry in LDAP does not have one.
    :setup:
        1. Create three users in LDAP: one with a home directory, one with
           another home directory, and one with an empty home directory.
        2. Configure SSSD with 'fallback_homedir = /home/B'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify home directories.
    :expectedresults:
        1. All users are found.
        2. The user with a non-empty home directory keeps it.
        3. The user with an empty home directory gets the fallback.
    :customerscenario: True
    """
    ldap.user("user_with_homedir_A").add(home="/home/A")
    ldap.user("user_with_homedir_B").add(home="/home/B")
    ldap.user("user_with_empty_homedir").add(home="")

    client.sssd.nss["fallback_homedir"] = "/home/B"
    client.sssd.start()

    user_a = client.tools.getent.passwd("user_with_homedir_A")
    assert user_a is not None and user_a.home == "/home/A"

    user_b = client.tools.getent.passwd("user_with_homedir_B")
    assert user_b is not None and user_b.home == "/home/B"

    user_empty = client.tools.getent.passwd("user_with_empty_homedir")
    assert user_empty is not None and user_empty.home == "/home/B"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_override_shell(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "override_shell" option
    :description:
        This test checks that the 'override_shell' option in the [nss]
        section of sssd.conf correctly overrides the login shell for
        all users.
    :setup:
        1. Create three users in LDAP with different loginShell attributes.
        2. Configure SSSD with 'override_shell = /bin/B'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify that the login shell for each user is '/bin/B'.
    :expectedresults:
        1. All users are found.
        2. Each user's login shell is overridden to '/bin/B'.
    :customerscenario: True
    """
    ldap.user("user_with_shell_A").add(shell="/bin/A")
    ldap.user("user_with_shell_B").add(shell="/bin/B")
    ldap.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["override_shell"] = "/bin/B"
    client.sssd.start()

    for user in ["user_with_shell_A", "user_with_shell_B", "user_with_empty_shell"]:
        result = client.tools.getent.passwd(user)
        assert result is not None, f"User '{user}' not found"
        assert result.shell == "/bin/B", f"User '{user}' has incorrect shell"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_shell_fallback(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "shell_fallback" option
    :description:
        This test checks that the 'shell_fallback' option in the [nss]
        section of sssd.conf provides a shell for users whose shell is
        not in /etc/shells.
    :setup:
        1. Create users in LDAP with different shells. One valid, one invalid,
           one empty.
        2. Configure SSSD with 'shell_fallback' and 'allowed_shells'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with a valid shell keeps it.
        2. User with an invalid shell gets the fallback shell.
        3. User with an empty shell has the default shell for the system.
    :customerscenario: True
    """
    ldap.user("user_with_sh_shell").add(shell="/bin/sh")
    ldap.user("user_with_not_installed_shell").add(shell="/bin/not_installed")
    ldap.user("user_with_empty_shell").add(shell="")

    # /bin/sh should be in /etc/shells by default in the container.
    # /bin/not_installed should not be.
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.nss["allowed_shells"] = "/bin/not_installed"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_not_installed = client.tools.getent.passwd("user_with_not_installed_shell")
    assert user_not_installed is not None and user_not_installed.shell == "/bin/fallback"

    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    # LDAP provider returns /bin/bash for empty shell by default
    assert user_empty is not None and user_empty.shell == "/bin/bash"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_default_shell(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "default_shell" option
    :description:
        This test checks that the 'default_shell' option in the [nss]
        section of sssd.conf provides a shell for users who don't have
        one defined in LDAP.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'default_shell', 'allowed_shells', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with valid shell keeps it.
        2. User with invalid shell gets fallback.
        3. User with empty shell gets default shell.
    :customerscenario: True
    """
    ldap.user("user_with_sh_shell").add(shell="/bin/sh")
    ldap.user("user_with_not_installed_shell").add(shell="/bin/not_installed")
    ldap.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["allowed_shells"] = "/bin/default, /bin/not_installed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_not_installed = client.tools.getent.passwd("user_with_not_installed_shell")
    assert user_not_installed is not None and user_not_installed.shell == "/bin/fallback"

    ## TODO: fix
    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    assert user_empty is not None and user_empty.shell == "/bin/default"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_vetoed_shells(client: Client, ldap: LDAP):
    """
    :title: Test the effect of the "vetoed_shells" option
    :description:
        This test checks that the 'vetoed_shells' option in the [nss]
        section of sssd.conf prevents users from having a shell from the
        vetoed list.
    :setup:
        1. Create users in LDAP with different shells.
        2. Configure SSSD with 'vetoed_shells', 'default_shell', and
           'shell_fallback'.
        3. Start SSSD.
    :steps:
        1. Look up each user.
        2. Verify their shells.
    :expectedresults:
        1. User with a valid, non-vetoed shell keeps it.
        2. User with a vetoed shell gets the fallback shell.
        3. User with an empty shell gets the default shell.
    :customerscenario: True
    """
    ldap.user("user_with_sh_shell").add(shell="/bin/sh")
    ldap.user("user_with_vetoed_shell").add(shell="/bin/vetoed")
    ldap.user("user_with_empty_shell").add(shell="")

    client.sssd.nss["default_shell"] = "/bin/default"
    client.sssd.nss["vetoed_shells"] = "/bin/vetoed"
    client.sssd.nss["shell_fallback"] = "/bin/fallback"
    client.sssd.start()

    user_sh = client.tools.getent.passwd("user_with_sh_shell")
    assert user_sh is not None and user_sh.shell == "/bin/sh"

    user_vetoed = client.tools.getent.passwd("user_with_vetoed_shell")
    assert user_vetoed is not None and user_vetoed.shell == "/bin/fallback"

    user_empty = client.tools.getent.passwd("user_with_empty_shell")
    assert user_empty is not None and user_empty.shell == "/bin/default"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_filters(client: Client, ldap: LDAP):
    """
    :title: Test filtering of users and groups with 'filter_users' and 'filter_groups'
    :description:
        This test verifies that users and groups can be filtered out from NSS
        lookups using the 'filter_users' and 'filter_groups' options.
    :setup:
        1. Create several users and groups in LDAP, including nested groups.
        2. Configure SSSD with 'filter_users' and 'filter_groups'.
        3. Start SSSD.
    :steps:
        1. Attempt to look up non-filtered users and groups.
        2. Attempt to look up filtered users and groups.
        3. Check group memberships to ensure filtered users are excluded.
        4. Check a user's group list to ensure filtered groups are excluded.
    :expectedresults:
        1. Non-filtered users and groups are found.
        2. Filtered users and groups are not found.
        3. Group memberships do not include filtered users.
        4. A user's group list does not include filtered groups.
    :customerscenario: True
    """
    # Create users
    user1 = ldap.user("user1").add(uid=1001, gid=2001)
    user2 = ldap.user("user2").add(uid=1002, gid=2002)
    ldap.user("user3").add(uid=1003, gid=2003)

    # Create groups
    ldap.group("group1", rfc2307bis=True).add(gid=2001)
    ldap.group("group2", rfc2307bis=True).add(gid=2002)
    ldap.group("group3", rfc2307bis=True).add(gid=2003)
    empty_group1 = ldap.group("empty_group1", rfc2307bis=True).add(gid=2010)
    empty_group2 = ldap.group("empty_group2", rfc2307bis=True).add(gid=2011)
    two_user_group = ldap.group("two_user_group", rfc2307bis=True).add(gid=2012)
    two_user_group.add_member(user1)
    two_user_group.add_member(user2)
    ldap.group("group_empty_group", rfc2307bis=True).add(gid=2013).add_member(empty_group1)
    ldap.group("group_two_empty_groups", rfc2307bis=True).add(gid=2014).add_member(empty_group1).add_member(
        empty_group2
    )
    one_user_group1 = ldap.group("one_user_group1", rfc2307bis=True).add(gid=2015).add_member(user1)
    one_user_group2 = ldap.group("one_user_group2", rfc2307bis=True).add(gid=2016).add_member(user2)
    ldap.group("group_one_user_group", rfc2307bis=True).add(gid=2017).add_member(one_user_group1)
    ldap.group("group_two_user_group", rfc2307bis=True).add(gid=2018).add_member(two_user_group)
    ldap.group("group_two_one_user_groups", rfc2307bis=True).add(gid=2019).add_member(
        one_user_group1
    ).add_member(one_user_group2)

    client.sssd.domain["ldap_schema"] = "rfc2307bis"
    client.sssd.nss["filter_users"] = "user2"
    client.sssd.nss["filter_groups"] = "group_two_one_user_groups"
    client.sssd.start()

    # Test users
    assert client.tools.id("user1") is not None
    assert client.tools.id("user3") is not None
    assert client.tools.id("user2") is None
    assert client.tools.getent.passwd(1002) is None

    # Test groups
    assert client.tools.getent.group("group1") is not None
    assert client.tools.getent.group("group_two_one_user_groups") is None
    assert client.tools.getent.group(2019) is None

    # Test group membership of filtered user
    two_user_group_ent = client.tools.getent.group("two_user_group")
    assert "user1" in two_user_group_ent.members
    assert "user2" not in two_user_group_ent.members

    # Test initgroups of filtered group
    user1 = client.tools.id("user1")
    user1_gids = [group.id for group in user1.groups]
    expected_gids = [2001, 2012, 2015, 2017, 2018]
    assert sorted(user1_gids) == sorted(expected_gids)


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__nss_filters_cached(client: Client, ldap: LDAP):
    """
    :title: Test caching of filtered users and groups
    :description:
        This test verifies that filtered users and groups are negatively
        cached and that root user/group are always filtered.
    :setup:
        1. Create users and groups in LDAP, including a user named 'root'
           and another with UID 0.
        2. Configure SSSD with 'filter_users', 'filter_groups', and a short
           'entry_negative_timeout'.
        3. Start SSSD.
    :steps:
        1. Look up a non-filtered user to confirm it is found.
        2. Look up a filtered user and group; they should not be found.
        3. Wait for the negative cache to expire and look them up again.
        4. Check that 'root' user and group (both by name and ID 0) are not
           found through SSSD, even if they exist in LDAP.
    :expectedresults:
        1. Non-filtered user is found.
        2. Filtered entries are not found and are negatively cached.
        3. After timeout, filtered entries are still not found.
        4. Root user and group are always filtered.
    :customerscenario: True
    """
    # Create users
    ldap.user("user1").add(uid=1001, gid=2001)
    ldap.user("user2").add(uid=1002, gid=2002)  # filtered
    ldap.user("user3").add(uid=1003, gid=2003)
    ldap.user("root").add(uid=1004, gid=2004)  # should be filtered
    ldap.user("zerouid").add(uid=0, gid=0)  # should be filtered

    # Create groups
    ldap.group("group1").add(gid=2001)
    ldap.group("group2").add(gid=2002)  # filtered
    ldap.group("group3").add(gid=2003)
    ldap.group("root").add(gid=2004)  # should be filtered
    ldap.group("zerogid").add(gid=0)  # should be filtered

    client.sssd.nss["filter_users"] = "user2"
    client.sssd.nss["filter_groups"] = "group2"
    client.sssd.nss["entry_negative_timeout"] = 2
    client.sssd.start()

    assert client.tools.id("user1") is not None
    assert client.tools.id("user3") is not None

    # Test filtered user and caching
    assert client.tools.id("user2") is None
    time.sleep(3)
    assert client.tools.id("user2") is None

    # Test filtered group and caching
    assert client.tools.getent.group("group2") is None
    time.sleep(3)
    assert client.tools.getent.group("group2") is None

    # Test root is always filtered
    getent_sss = ["getent", "-s", "sss"]
    res = client.host.conn.exec(getent_sss + ["passwd", "root"])
    assert res.return_code != 0

    res = client.host.conn.exec(getent_sss + ["group", "root"])
    assert res.return_code != 0

    res = client.host.conn.exec(getent_sss + ["passwd", "0"])
    assert res.return_code != 0

    res = client.host.conn.exec(getent_sss + ["group", "0"])
    assert res.return_code != 0

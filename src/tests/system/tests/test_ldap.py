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


"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move
->> duplicate test, test_ldap.py::rfc2307bis, test_**::generic

notes
=====
* generic provider covers rfc2307 tests and are rfc2307bis tests are cloned here
* parametrized SSL and StartTLS
* parameterize getent.passwd[name, uid]:


bash
====
# ldap_deref
?:Set deref to never
?:Set deref to always
?:Set deref to finding
?:Set deref to searching
?:Points to a different common name
?:Deref object does not exist
?:Deref objects in closed cycle
?:auth with deref object
?:Without deref in sssd conf should default to never

# ldap_id_ldap_auth
?:Raise limits for max num of files sssd nss or sssd pam can use bz799929
?:netgroups do not honor entry cache nowait percentage bz822236
?:Honour TTL when resolving host names bz785884
?:Crash with netgroup lookup after cache lifetime bz682807
?:id command shows recently deleted users bz678410 bz894381
?:debug timestamps equals to 1 is not passed to providers bz785909
?:client idle timeout set to 30 bz827036
?:Warn to syslog when dereference requests fail bz799009
?:sss debuglevel help should not list debug bz799039
?:SSSD will sometimes lose groups from the cache bz649286
?:getent passwd username returns nothing if its uidNumber gt 2147483647 bz645449
?:sssd be crashes when resolving non trivial nested group structure bz801533
?:SSSD starts multiple processes due to syntax error in ldap uri bz869466
?:Verify when nesting limit is reached bz790848 bz894997
?:SSSD fails to store users if any of the requested attribute is empty bz842842
?:Verifying ldb
?:Get Valid LDAP Users
?:Get Valid LDAP Groups
?:Users uidNumbers below Minimum and above Maximum
?:Groups gidNumbers below Minimum and above Maximum
?:Enumerating Non Posix User
?:Enumerating Non Posix Group
?:Authentication LDAP User with Password Assigned
?:Change LDAP Users Password and Authenticate
?:Authentication LDAP User Without Password Assigned
?:Authentication LDAP User with Incorrect Password
?:Get Valid LDAP Users Fully Qualified Names
?:Get Valid LDAP Groups Fully Qualified Names
?:LDAP User uidNumber not Within Allowed Range
?:Group gidNumber not Within Allowed Range
?:New LDAP User Added Cache Test
?:New LDAP Group Added Negative Cache Test
?:Authentication fully qualified LDAP User with Password Assigned
?:Change Password and Authenticate LDAP user with FQDN
?:Get Valid LDAP Users LDAPS
?:Get valid LDAP Groups LDAPS
?:Authentication LDAP User with Passwd Assigned Require Cert Never
?:Get Valid LDAP Users Require Cert Hard
?:Get Valid LDAP Groups Require Cert Hard
?:Authentication LDAP User with Password Assigned Require Cert Hard
?:Get Valid LDAP Users Bind DN
?:Get Valid LDAP Groups Bind DN
?:LDAP BE Unreachable
?:id Command and Group Memberships
?:Verify Groups and Users same OU
?:Case Sensitive Group Memberships
?:Change LDAP Domain User Passwd default chpass provider
?:Wrapping the value for ldap access filter in parentheses causes ldap search ext to fail bz600352
?:Multiple entries of ldap access filter and lower one wins
?:ldap access filter with a global character
?:ldap access filter with memberOf option
?:ldap access filter with long version of memberOf option
?:Multiple entries of ldap search file and lower one wins offline
?:ldap access filter with a global character offline -> test_access_filter.py
?:ldap access filter with memberOf option offline -> test_access_filter.py
?:ldap access filter with long version of memberOf option offline
?:ldap access allow attribute in cache LDAP ldb
?:SSSD segfaults when c ares is using tcp scokets
?:Authentication succeeds if user is in whitelist
?:Authentication fails if the user is not in whitelist
?:getent returns both users
?:Authentication succeeds and connection closes if user is in blacklist
?:Authentication succeeds if the user is not in blacklist
?:sssd with ldap backend throws error domain log bz1227685
?:SSSD ldap ldap rfc2307 test trac 622 625
?:SSSD ldap ldap rfc2307bis test trac 595 620 621 626
?:Create a ou set to netgroup and nisNetgroupTriple
?:Decrease the cache time out and add new entry for nisNetgroupTriple
?:Create multiple netgroups
?:Adding memberNisNetgroup
?:Adding dn to memberNisNetgroup
?:Using different syntax for nisNetgroupTriple
?:With just host and domain info
?:netgroups with nested loop
?:ldapsearch base specified in sssd conf
?:Without ldapsearch base specified in sssd conf and rootDSE exists
?:Without ldapsearch base and with ldap user search base specified
?:Without ldapsearch base and with ldap group search base specified
?:Without ldapsearch base and with ldap netgroup search base specified
?:Without ldapsearch base and multiple namingContexts and 1 defaultnamingcontext
?:With ldapsearch base and with ldap user search base specified
?:With ldapsearch base and with ldap user search base specified multi namingContexts

# paging
?:Set maxpagesize equals to 10 on ldapserver
?:Enumerate users with maxpagesize 10 in ldap server and ldap page size 10 in sssd
?:Enumerate groups with maxpagesize 10 in ldap server and ldap page size 10 in sssd
?:paging plus filter
?:Enumerate user in 20 groups with enumerate false
?:Enumerate user in 20 groups with enumerate false and totalpageentries 5 in ldap server
?:Enumerate false and totalpageentries 5 in ldap server and ldap page size 5 in sssd
?:Primary group of user is not enumerated when prtotal set to 5
?:Set paging disabled on ldapserver bz728212
?:Page size unlimited on ldap server and ldap disable paging is false in sssd
?:Page size unlimited on ldap server and ldap disable paging is true in sssd
?:LDAP server page size is 10 sssd page size is 5 and ldap disable paging is false
?:LDAP server page size is 10 sssd page size is 20 and ldap disable paging is false
?:LDAP server page size is 10 sssd page size is 5 and ldap disable paging is true
?:LDAP server page size disabled and sssd ldap disable paging is true
?:LDAP server page size disabled sssd page size 10 and ldap disable paging is false
?:LDAP server page size is 10 and sssd ldap disable paging is true


intg tests
==========
+:test_regression_ticket2163:'\\' character is permitted -> test_authentication.py
-:test_sanity_rfc2307
-:test_sanity_rfc2307_bis
+:test_member_with_different_cases_rfc2307_bis::bz1817122 ->> test_identity.py
+:test_refresh_after_cleanup_task::sssd.conf,entry_cache_timeout -> test_cache.py
+:test_update_ts_cache_after_cleanup_task::sssd.conf,ldap_purge_cache_timeout -> test_cache.py
-:test_ldap_group_dereference
p:test_override_homedir::test_authentication.py
+:test_fallback_homedir -> test_authentication.py
+:test_override_shell -> test_authentication.py
+:test_shell_fallback -> test_authentication.py
+:test_default_shell -> test_authentication.py
+:test_vetoed_shells -> test_authentication.py
+:test_user_2307bis_nested_groups -> test_identity.py
+:test_special_characters_in_names -> test_authentication.py
-:test_extra_attribute_already_exists::vetoed shells
p:test_add_user_to_group::test_identity__lookup_groups_by_name_and_gid_with_getent
+:test_remove_user_from_group -> test_cache.py
+:test_remove_user_from_nested_group -> test_cache.py
+:test_zero_nesting_level -> test_identity.py
+:test_nss_filters -> test_nss.py
+:test_nss_filters_cached -> test_nss.py
p:test_ldap_auto_private_groups_direct::test_identity__lookup_when_auto_private_groups_is_set_to_true
p:test_ldap_auto_private_groups_conflict::test_identity__lookup_when_auto_private_groups_is_set_to_true
p:test_ldap_auto_private_groups_direct_no_gid::test_identity__lookup_when_auto_private_groups_is_set_to_true
p:test_ldap_auto_private_groups_hybrid_direct::test_identity__lookup_when_auto_private_groups_is_set_to_hybrid
p:test_ldap_auto_private_groups_hybrid_priv_group_byname::test_identity__lookup_when_auto_private_groups_is_set_to_hybrid
p:test_ldap_auto_private_groups_hybrid_priv_group_byid::test_identity__lookup_when_auto_private_groups_is_set_to_hybrid
p:test_ldap_auto_private_groups_hybrid_name_gid_identical::test_identity__lookup_when_auto_private_groups_is_set_to_hybrid
p:test_ldap_auto_private_groups_hybrid_initgr::gh2914
+:test_rename_incomplete_group_same_dn -> test_cache.py, rename group by modifying the name
+:test_rename_incomplete_group_rdn_changed -> test_cache.py, rename group by the cn
+:test_local_negative_timeout_enabled_by_default -> test_cache.py, local_negative_timeout value
+:test_local_negative_timeout_disabled -> test_cache.py, local_negative_timeout value = 0
p:test_lookup_by_email::test_authentication__using_the_users_email_address
+:test_conflicting_mail_addresses_and_fqdn::email == fqn :: gh4630
+:test_conflicting_mail_addresses::lookup email owned by two accounts, negative

multihost
=========
# test_ldap_extra_attrs.py
?:test_0001_bz1362023
?:test_0002_givenmail
?:test_0003_checkldb
?:test_0004_negativecache
?:test_0005_ldapextraattrs
?:test_0006_bz1667252
?:test_bz847043

# test_ldap_library_debug_level.py
?:test_ldap_library_debug_level.py:?:test_0001_bz1884207
?:test_ldap_library_debug_level.py:?:test_0002_bz1884207
?:test_ldap_library_debug_level.py:?:test_0003_bz1884207

# test_ldap_password_policy.py
?:test_bz748856
?:test_maxage
?:test_bz954323
?:test_bz1146198_bz1144011

# test_ldap_time_logging.py
?:test_0001_bz1925559
?:test_0002_bz1925559
?:test_0003_bz1925559
"""


@pytest.mark.ticket(bz=[795044, 1695574])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
@pytest.mark.builtwith("ldap_use_ppolicy")
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

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.domain["ldap_use_ppolicy"] = use_ppolicy
    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.ssh.password(user, old_pass), "Login with old password failed!"

    assert client.auth.passwd.password(user, old_pass, new_pass), "Password change failed!"

    assert client.auth.ssh.password(user, new_pass), "User login failed!"
    assert not client.auth.ssh.password(user, old_pass), "Login with old password passed!"


@pytest.mark.ticket(bz=[795044, 1695574])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.builtwith("ldap_use_ppolicy")
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
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.builtwith("ldap_use_ppolicy")
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

    match = client.journald.is_match(r"pam_sss\(passwd:chauthtok\): User info message: Password change failed.")
    assert match, "'Password change failed.' message is not in log!"


@pytest.mark.ticket(bz=[1695574, 1795220])
@pytest.mark.importance("critical")
@pytest.mark.parametrize("modify_mode", ["exop", "ldap_modify", "exop_force"])
@pytest.mark.parametrize("use_ppolicy", ["true", "false"])
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.builtwith("ldap_use_ppolicy")
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


@pytest.mark.ticket(jira="RHEL-55993")
@pytest.mark.importance("critical")
@pytest.mark.parametrize(
    "modify_mode, expected, err_msg",
    [("exop", 1, "Expected login failure"), ("exop_force", 3, "Expected password change request")],
)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__password_change_no_grace_logins_left(
    client: Client, ldap: LDAP, modify_mode: str, expected: int, err_msg: str, method: str
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
        1. Set "passwordExp" to "on"
        2. Set "passwordMaxAge" to "1"
        3. Set "passwordGraceLimit" to "0"
        4. Add a user to LDAP
        5. Wait until the password is expired
        6. Set "ldap_pwmodify_mode"
        7. Start SSSD
    :steps:
        1. Authenticate as the user with 'exop_force' set
        2. Authenticate as the user with 'exop' set
    :expectedresults:
        1. With 'exop_force' expect a request to change the password
        2. With 'exop' expect just a failed login
    :customerscenario: False
    """
    ldap.ldap.modify("cn=config", replace={"passwordExp": "on", "passwordMaxAge": "1", "passwordGraceLimit": "0"})
    ldap.user("user1").add(password="Secret123")

    # make sure the password is expired
    time.sleep(3)

    client.sssd.domain["ldap_pwmodify_mode"] = modify_mode
    client.sssd.start()

    rc, _, _, _ = client.auth.parametrize(method).password_with_output("user1", "Secret123")
    assert rc == expected, err_msg

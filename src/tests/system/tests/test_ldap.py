"""
SSSD LDAP provider tests

:requirement: IDM-SSSD-REQ : LDAP Provider
"""

from __future__ import annotations

import time
import types
from contextlib import contextmanager, nullcontext
from typing import Generator

import ldap as pyldap
import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@contextmanager
def _extra_naming_context(
    ldap: LDAP, suffix: str = "dc=other,dc=test", be_name: str = "otherRoot"
) -> Generator[str, None, None]:
    """
    Create an extra 389-ds naming context for the duration of the block.

    Prefers :meth:`LDAP.extra_naming_context` from sssd-test-framework when
    available; otherwise falls back to ``dsconf backend create`` so multi-NC
    coverage works before that helper is released.
    """
    if hasattr(ldap, "extra_naming_context"):
        with ldap.extra_naming_context(suffix=suffix, be_name=be_name) as extra:
            yield extra
        return

    binddn = ldap.host.binddn
    bindpw = ldap.host.bindpw
    bind = f'-D "{binddn}" -w "{bindpw}"'
    mapping_dn = f'cn="{suffix}",cn=mapping tree,cn=config'
    backend_dn = f"cn={be_name},cn=ldbm database,cn=plugins,cn=config"

    def _dsconf(*args: str, raise_on_error: bool = True, json: bool = False):
        jflag = "-j " if json else ""
        cmd = f'dsconf {jflag}-D "{binddn}" -w "{bindpw}" ldap://localhost ' + " ".join(args)
        return ldap.host.conn.run(cmd, raise_on_error=raise_on_error)

    def _cleanup() -> None:
        ldap.host.conn.run(
            f"ldapdelete -x {bind} -H ldap://localhost -r '{suffix}' || true\n"
            f"ldapdelete -x {bind} -H ldap://localhost '{mapping_dn}' || true\n"
            f"ldapdelete -x {bind} -H ldap://localhost '{backend_dn}' || true\n",
            raise_on_error=False,
        )
        _dsconf("backend", "delete", f'"{be_name}"', "--do-it", json=True, raise_on_error=False)
        _dsconf("mappingtree", "delete", f'"{suffix}"', raise_on_error=False)

    # Stock LDAPUtils.dn() appends naming_context to every basedn string, which
    # breaks absolute DNs under the extra suffix. Patch for the duration.
    utils = ldap.ldap
    original_dn = utils.dn

    def _dn(self, rdn: str, basedn: str | None = None) -> str:
        if not basedn:
            return f"{rdn},{self.naming_context}"
        naming_contexts = {self.naming_context, suffix}
        if basedn in naming_contexts or any(
            basedn == nc or basedn.endswith(f",{nc}") for nc in naming_contexts
        ):
            return f"{rdn},{basedn}"
        return f"{rdn},{basedn},{self.naming_context}"

    _cleanup()
    _dsconf("backend", "create", f'--suffix "{suffix}"', f'--be-name "{be_name}"', "--create-suffix")
    aci = (
        '(targetattr=*)(version 3.0; acl "Enable anyone read"; '
        'allow (read, search, compare)(userdn="ldap:///anyone");)'
    )
    try:
        utils.modify(suffix, add={"aci": aci})
    except pyldap.TYPE_OR_VALUE_EXISTS:
        pass

    utils.dn = types.MethodType(_dn, utils)
    try:
        yield suffix
    finally:
        utils.dn = original_dn
        _cleanup()


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
    client.sssd.clear(logs=True)
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


def _ldap_ous_under(ldap: LDAP, base: str | None):
    """Create People/Groups/Netgroups OUs under ``base``, or the default NC when ``base`` is None."""
    kwargs = {"basedn": base} if base is not None else {}
    return (
        ldap.ou("People", **kwargs).add(),
        ldap.ou("Groups", **kwargs).add(),
        ldap.ou("Netgroups", **kwargs).add(),
    )


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("use_extra_nc", [False, True], ids=["default-nc", "extra-nc"])
def test_ldap__lookup_user_with_search_bases(client: Client, ldap: LDAP, use_extra_nc: bool):
    """
    :title: Looking up users, groups, and netgroups with only ldap_search_base (or rootDSE discovery)
    :setup:
        1. Optionally create an extra naming context
        2. Create People/Groups/Netgroups OUs and objects under the chosen NC
        3. For the extra NC, set ldap_search_base only; otherwise leave search bases unset
        4. Start SSSD
    :steps:
        1. Look up user, group, and netgroup
        2. For the default NC, check rootDSE discovery logs
    :expectedresults:
        1. User, group, and netgroup are found
        2. Default NC logs show rootDSE-based search base discovery
    :customerscenario: False
    """
    ctx = _extra_naming_context(ldap) if use_extra_nc else nullcontext(None)
    with ctx as base:
        ou_users, ou_groups, ou_netgroups = _ldap_ous_under(ldap, base)
        nc = base or ldap.ldap.naming_context

        user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")
        ldap.group("pgroup1", basedn=ou_groups).add(gid=10001)
        ldap.netgroup("pnetgroup1", basedn=ou_netgroups).add()

        if use_extra_nc:
            # Multi-NC: discovery cannot pick a single NC, so set ldap_search_base alone.
            client.sssd.dom("test")["ldap_search_base"] = nc

        client.sssd.start()

        passwd = client.tools.getent.passwd(user.name)
        assert passwd is not None, "User not found!"
        assert passwd.name == user.name, "Username is not correct!"

        group = client.tools.getent.group("pgroup1")
        assert group is not None, "Group not found!"
        assert group.name == "pgroup1"

        netgroup = client.tools.getent.netgroup("pnetgroup1")
        assert netgroup is not None, "Netgroup not found!"

        if not use_extra_nc:
            time.sleep(3)
            log = client.fs.read(client.sssd.logs.domain())
            assert "Got rootdse" in log, "Unable to find rootDSE!"
            assert "Using value from [defaultNamingContext] as naming context" in log, (
                "Unable to find naming context!"
            )
            assert f"Setting option [ldap_search_base] to [{nc}]" in log, "Unable to set ldap_search_base!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("use_extra_nc", [False, True], ids=["default-nc", "extra-nc"])
def test_ldap__lookup_and_authenticate_as_user_with_different_object_search_bases(
    client: Client, ldap: LDAP, use_extra_nc: bool
):
    """
    :title: Explicit per-object search bases resolve users, groups, netgroups, and authentication
    :setup:
        1. Optionally create an extra naming context
        2. Create OUs for users, groups, and netgroups under the chosen NC
        3. Configure ldap_search_base plus ldap_user/group/netgroup_search_base and start SSSD
    :steps:
        1. Look up user by name
        2. Look up group by name
        3. Look up netgroup by name
        4. Authenticate as user
    :expectedresults:
        1. User is found with correct name
        2. Group is found with correct name
        3. Netgroup is found
        4. Authentication succeeds
    :customerscenario: False
    """
    ctx = _extra_naming_context(ldap) if use_extra_nc else nullcontext(None)
    with ctx as base:
        ou_users, ou_groups, ou_netgroups = _ldap_ous_under(ldap, base)
        nc = base or ldap.ldap.naming_context

        user = ldap.user("puser1", basedn=ou_users).add(uid=10001, gid=10001, password="Secret123")
        ldap.group("pgroup1", basedn=ou_groups).add(gid=10001)
        ldap.netgroup("pnetgroup1", basedn=ou_netgroups).add()

        # Default NC keeps the original "ldap_search_base differs from object bases"
        # coverage; extra NC mirrors the bash multi-NC success path with all bases set.
        client.sssd.dom("test")["ldap_search_base"] = nc if use_extra_nc else "dc=shanks,dc=com"
        client.sssd.dom("test")["ldap_user_search_base"] = f"ou=People,{nc}"
        client.sssd.dom("test")["ldap_group_search_base"] = f"ou=Groups,{nc}"
        client.sssd.dom("test")["ldap_netgroup_search_base"] = f"ou=Netgroups,{nc}"

        client.sssd.start()

        passwd = client.tools.getent.passwd(user.name)
        assert passwd is not None, "User is not found!"
        assert passwd.name == user.name, "Username is not correct!"

        group = client.tools.getent.group("pgroup1")
        assert group is not None, "Group is not found!"
        assert group.name == "pgroup1"

        netgroup = client.tools.getent.netgroup("pnetgroup1")
        assert netgroup is not None, "Netgroup is not found!"

        assert client.auth.ssh.password(user.name, "Secret123"), "User login failed!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__partial_search_base_config_fails_gracefully_for_missing_subtrees(client: Client, ldap: LDAP):
    """
    :title: Partial ldap_user_search_base config fails other lookups under multiple NCs
    :setup:
        1. Configure LDAP server with multiple naming contexts
        2. Create users/groups/netgroups/services under a chosen NC
        3. Configure SSSD with only ldap_user_search_base (no ldap_search_base)
        4. Start SSSD
    :steps:
        1. With only ldap_user_search_base set, look up user, group, netgroup, and service; run id
        2. Check domain log for missing-search-base warnings
        3. Reconfigure with only group/netgroup/service bases and look up user and other objects
    :expectedresults:
        1. User lookup and authentication succeed; group/netgroup/service lookups fail
        2. Log contains group/netgroup/services/initgroups without-search-base messages
        3. User lookup fails with log warning; group/netgroup/service lookups succeed
    :customerscenario: False
    """
    with _extra_naming_context(ldap) as extra:
        ou_users = ldap.ou("Users", basedn=extra).add()
        ou_groups = ldap.ou("Groups", basedn=extra).add()
        ou_netgroups = ldap.ou("Netgroups", basedn=extra).add()
        ou_services = ldap.ou("Services", basedn=extra).add()

        user = ldap.user("nctest1", basedn=ou_users).add(uid=12300, gid=12300, password="Secret123")
        ldap.group("nctest1_grp1", basedn=ou_groups).add(gid=12300)
        ldap.netgroup("nctest1_netgroup1", basedn=ou_netgroups).add()
        ldap.services("nctest1_service1", basedn=ou_services).add(port=12304, protocol="tcp")

        client.sssd.dom("test")["debug_level"] = "0xFFF0"
        client.sssd.dom("test")["ldap_user_search_base"] = f"ou=Users,{extra}"
        client.sssd.start()

        passwd = client.tools.getent.passwd(user.name)
        assert passwd is not None, "User lookup should succeed when ldap_user_search_base is set!"
        assert passwd.name == "nctest1"

        group = client.tools.getent.group("nctest1_grp1")
        assert group is None, "Group lookup should fail when ldap_group_search_base is not set!"

        assert client.tools.id(user.name) is not None, "id lookup should still return the user!"

        netgroup = client.tools.getent.netgroup("nctest1_netgroup1")
        assert netgroup is None, "Netgroup lookup should fail when ldap_netgroup_search_base is not set!"

        service = client.tools.getent.services("nctest1_service1", service="sss")
        assert service is None, "Service lookup should fail when ldap_service_search_base is not set!"

        assert client.auth.ssh.password(user.name, "Secret123"), "Authentication failed!"

        log = client.fs.read(client.sssd.logs.domain())
        assert "Group lookup request without a search base" in log
        assert "Initgroups lookup request without a group search base" in log
        assert "Netgroup lookup request without a netgroup search base" in log
        assert "Services lookup request without a search base" in log

        client.sssd.stop()
        client.sssd.clear(logs=True)
        domain = client.sssd.dom("test")
        domain["debug_level"] = "0xFFF0"
        if "ldap_user_search_base" in domain:
            del domain["ldap_user_search_base"]
        domain["ldap_group_search_base"] = f"ou=Groups,{extra}"
        domain["ldap_netgroup_search_base"] = f"ou=Netgroups,{extra}"
        domain["ldap_service_search_base"] = f"ou=Services,{extra}"
        client.sssd.start()

        passwd = client.tools.getent.passwd(user.name)
        assert passwd is None, "User lookup should fail when ldap_user_search_base is not set!"

        group = client.tools.getent.group("nctest1_grp1")
        assert group is not None, "Group lookup should succeed when ldap_group_search_base is set!"

        netgroup = client.tools.getent.netgroup("nctest1_netgroup1")
        assert netgroup is not None, "Netgroup lookup should succeed when ldap_netgroup_search_base is set!"

        service = client.tools.getent.services("nctest1_service1", service="sss")
        assert service is not None, "Service lookup should succeed when ldap_service_search_base is set!"

        log = client.fs.read(client.sssd.logs.domain())
        assert "User lookup request without a search base" in log


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


@pytest.mark.parametrize(
    ("ip_addresses", "aliases"),
    [
        (["192.168.1.1"], []),
        (["192.168.1.1", "192.168.1.2"], ["host1", "host2"]),
        (["2001:db8:1::1", "2001:db8:1::2"], ["host1.ldap.test", "host2.ldap.test"]),
    ],
)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_hosts(client: Client, ldap: LDAP, ip_addresses, aliases):
    """
    :title: Resolver provider lookup hosts
    :setup:
        1. Create hosts and host aliases
        2. Start SSSD
    :steps:
        1. Lookup host and check for IP addresses
        2. Lookup host and check for aliases
    :expectedresults:
        1. All IP addresses found
        2. All aliases found
    :customerscenario: False
    """
    ldap.hosts("host0").add(ip_address=ip_addresses, aliases=aliases)
    client.sssd.start()

    result = client.tools.getent.hosts("host0", service="sss")
    if result is not None and result.ip is not None:
        for ip in ip_addresses:
            assert ip in result.ip, f"Host IP addresses {ip} was not found!"
        if result.aliases is not None:
            for host in aliases:
                assert host in result.aliases, f"'Host alias {host} for 'host0' was not found!"
    else:
        raise AssertionError("Hosts entry not found!")

    for alias in aliases:
        result = client.tools.getent.hosts(alias, service="sss")
        if result is not None and result.ip is not None:
            for ip in ip_addresses:
                assert ip in result.ip, f"Alias IP addresses {ip} was not found!"


@pytest.mark.parametrize(
    "ip_addresses",
    [
        ["192.168.1.1"],
        ["192.168.1.1", "192.168.1.2"],
        ["2001:db8:1::1", "2001:db8:1::2"],
    ],
)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_hosts_by_ip(client: Client, ldap: LDAP, ip_addresses):
    """
    :title: Resolver provider lookup hosts by ip
    :setup:
        1. Create hosts and host aliases
        2. Start SSSD
    :steps:
        1. Lookup host IP address
    :expectedresults:
        1. IP addresses found
    :customerscenario: False
    """
    ldap.hosts("host0").add(ip_address=ip_addresses, aliases=[])
    client.sssd.start()

    for ip in ip_addresses:
        result = client.tools.getent.hosts(ip, service="sss")
        if result is not None and result.ip is not None:
            assert ip in result.ip, f"Host IP addresses {ip} was not found!"
        else:
            raise AssertionError("Host entry not found by IP!")


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.importance("medium")
def test_ldap__resolver_provider_lookup_hosts_mixed_ip_versions(client: Client, ldap: LDAP):
    """
    :title: Resolver provider lookup hosts with mixed ip versions

    ``getent hosts`` has two other commands, ``ahosts``  and ``ahostsv6``.
    ``hosts`` is used, when results contains both ipv4 and ipv4 addresses, only ipv6
    will be returned.

    :setup:
        1. Create hosts and host aliases
        2. Start SSSD
    :steps:
        1. Lookup host and check for IP addresses
        2. Lookup host and check for aliases
    :expectedresults:
        1. All IP addresses found
        2. Only ipv6 aliases are found
    :customerscenario: False
    """
    ip_addresses = [
        "2001:db8:1::1",
        "2001:db8:1::2",
        "192.168.1.1",
        "192.168.1.2",
    ]
    ipv6_addresses = ["2001:db8:1::1", "2001:db8:1::2"]
    aliases = ["host1.ldap.test", "host2.ldap.test"]

    ldap.hosts("host0").add(ip_address=ip_addresses, aliases=aliases)
    client.sssd.start()

    result = client.tools.getent.hosts("host0", service="sss")
    if result is not None and result.ip is not None:
        for ip in ipv6_addresses:
            assert ip in result.ip, f"Host IPv6 address {ip} was not found!"
        for alias in aliases:
            if result.aliases is not None:
                assert alias in result.aliases, f"'Host alias {alias} was not found!"
    else:
        raise AssertionError("No hosts entry found!")


@pytest.mark.parametrize(
    ("ip_address", "aliases"),
    [
        ("192.168.1.1", []),
        ("192.168.2.1", ["net1", "net2"]),
    ],
)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_networks(client: Client, ldap: LDAP, ip_address, aliases):
    """
    :title: Resolver provider lookup networks
    :setup:
        1. Create network and network aliases
        2. Start SSSD
    :steps:
        1. Lookup IP addresses
        2. Lookup network
        3. Lookup network aliases
    :expectedresults:
        1. IP addresses found
        2. Network found
        3. Network aliases found
    :customerscenario: False
    """
    ldap.networks("net0").add(ip_address=ip_address, aliases=aliases)
    client.sssd.start()

    result = client.tools.getent.networks("net0", service="sss")
    if result is not None and result.name is not None and result.ip is not None:
        assert "net0" == result.name, "Network 'net0'  was not found!"
        assert all(ip in result.ip for ip in ip_address), f"Network IP addresses {ip_address} was not found!"
    else:
        raise AssertionError("No networks entry found!")

    result = client.tools.getent.networks(ip_address, service="sss")
    if result is not None:
        assert "net0" == result.name, "Network 'net0'  was not found!"
        if result.aliases is not None:
            for network in aliases:
                assert network in result.aliases, f"Network alias {network} for 'net0' was not found!"
    else:
        raise AssertionError("No networks entry found by IP!")

    for alias in aliases:
        result = client.tools.getent.networks(alias, service="sss")
        if result is not None and result.ip is not None:
            assert ip_address == result.ip, f"Network IP addresses {ip_address} was not found!"


@pytest.mark.parametrize(
    ("port", "protocol", "aliases"),
    [
        (12345, "tcp", []),
        (12345, "tcp", ["service1"]),
    ],
)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_services(client: Client, ldap: LDAP, port, protocol, aliases):
    """
    :title: Resolver provider lookup services
    :setup:
        1. Create services
        2. Start SSSD
    :steps:
        1. Lookup service
        2. Lookup service by alias
    :expectedresults:
        1. Service found and port and protocol matches
        2. Service alias found
    :customerscenario: False
    """
    ldap.services("service0").add(port=port, protocol=protocol, aliases=aliases)
    client.sssd.start()

    result = client.tools.getent.services("service0", service="sss")
    if result is not None and result.name is not None and result.port is not None and result.protocol is not None:
        assert "service0" == result.name, "Service 'service0' was not found!"
        assert port == result.port, f"Service port '{str(port)}' was not found!"
        assert protocol in result.protocol, f"Service protocol '{protocol}' was not found!"
        for service in aliases:
            assert service in aliases, f"Alias service  '{service}' was not found!"
    else:
        raise AssertionError("No service entry found!")

    for alias in aliases:
        result = client.tools.getent.services(alias, service="sss")
        if result is not None and result.name is not None and result.port is not None and result.protocol is not None:
            assert port == result.port, f"Alias service port '{str(port)}'  port was not found!"
            assert protocol == result.protocol, f"Alias service protocol  '{protocol}'  protocol was not found!"


@pytest.mark.parametrize(("port", "protocol"), [(12345, "tcp"), (12345, "udp")])
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_services_by_port(client: Client, ldap: LDAP, port, protocol):
    """
    :title: Resolver provider lookup services by port
    :setup:
        1. Create services
        2. Start SSSD
    :steps:
        1. Lookup service by port
    :expectedresults:
        1. Service found and port and protocol matches
    :customerscenario: False
    """
    ldap.services("service0").add(port=port, protocol=protocol, aliases=[])
    client.sssd.start()

    result = client.tools.getent.services(str(port), service="sss")
    if result is not None and result.name is not None and result.port is not None and result.protocol is not None:
        assert "service0" == result.name, "Service 'service0' was not found!"
        assert port == result.port, f"Service port'{str(port)}'  was not found!"
        assert protocol in result.protocol, f"Service '{protocol}' was not found!"
    else:
        raise AssertionError("No service entry found!")


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_service_when_port_is_out_range(client: Client, ldap: LDAP):
    """
    :title: Lookup a service when a port is out of range and the invalid port should not be returned using getent
    :setup:
        1. Create a service with port 1234567 (out of valid range)
        2. Start SSSD
    :steps:
        1. Look up the service by name
        2. Check SSSD domain log for port-range error
    :expectedresults:
        1. getent returns no result for the service
        2. Log contains "Failed to identify service port" and "Numerical result out of range"
    :customerscenario: False
    """
    ldap.services("svc_badport").add(port=1234567, protocol="udp", aliases=[])
    client.sssd.start()

    result = client.tools.getent.services("svc_badport", service="sss")
    assert result is None, "Service with out-of-range port should not be returned!"

    log = client.fs.read(client.sssd.logs.domain())
    assert "Failed to identify service port" in log, "Expected port-out-of-range error in log!"
    assert "Numerical result out of range" in log, "Expected 'Numerical result out of range' message in log!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_services_with_filtered_search_base(client: Client, ldap: LDAP):
    """
    :title: ldap_service_search_base with a protocol filter limits the returned services
    :setup:
        1. Create a TCP service
        2. Create a UDP service
        3. Configure ldap_service_search_base with a filter restricting to UDP protocol
        4. Start SSSD
    :steps:
        1. Look up the UDP service
        2. Look up the TCP service
    :expectedresults:
        1. UDP service is found
        2. TCP service is not found (excluded by the filter)
    :customerscenario: False
    """
    base = ldap.ldap.naming_context
    ldap.services("svc_tcp").add(port=1234, protocol="tcp", aliases=[])
    ldap.services("svc_udp").add(port=1234, protocol="udp", aliases=[])

    client.sssd.dom("test")["ldap_service_search_base"] = f"ou=Services,{base}?one?(ipServiceProtocol=udp)"
    client.sssd.start()

    result = client.tools.getent.services("svc_udp", service="sss")
    assert result is not None, "UDP service should be found with the protocol filter!"
    assert result.name == "svc_udp"

    result = client.tools.getent.services("svc_tcp", service="sss")
    assert result is None, "TCP service should not be found with udp-only protocol filter!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__resolver_provider_lookup_services_with_case_sensitivity_set_to_false(client: Client, ldap: LDAP):
    """
    :title: Service lookups succeed with mixed-case names and aliases when case_sensitive is false
    :setup:
        1. Create a service named "Svc1" with a mixed-case alias "SVC1_Alias1"
        2. Configure SSSD with case_sensitive = false
        3. Start SSSD
    :steps:
        1. Look up service using lowercase name "svc1"
        2. Look up service using uppercase alias "svc1_alias1"
        3. Look up service by port with mixed-case protocol "TCP"
    :expectedresults:
        1. Service is found regardless of case
        2. Alias lookup succeeds regardless of case
        3. Port/protocol lookup succeeds regardless of case
    :customerscenario: False
    """
    ldap.services("Svc1").add(port=1234, protocol="tcp", aliases=["SVC1_Alias1"])

    client.sssd.dom("test")["case_sensitive"] = "false"
    client.sssd.start()

    result = client.tools.getent.services("svc1", service="sss")
    assert result is not None, "Service lookup should succeed with lowercase name when case_sensitive=false!"
    assert result.port == 1234

    result = client.tools.getent.services("svc1_alias1", service="sss")
    assert result is not None, "Service alias lookup should succeed case-insensitively!"

    result = client.tools.getent.services("1234/TCP", service="sss")
    assert result is not None, "Service port/protocol lookup should succeed with uppercase protocol!"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("timeout, expect_expire", [(15, True), (0, True), (-100, True)])
@pytest.mark.importance("medium")
def test_ldap__connection_expire_timeout_releases_connection(
    client: Client, ldap: LDAP, timeout: int, expect_expire: bool
):
    """
    :title: LDAP connection is released after ldap_connection_expire_timeout
    :setup:
        1. Create user "user-1" and "user-2"
        2. Set ldap_connection_expire_timeout to @timeout
        3. Start SSSD
    :steps:
        1. Lookup user-1 to establish a connection
        2. Wait for timeout to expire (or a short period for instant-expire values)
        3. Lookup user-2 to trigger a new connection
        4. Verify the connection was recycled by checking domain logs
    :expectedresults:
        1. User-1 is found
        2. Timeout period passes
        3. User-2 is found
        4. Log contains "Connection is about to expire, releasing it" for positive timeouts,
           or connection is instantly recycled for zero/negative values
    :customerscenario: False
    """
    ldap.user("user-1").add()
    ldap.user("user-2").add()
    client.sssd.domain["ldap_connection_expire_timeout"] = str(timeout)
    client.sssd.start()

    result = client.tools.id("user-1")
    assert result is not None, "user-1 not found!"

    wait = timeout + 5 if timeout > 0 else 5
    time.sleep(wait)

    result = client.tools.id("user-2")
    assert result is not None, "user-2 not found!"

    if timeout > 0:
        log = client.fs.read(client.sssd.logs.domain())
        assert (
            "Connection is about to expire, releasing it" in log
        ), "Connection expire message not found in domain log!"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.importance("medium")
def test_ldap__connection_expire_timeout_out_of_range(client: Client, ldap: LDAP):
    """
    :title: SSSD rejects ldap_connection_expire_timeout value out of integer range
    :setup:
        1. Create user "user-1"
        2. Set ldap_connection_expire_timeout to a value exceeding INT_MAX
    :steps:
        1. Start SSSD
        2. Check domain log for "Numerical result out of range" error
    :expectedresults:
        1. SSSD starts but the domain may fail to initialize properly
        2. Log contains the out-of-range error message
    :customerscenario: False
    """
    ldap.user("user-1").add()
    out_of_range = str(2**31)
    client.sssd.domain["ldap_connection_expire_timeout"] = out_of_range
    client.sssd.start(raise_on_error=False, check_config=False)

    log = client.fs.read(client.sssd.logs.domain())
    assert (
        "Numerical result out of range" in log
    ), "Expected 'Numerical result out of range' error not found in domain log!"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.importance("low")
def test_ldap__connection_expire_timeout_default_value_is_logged(client: Client, ldap: LDAP):
    """
    :title: Default ldap_connection_expire_timeout value (900) is logged at startup
    :setup:
        1. Create user "user-1"
        2. Do not set ldap_connection_expire_timeout (use default)
        3. Start SSSD
    :steps:
        1. Lookup user-1
        2. Check domain log for the default timeout value
    :expectedresults:
        1. User is found
        2. Log contains "Option ldap_connection_expire_timeout has value 900"
    :customerscenario: False
    """
    ldap.user("user-1").add()
    client.sssd.start()

    result = client.tools.id("user-1")
    assert result is not None, "user-1 not found!"

    log = client.fs.read(client.sssd.logs.domain())
    assert (
        "Option ldap_connection_expire_timeout has value 900" in log
    ), "Default ldap_connection_expire_timeout value (900) not found in domain log!"


@pytest.mark.ticket(bz=748856)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__display_password_expiration_warning(client: Client, ldap: LDAP):
    """
    :title: Display password expiration warning
    :setup:
        1. Set "passwordExp" to "on"
        2. Set "passwordMaxAge" to "86400"
        3. Set "passwordWarning" to "86400"
        4. Add a user to LDAP
        5. Start SSSD
    :steps:
        1. Authenticate as the user1 via 'su' with password "Secret123"
        2. Check that user was informed about password expiration
        3. Repeat the steps above with 'ssh' method
    :expectedresults:
        1. Authentication should succeed
        2. Corresponding password expiration warning should be generated
        3. Same results are expected for 'ssh' too
    :customerscenario: False
    """
    ldap.ldap.modify("cn=config", replace={"passwordExp": "on", "passwordMaxAge": "86400", "passwordWarning": "86400"})
    ldap.user("user1").add(password="Secret123")
    client.sssd.start()

    for method in ["su", "ssh"]:
        rc, _, stdout, _ = client.auth.parametrize(method).password_with_output("user1", "Secret123")
        assert rc == 0, "User 'user1' login failed!"
        assert "Your password will expire in " in stdout, "Password expiration warning not generated!"


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=785908)
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__search_base_limits_rfc2307bis_posixgroup_scope(client: Client, ldap: LDAP):
    """
    :title: ldap_search_base limits group scope for rfc2307bis and groupOfNames schema
    :description:
        When ldap_search_base is set, groups stored outside that base must not be resolved,
        even when they are nested members of a group that is inside the base.
    :setup:
        1. Create groups inside and outside the configured ldap_search_base, nested across the boundary
        2. Configure SSSD with rfc2307bis schema, groupOfNames object class and a limited ldap_search_base
        3. Start SSSD
    :steps:
        1. Lookup groups that are inside the search base
        2. Lookup groups that are outside the search base
    :expectedresults:
        1. Groups inside the search base are found
        2. Groups outside the search base are not found
    :customerscenario: True
    :requirement: SSSD - Default debug level
    """
    outside_ou = ldap.ou("qagroup").add()
    user = ldap.user("tempuser").add()

    outside_group = ldap.group("outside_group", basedn=outside_ou, rfc2307bis=True).add(members=[user])
    ldap.group("inside_group", rfc2307bis=True).add(members=[outside_group])

    client.sssd.domain["ldap_schema"] = "rfc2307bis"
    client.sssd.domain["ldap_group_object_class"] = "groupOfNames"
    client.sssd.dom("test")["ldap_search_base"] = f"ou=groups,{ldap.ldap.naming_context}"
    client.sssd.start()

    assert client.tools.getent.group("inside_group") is not None, "inside_group was not found!"
    assert (
        client.tools.getent.group("outside_group") is None
    ), "outside_group should not be visible outside search base!"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.importance("low")
def test_ldap__password_expiration_warning_does_not_overwrite_errors(client: Client, provider: LDAP):
    """
    :title: SSSD warns that a password is about to expire
    :setup:
        1. Create user with expired password
        3. Set 'ldap_access_order = pwd_expire_policy_warn' and restart SSSD
        4. Create SSH key for the user and write it to 'authorizred_keys'
    :steps:
        1. SSH into the local host with the SSH key of the user
        2. Change 'ldap_access_order' to 'pwd_expire_policy_warn, expire'
        3. SSH into the local host with the SSH key of the user
    :expectedresults:
        1. SSH is successful and shows 'Your password has expired.' on standard error
        2. Config change is successful
        3. SSH fails because the 'expire' policy rejects the locked user
    :customerscenario: False
    """

    user = provider.user("user1").add(
        shadowMin=0, shadowMax=99999, shadowWarning=7, shadowLastChange=0, shadowExpire=1, password="Secret123"
    )

    client.sssd.domain["auto_private_groups"] = "True"
    client.sssd.domain["access_provider"] = "ldap"
    client.sssd.domain["ldap_pwd_policy"] = "shadow"
    client.sssd.domain["ldap_account_expire_policy"] = "shadow"
    client.sssd.domain["ldap_access_order"] = "pwd_expire_policy_warn"
    client.sssd.restart()

    pwd = client.tools.getent.passwd(user.name)
    assert pwd is not None, "User not found!"
    assert pwd.name is not None, "User name is missing!"
    assert pwd.home is not None, "home directory is missing!"

    client.host.conn.run(f"su - {user.name}", raise_on_error=False)
    key = client.tools.sshkey.generate(pwd.name, pwd.home)[0]
    client.fs.write(f"{pwd.home}/.ssh/authorized_keys", key)
    # remove password from keyfile to make non-interactive login work
    client.host.conn.run(f"ssh-keygen -p -P ' ' -N '' -f {pwd.home}/.ssh/id_rsa")

    client.sssd.restart(clean=True)

    result = client.host.conn.run(
        f"sudo -u {user.name} ssh -o StrictHostKeychecking=no "
        "-o PubkeyAuthentication=yes -o GSSAPIAuthentication=no "
        "-o KbdInteractiveAuthentication=no -o PasswordAuthentication=no "
        f"-l {user.name} localhost whoami",
        raise_on_error=False,
    )
    assert result.rc == 0, "SSH with pubkey failed!"
    assert result.stdout == f"{user.name}", "Missing user name output!"
    assert "Your password has expired." in result.stderr, "Missing 'Your password has expired.' in error output!"

    client.sssd.domain["ldap_access_order"] = "pwd_expire_policy_warn, expire"
    client.sssd.restart(clean=True)

    result = client.host.conn.run(
        f"sudo -u {user.name} ssh -o StrictHostKeychecking=no "
        "-o PubkeyAuthentication=yes -o GSSAPIAuthentication=no "
        "-o KbdInteractiveAuthentication=no -o PasswordAuthentication=no "
        f"-l {user.name} localhost whoami",
        raise_on_error=False,
    )
    assert result.rc != 0, "SSH was successful but should have failed!"
    assert result.stdout == "", "Output is not empty!"
    assert "Your password has expired." in result.stderr, "Missing 'Your password has expired.' in error output!"


@pytest.mark.ticket(bz=954323)
@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap__display_grace_logins_when_password_has_expired(client: Client, ldap: LDAP):
    """
    :title: Display number of remaining grace logins when password is expired
    :description: Warns user of remaining grace logins upon logging in with an expired password.
    :setup:
        1. Set "passwordExp" to "on"
        2. Set "passwordMaxAge" to "1"
        3. Set "passwordGraceLimit" to "2"
        3. Add a user to LDAP
        4. Wait until the password is expired
        6. Start SSSD
    :steps:
        1. Authenticate as the user1 via 'su' with password "Secret123"
        2. Verify stdout for the message indicating remaining grace logins
        3. Repeat steps 1-2 with 'ssh' method
    :expectedresults:
        1. Authentication should succeed
        2. Corresponding log should be generated
        3. Results above are expected in every iteration
    :customerscenario: False
    """
    ldap.ldap.modify("cn=config", replace={"passwordExp": "on", "passwordMaxAge": "1", "passwordGraceLimit": "2"})
    ldap.user("user1").add(password="Secret123")
    client.sssd.start()
    time.sleep(2)

    grace_logins = 2
    for method in ["su", "ssh"]:
        rc, _, stdout, _ = client.auth.parametrize(method).password_with_output("user1", "Secret123")
        grace_logins -= 1
        assert rc == 0, f"User 'user1' login failed!: rc == {rc}; method: {method}, grace logins left: {grace_logins}"
        assert (
            f"You have {grace_logins} grace login(s) remaining" in stdout
        ), "Expected grace logins message in stdout, but none was found."

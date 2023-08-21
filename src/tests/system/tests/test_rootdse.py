"""
SSSD Log tests.

:requirement: Ldap Provider - ldap_id_ldap_auth
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.LDAP)
def test_ldap_search_base(client: Client, ldap: LDAP):
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
def test_ldap_user_search_base_set(client: Client, ldap: LDAP, user_search_base, search_base):
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
def test_default_naming_context(client: Client, ldap: LDAP):
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
def test_multiple_naming_contexts(client: Client, ldap: LDAP, user_search_base):
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

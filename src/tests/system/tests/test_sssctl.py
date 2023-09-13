"""
SSSCTL tests.

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import re

import pytest
from pytest_mh.ssh import SSHProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=2100789)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__check_id_provider(client: Client):
    """
    :title: Check id_provider in domain section with sssctl config-check command
    :setup:
        1. Create the sssd.conf, here we are using provider as a LDAP server
    :steps:
        1. Remove id_provider from domain section.
        2. Check error message using sssctl config-check.
    :expectedresults:
        1. Successfully remove id_provider from domain section.
        2. Successfully get the error message.
    :customerscenario: False
    """
    # create sssd.conf and start the sssd, with default configuration with a LDAP server.
    client.sssd.start()

    # remove id_provider parameter from domain section.
    client.sssd.config.remove_option("domain/test", "id_provider")
    client.sssd.config_apply(check_config=False)

    # Check the error message in output of # sssctl config-check
    output = client.host.ssh.run("sssctl config-check", raise_on_error=False)
    assert "[rule/sssd_checks]: Attribute 'id_provider' is missing in section 'domain/test'." in output.stdout_lines[1]


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=2100789)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__check_invalid_id_provider(client: Client):
    """
    :title: Check id_provider in domain section with sssctl config-check command with provider
    :setup:
        1. Create the sssd.conf, here we are using provider as a LDAP server
    :steps:
        1. Add invalid, id_provider's value to domain section.
        2. Check error message using sssctl config-check.
    :expectedresults:
        1. Successfully remove id_provider from domain section.
        2. Successfully get the error message.
    :customerscenario: False
    """
    # create sssd.conf and start the sssd, with deafult configuration with a LDAP server.
    client.sssd.start()

    # Add 'invalid' as a id_provider's value in domain section.
    client.sssd.config.remove_option("domain/test", "id_provider")
    client.sssd.domain["id_provider"] = "invalid"
    client.sssd.config_apply(check_config=False)

    # Check the return code of # sssctl config-check command
    output = client.host.ssh.run("sssctl config-check", raise_on_error=False)
    assert (
        "[rule/sssd_checks]: Attribute 'id_provider' in section 'domain/test' has an invalid value: invalid"
        in output.stdout_lines[1]
    )


@pytest.mark.ticket(bz=1640576)
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__user_show_cache_expiration_time(client: Client):
    """
    :title: sssctl user-show reports correct expiration time of local user
    :setup:
        1. Add local users
        2. Configure local domain
        3. Start SSSD
    :steps:
        1. Call sssctl user-show $user
        2. Check correct output
    :expectedresults:
        1. Called successfully
        2. Output is as expected
    :customerscenario: True
    """
    client.local.user("local1").add()
    client.local.user("local2").add()
    client.local.user("local3").add()

    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.domain["id_provider"] = "files"
    client.sssd.domain["passwd_files"] = "/etc/passwd"

    client.sssd.start()

    for user in {"local1", "local2", "local3"}:
        cmd = client.sssctl.user_show(user=user)
        assert cmd.rc == 0, "Command call failed"
        assert "Cache entry expiration time: Never" in cmd.stdout, "Wrong output"


@pytest.mark.ticket(bz=1599207)
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__handle_implicit_domain(client: Client):
    """
    :title: sssctl handle implicit domain
    :setup:
        1. Add local users
        2. Set sssd "enable_files_domain" to "true"
        3. Start SSSD
    :steps:
        1. Call getent passwd user -s sss
        2. Call sssctl user-show --user=$user
        3. Check correct output
    :expectedresults:
        1. Called successfully
        2. Called successfully
        3. Output is correct
    :customerscenario: True
    """
    client.local.user("local1").add()
    client.local.user("local2").add()
    client.local.user("local3").add()

    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    for user in {"local1", "local2", "local3"}:
        assert client.tools.getent.passwd(user, service="sss") is not None
        cmd = client.sssctl.user_show(user=user)
        assert cmd.rc == 0
        assert "Cache entry creation date" in cmd.stdout


@pytest.mark.ticket(bz=1902280)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__reset_cached_timestamps(client: Client, ldap: LDAP):
    """
    :title: fix sssctl cache-expire to also reset cached timestamp
    :setup:
        1. Add user to LDAP
        2. Add group to LDAP
        3. Set proper domain config options in sssd.conf file
        4. Start SSSD
    :steps:
        1. Call getent group
        2. Modify group entry in LDAP
        3. Call 'sssctl cache-expire -E'
        4. Call getent group
    :expectedresults:
        1. Group is properly cached, user is its member
        2. Member of group is removed, group entry changed
        3. Whole cache is invalidated
        4. User is not member of group anymore
    :customerscenario: True
    """
    u = ldap.user("user1").add()
    ldap.group("group1", rfc2307bis=True).add().add_member(u)

    client.sssd.domain["ldap_schema"] = "rfc2307bis"
    client.sssd.domain["ldap_group_member"] = "member"

    client.sssd.start()

    res1 = client.tools.getent.group("group1")
    assert res1 is not None
    assert "user1" in res1.members

    ldap.group("group1", rfc2307bis=True).remove_member(ldap.user("user1"))
    client.sssctl.cache_expire(everything=True)

    res1 = client.tools.getent.group("group1")
    assert res1 is not None
    assert "user1" not in res1.members


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_typo_option_name(client: Client):
    """
    :title: sssctl config-check detects mistyped option name
    :setup:
        1. Add wrong_option to domain section
        2. Start SSSD, without config check
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.dom("test")["wrong_option"] = "true"

    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"

    pattern = re.compile(r"Attribute 'wrong_option' is not allowed.*")
    assert pattern.search(result.stdout), "Wrong error message was returned"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_typo_domain_name(client: Client):
    """
    :title: sssctl config-check detects mistyped domain name
    :setup:
        1. Create mistyped domain ("domain/")
        2. Start SSSD
    :steps:
        1. Call sssctl config-check, implicitly
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.dom("")["debug_level"] = "9"

    with pytest.raises(SSHProcessError) as ex:
        client.sssd.start(raise_on_error=True, check_config=True)

    assert ex.match(r"Section \[domain\/\] is not allowed. Check for typos.*"), "Wrong error message was returned"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_misplaced_option(client: Client):
    """
    :title: sssctl config-check detects misplaced option
    :setup:
        1. In domain set "services" to "nss, pam"
        2. Start SSSD, without config check
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.dom("test")["services"] = "nss, pam"

    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"

    pattern = re.compile(r".Attribute 'services' is not allowed in section .*")
    assert pattern.search(result.stdout), "Wrong error message was returned"

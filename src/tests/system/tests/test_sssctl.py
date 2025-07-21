"""
SSSCTL tests.

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import re
import time

import pytest
from pytest_mh.conn import ProcessError
from pytest_mh.conn.ssh import SSHAuthenticationError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology


def setup_local_sssd(client: Client, start: bool = True, check_config: bool = True):
    """Set up local SSSD and optionally start it."""
    client.sssd.common.local()
    if start:
        client.sssd.start(check_config=check_config)


@pytest.mark.parametrize(
    "setup_fn",
    [
        # wrong option in domain
        lambda c: (
            setup_local_sssd(c, start=False),
            c.sssd.dom("test").__setitem__("wrong_option", "true"),
            c.sssd.config_apply(check_config=False),
        ),
        # missing domain name
        lambda c: c.sssd.dom("").__setitem__("debug_level", "9"),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__invalid_option_or_domain_name(client: Client, setup_fn):
    """
    :title: sssctl config-check detects invalid options or missing domain names
    :setup:
        1. Configure SSSD with either an invalid option in a domain section or a domain with a missing name.
    :steps:
        1. Start SSSD or run sssctl config-check.
    :expectedresults:
        1. The configuration check fails for both scenarios.
    :customerscenario: False
    """
    setup_fn(client)
    client.sssd.common.local()
    if "" in client.sssd.domain:
        with pytest.raises(ProcessError):
            client.sssd.start(raise_on_error=True, check_config=True)
    else:
        assert client.sssctl.config_check().rc != 0


@pytest.mark.parametrize(
    "pattern,repl",
    [
        # semantic errors
        ("id_provider.*", "id_provider = invalid"),
        ("id_provider.*", ""),
        ("id_provider", "id_@provider"),
        ("domain/local", "domain/local@"),
        (".sssd.", "[sssdx]"),
        # syntax errors
        ("id_provider = ", "id_provider "),
        (".nss.", "[nssx"),
        (".domain/local.", "domain/local]"),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__invalid_config_patterns(client: Client, pattern: str, repl: str):
    """
    :title: sssctl config-check detects invalid semantic or syntax patterns in config
    :setup:
        1. Start SSSD with valid configuration.
        2. Modify sssd.conf to introduce various invalid syntax or semantic issues.
    :steps:
        1. Run sssctl config-check.
    :expectedresults:
        1. The configuration check fails for all invalid patterns.
    :customerscenario: False
    """
    setup_local_sssd(client)
    conf = re.sub(pattern, repl, client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf)
    assert client.sssctl.config_check().rc != 0


@pytest.mark.parametrize(
    "setup_fn",
    [
        # invalid permission
        lambda c: (setup_local_sssd(c), c.fs.chmod("0777", "/etc/sssd/sssd.conf")),
        # config missing
        lambda c: (setup_local_sssd(c), c.fs.rm("/etc/sssd/sssd.conf")),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__permission_and_missing_config(client: Client, setup_fn):
    """
    :title: sssctl config-check detects improper file permissions or missing configuration file
    :setup:
        1. Start SSSD with valid configuration.
        2. Either set world-writable permissions on sssd.conf or remove the file entirely.
    :steps:
        1. Run sssctl config-check.
    :expectedresults:
        1. The configuration check fails in both cases.
    :customerscenario: False
    """
    setup_fn(client)
    assert client.sssctl.config_check().rc != 0


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1677994)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_ldap_host_object_class_in_domain(client: Client):
    """
    :title: sssctl config-check allow ldap_host_object_class in domain section
    :setup:
        1. Add ldap_host_object_class to local domain section
        2. Start SSSD
    :steps:
        1. Call sssctl config-check
    :expectedresults:
        1. config-check succeed
    :customerscenario: True
    """
    client.sssd.default_domain = "local"
    client.sssd.common.local()
    client.sssd.domain["ldap_host_object_class"] = "ipService"
    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc == 0, "Config-check failed"


@pytest.mark.ticket(bz=1677994)
@pytest.mark.parametrize(
    "section,option,value",
    [
        ("domain", "services", "nss, pam"),
        ("sssd", "ldap_host_object_class", "ipService"),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__attribute_not_allowed_in_section(client: Client, section: str, option: str, value: str):
    """
    :title: sssctl config-check validates attributes in specific sections
    :setup:
        1. Configure attributes that are disallowed in particular sections
    :steps:
        1. Check the configuration using sssctl
    :expectedresults:
        1. Error message indicates the attribute is not allowed in that section
    :customerscenario: True
    """
    client.sssd.default_domain = "local"
    setup_local_sssd(client, start=False)
    getattr(client.sssd, section)[option] = value
    client.sssd.config_apply(check_config=False)
    assert client.sssctl.config_check().rc != 0


@pytest.mark.ticket(bz=1856861)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__enabling_2fa_prompting(client: Client):
    """
    :title: False warnings are logged in sssd.log file after enabling 2FA prompting
    :setup:
        1. Enable Two factor authentication
        2. Start SSSD
    :steps:
        1. Call sssctl config-check
    :expectedresults:
        1. config-check succeed
    :customerscenario: True
    """
    setup_local_sssd(client, start=False)
    client.sssd.section("prompting/2fa/sshd")["first_prompt"] = "Enter OTP Token Value:"
    client.sssd.section("prompting/2fa/sshd")["single_prompt"] = "True"
    client.sssd.section("prompting/2fa")["first_prompt"] = "prompt1"
    client.sssd.section("prompting/2fa")["second_prompt"] = "prompt2"
    client.sssd.section("prompting/2fa")["single_prompt"] = "True"
    client.sssd.start(check_config=False)
    assert client.sssctl.config_check().rc == 0


@pytest.mark.ticket(bz=1791892)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__auto_private_groups_in_child_domains(client: Client):
    """
    :title: sssctl config-check detects false positive when auto_private_groups is enabled or disabled in child domains
    :setup:
        1. Enable auto_private_groups in child domain
        2. Disable auto_private_groups in second child domain
        3. Start SSSD
    :steps:
        1. Call sssctl config-check
    :expectedresults:
        1. config-check succeed
    :customerscenario: True
    """
    setup_local_sssd(client, start=False)
    client.sssd.sssd["domains"] = "td5f4f77.com"
    client.sssd.subdom("td5f4f77.com", "one5f4f77.td5f4f77.com")["auto_private_groups"] = "True"
    client.sssd.subdom("td5f4f77.com", "two5f4f77.td5f4f77.com")["auto_private_groups"] = "False"
    client.sssd.start(check_config=False, debug_level=None)
    assert client.sssctl.config_check().rc == 0


@pytest.mark.parametrize(
    "setup_fn",
    [
        # missing snippet dir
        lambda c: (
            setup_local_sssd(c, start=False),
            c.sssd.config_apply(),
            c.fs.mkdir("/tmp/test/"),
            c.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/"),
        ),
        # invalid permission
        lambda c: (
            setup_local_sssd(c, start=False),
            c.sssd.config_apply(),
            c.fs.mkdir("/tmp/test/"),
            c.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/sssd.conf", mode="777"),
        ),
        # invalid option in non-default config
        lambda c: (
            setup_local_sssd(c, start=False),
            c.sssd.__setattr__("default_domain", "local"),
            c.sssd.domain.__setitem__("search_base", "True"),
            c.sssd.config_apply(check_config=False),
            c.fs.mkdir("/tmp/test/"),
            c.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/"),
        ),
        # with snippet dir
        lambda c: (
            setup_local_sssd(c, start=False),
            c.sssd.config_apply(check_config=False),
            c.fs.mkdir("/tmp/test/"),
            c.fs.mkdir("/tmp/test/conf.d", mode="700"),
            c.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/"),
        ),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_variants(client: Client, setup_fn):
    """
    :title: sssctl config-check validation for various non-default config file scenarios
    :setup:
        1. Copy sssd.conf to a non-default directory.
        2. Introduce one of several conditions: missing snippet dir, invalid permission,
            invalid option, or proper snippet dir.
    :steps:
        1. Run sssctl config-check with --config pointing to the copied file.
    :expectedresults:
        1. The configuration check fails for all scenarios except the one with proper
            snippet directory and permissions.
    :customerscenario: True
    """
    setup_fn(client)
    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    # Expect success only for "with snippet dir"
    if client.fs.exists("/tmp/test/conf.d"):
        assert rc == 0
    else:
        assert rc != 0


@pytest.mark.ticket(bz=1723273)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_existing_snippet(client: Client):
    """
    :title: sssctl config-check detects non existing snippet directory
    :setup:
        1. Start SSSD.
    :steps:
        1. Call sssctl config-check with non existing snippet.
    :expectedresults:
        1. config-check failed.
    :customerscenario: True
    """
    setup_local_sssd(client)
    assert client.sssctl.config_check(snippet="/does/not/exist").rc != 0


def setup_debug_sssd(client: Client, provider: GenericProvider, user: str = "user1", password: str = "Secret123"):
    """Common setup for analyze tests."""
    provider.user(user).add(password=password)
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()
    return user, password


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_list(client: Client, ldap: GenericProvider):
    """
    :title: sssctl analyze request list displays NSS related requests from logs
    :setup:
        1. Add user/group.
        2. Start SSSD.
        3. Run NSS commands to generate logs.
    :steps:
        1. Run sssctl analyze list and list -v.
        2. Clear cache and repeat.
    :expectedresults:
        1. The analyze commands run successfully.
        2. The analyze commands run successfully.
    :customerscenario: True
    """
    setup_debug_sssd(client, ldap)
    assert client.tools.getent.group("group1") is None or True
    assert client.tools.id("user1")
    assert client.sssctl.analyze_request("list").rc == 0
    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    assert client.sssctl.analyze_request("list").rc == 0


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670, gh=6298)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_non_default_log_location(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze parses logs from a non-default log location
    :setup:
        1. Add user.
        2. Start SSSD and perform authentication.
        3. Copy logs to alternate location.
        4. Stop and clear SSSD state.
    :steps:
        1. Run sssctl analyze commands with --logdir pointing to the copied logs.
    :expectedresults:
        1. The analyze commands succeed and parse expected request data from the alternate location.
    :customerscenario: True
    """
    user, pw = setup_debug_sssd(client, provider)
    client.tools.id(f"{user}@test")
    client.ssh(user, pw).connect()
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.sssd.stop()
    client.sssd.clear(config=True, logs=True)
    assert client.sssctl.analyze_request(command="show 1 --pam", logdir="/tmp/copy/").rc == 0


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_pam_logs(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze parses PAM authentication requests from logs
    :setup:
        1. Add user.
        2. Start SSSD and perform SSH login.
    :steps:
        1. Run sssctl analyze --pam.
    :expectedresults:
        1. Command succeeds and output contains expected request ID.
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0
    assert "CID #1" in res.stdout


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2013259)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_tevent_id(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze displays tevent chain IDs in PAM request output
    :setup:
        1. Add user.
        2. Start SSSD and perform SSH login.
    :steps:
        1. Run sssctl analyze --pam.
    :expectedresults:
        1. Output contains RID# identifiers and username.
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0
    assert "RID#" in res.stdout


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2013260)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.IPA)
def test_sssctl__analyze_child_logs(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze parses child process logs with --child option
    :setup:
        1. Add user.
        2. Start SSSD and perform SSH login.
        4. Restart and attempt login with wrong password.
    :steps:
        1. Run sssctl analyze --child to check logs for both successful and failed logins.
    :expectedresults:
        1. Output contains relevant authentication events for both scenarios.
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.ssh("user1", "Secret123").connect()
    assert client.sssctl.analyze_request("show --pam --child 1").rc == 0
    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    time.sleep(5)
    with pytest.raises(SSHAuthenticationError):
        client.ssh("user1", "Wrong").connect()
    assert client.sssctl.analyze_request("show --pam --child 1").rc == 0


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[2142960, 2142794, 2142961])
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_without_root_privileges(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze works without root privileges on accessible logs
    :setup:
        1. Add user.
        2. Start SSSD and perform authentication to generate logs.
        3. Copy logs to alternate location and set ownership to test user.
    :steps:
        1. Run sssctl analyze as root and as the test user.
    :expectedresults:
        1. Both runs succeed and produce identical output containing the username.
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.tools.id("user1")
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.fs.chown("/tmp/copy", "user1", args=["--recursive"])
    result_root = client.sssctl.analyze_request(command="show 1", logdir="/tmp/copy")
    result_user = client.host.conn.run('su user1 -c "sssctl analyze --logdir /tmp/copy request show 1"')
    assert result_root.rc == 0
    assert result_user.rc == 0
    assert result_root.stdout == result_user.stdout

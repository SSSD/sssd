"""
SSSCTL tests.

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import re

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


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__invalid_option_in_domain(client: Client):
    """
    :title: sssctl config-check fails with invalid option in domain section
    :setup:
        1. Configure SSSD with invalid option in domain section
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails
    :customerscenario: False
    """
    setup_local_sssd(client, start=False)
    client.sssd.dom("test")["wrong_option"] = "true"
    client.sssd.config_apply(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for invalid domain option"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__missing_domain_name(client: Client):
    """
    :title: sssctl config-check fails with missing domain name
    :setup:
        1. Configure SSSD with missing domain name
    :steps:
        1. Start SSSD
    :expectedresults:
        1. Service fails to start
    :customerscenario: False
    """
    client.sssd.dom("")["debug_level"] = "9"
    with pytest.raises(ProcessError):
        client.sssd.start(raise_on_error=True, check_config=True)


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
    :title: sssctl config-check detects invalid config patterns
    :setup:
        1. Start with valid SSSD config
        2. Modify config with invalid patterns
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails for all invalid patterns
    :customerscenario: False
    """
    setup_local_sssd(client)
    conf = re.sub(pattern, repl, client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for pattern '{pattern}' -> '{repl}'"


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
    :title: sssctl config-check detects file permission issues
    :setup:
        1. Start with valid SSSD config
        2. Set improper permissions or remove config file
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails
    :customerscenario: False
    """
    setup_fn(client)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for file permission issue"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1677994)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_ldap_host_object_class_in_domain(client: Client):
    """
    :title: sssctl config-check allows ldap_host_object_class in domain
    :setup:
        1. Add ldap_host_object_class to domain section
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check succeeds
    :customerscenario: True
    """
    client.sssd.default_domain = "local"
    client.sssd.common.local()
    client.sssd.domain["ldap_host_object_class"] = "ipService"
    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc == 0, f"config-check failed"


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
    :title: sssctl config-check validates section attributes
    :setup:
        1. Configure disallowed attributes in sections
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    client.sssd.default_domain = "local"
    setup_local_sssd(client, start=False)
    getattr(client.sssd, section)[option] = value
    client.sssd.config_apply(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for {section}.{option}={value}"


@pytest.mark.ticket(bz=1856861)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__enabling_2fa_prompting(client: Client):
    """
    :title: sssctl config-check works with 2FA prompting
    :setup:
        1. Enable Two factor authentication
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check succeeds
    :customerscenario: True
    """
    setup_local_sssd(client, start=False)
    client.sssd.section("prompting/2fa/sshd")["first_prompt"] = "Enter OTP Token Value:"
    client.sssd.section("prompting/2fa/sshd")["single_prompt"] = "True"
    client.sssd.section("prompting/2fa")["first_prompt"] = "prompt1"
    client.sssd.section("prompting/2fa")["second_prompt"] = "prompt2"
    client.sssd.section("prompting/2fa")["single_prompt"] = "True"
    client.sssd.start(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc == 0, f"config-check failed with 2FA"


@pytest.mark.ticket(bz=1791892)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__auto_private_groups_in_child_domains(client: Client):
    """
    :title: sssctl config-check with auto_private_groups in child domains
    :setup:
        1. Configure auto_private_groups in child domains
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check succeeds
    :customerscenario: True
    """
    setup_local_sssd(client, start=False)
    client.sssd.sssd["domains"] = "td5f4f77.com"
    client.sssd.subdom("td5f4f77.com", "one5f4f77.td5f4f77.com")["auto_private_groups"] = "True"
    client.sssd.subdom("td5f4f77.com", "two5f4f77.td5f4f77.com")["auto_private_groups"] = "False"
    client.sssd.start(check_config=False, debug_level=None)
    result = client.sssctl.config_check()
    assert result.rc == 0, f"config-check failed with auto_private_groups"


def setup_invalid_option(c):
    """Configure SSSD with invalid option in non-default config."""
    setup_local_sssd(c, start=False)
    c.sssd.default_domain = "local"
    c.sssd.domain["search_base"] = "True"
    c.sssd.config_apply(check_config=False)
    c.fs.mkdir("/tmp/test/")
    c.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")


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
        # invalid option
        setup_invalid_option,
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_failures(client: Client, setup_fn):
    """
    :title: sssctl config-check fails for non-default config issues
    :setup:
        1. Copy config to non-default location
        2. Introduce various issues
    :steps:
        1. Run sssctl config-check with --config
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    setup_fn(client)
    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc != 0, f"config-check should fail for non-default config"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_with_snippet_dir(client: Client):
    """
    :title: sssctl config-check succeeds with proper non-default config
    :setup:
        1. Copy config to non-default location with proper snippet dir
    :steps:
        1. Run sssctl config-check with --config
    :expectedresults:
        1. Configuration check succeeds
    :customerscenario: True
    """
    setup_local_sssd(client, start=False)
    client.sssd.config_apply(check_config=False)
    client.fs.mkdir("/tmp/test/")
    client.fs.mkdir("/tmp/test/conf.d", mode="700")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc == 0, f"config-check failed for valid non-default config"


@pytest.mark.ticket(bz=1723273)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_existing_snippet(client: Client):
    """
    :title: sssctl config-check detects non-existing snippet directory
    :setup:
        1. Start SSSD
    :steps:
        1. Run sssctl config-check with non-existing snippet
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    setup_local_sssd(client)
    result = client.sssctl.config_check(snippet="/does/not/exist")
    assert result.rc != 0, f"config-check should fail for non-existing snippet"


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
    :title: sssctl analyze request list displays NSS requests
    :setup:
        1. Add user/group and start SSSD
        2. Run NSS commands
    :steps:
        1. Run sssctl analyze list
        2. Clear cache and repeat
    :expectedresults:
        1. Analyze commands succeed
        2. Analyze commands succeed
    :customerscenario: True
    """
    setup_debug_sssd(client, ldap)
    assert client.tools.getent.group("group1") is None
    assert client.tools.id("user1")
    result = client.sssctl.analyze_request("list")
    assert result.rc == 0, f"analyze list failed"
    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    result = client.sssctl.analyze_request("list")
    assert result.rc == 0, f"analyze list failed after restart"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670, gh=6298)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_non_default_log_location(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze parses logs from non-default location
    :setup:
        1. Add user and perform authentication
        2. Copy logs to alternate location
    :steps:
        1. Run sssctl analyze with --logdir
    :expectedresults:
        1. Analyze succeeds with alternate log location
    :customerscenario: True
    """
    user, pw = setup_debug_sssd(client, provider)
    client.tools.id(f"{user}@test")
    client.ssh(user, pw).connect()
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.sssd.stop()
    client.sssd.clear(config=True, logs=True)
    result = client.sssctl.analyze_request(command="show 1 --pam", logdir="/tmp/copy/")
    assert result.rc == 0, f"analyze failed with non-default logs"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_pam_logs(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze parses PAM authentication requests
    :setup:
        1. Add user and perform SSH login
    :steps:
        1. Run sssctl analyze --pam
    :expectedresults:
        1. Analyze succeeds and shows request ID
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0, f"analyze pam failed (rc={res.rc})"
    assert "CID #1" in res.stdout, f"Expected 'CID #1' in output: {res.stdout}"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2013259)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_tevent_id(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze displays tevent chain IDs
    :setup:
        1. Add user and perform SSH login
    :steps:
        1. Run sssctl analyze --pam
    :expectedresults:
        1. Output contains RID# identifiers
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0, f"analyze failed (rc={res.rc})"
    assert "RID#" in res.stdout, f"Expected 'RID#' in output: {res.stdout}"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=2013260)
@pytest.mark.topology(KnownTopology.IPA)
def test_sssctl__analyze_child_logs(client: Client, provider: GenericProvider):
    """
    :title: "sssctl analyze" to parse child logs
    :description: analyzer request --child argument must search child process logs
    :setup:
        1. Add user
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
    :steps:
        1. Log in as user via ssh
        2. Call sssctl analyze to check logs
        3. Clear cache and restart SSSD
        4. Log in as user via ssh with wrong password
        5. Call sssctl analyze to check child logs
    :expectedresults:
        1. Logged in successfully
        2. Logs contain login related child logs
        3. Successful
        4. Failed to login
        5. Child (krb5) Logs contain info about failed login
    :customerscenario: True
    """
    analyze_output = ""
    provider.user("user1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    with client.ssh("user1", "Secret123"):
        # close immediately, we just need the logs
        pass

    # A different request to SSSD can happen before the login attempt below,
    # making this other request show as CID #1 in the logs, causing this test to fail.
    # Concatenate the first three CID requests to address this.
    for cid in range(1, 4):
        result = client.sssctl.analyze_request(f"show --pam --child {cid}")
        analyze_output += result.stdout

    assert "user1@test" in analyze_output
    assert "SSS_PAM_AUTHENTICATE" in analyze_output

    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    with pytest.raises(SSHAuthenticationError):
        client.ssh("user1", "Wrong").connect()

    # See comment above
    for cid in range(1, 4):
        result = client.sssctl.analyze_request(f"show --pam --child {cid}")
        analyze_output += result.stdout

    assert "Preauthentication failed" in analyze_output, "'Preauthentication failed' was not found!"


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=[2142960, 2142794, 2142961])
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_without_root_privileges(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze works without root privileges
    :setup:
        1. Add user and generate logs
        2. Copy logs with user ownership
    :steps:
        1. Run sssctl analyze as root and as user
    :expectedresults:
        1. Both runs succeed with identical output
    :customerscenario: True
    """
    setup_debug_sssd(client, provider)
    client.tools.id("user1")
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.fs.chown("/tmp/copy", "user1", args=["--recursive"])
    result_root = client.sssctl.analyze_request(command="show 1", logdir="/tmp/copy")
    result_user = client.host.conn.run('su user1 -c "sssctl analyze --logdir /tmp/copy request show 1"')
    assert result_root.rc == 0, f"analyze failed as root"
    assert result_user.rc == 0, f"analyze failed as user"
    assert result_root.stdout == result_user.stdout, "Root and user output mismatch"

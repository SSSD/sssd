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
    client.sssd.common.local()
    client.sssd.dom("test")["wrong_option"] = "true"
    client.sssd.config_apply(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc != 0, "config-check should fail for invalid domain option!"


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
    "pattern,repl,description",
    [
        ("id_provider.*", "id_provider = invalid", "invalid id_provider value"),
        ("id_provider.*", "", "missing id_provider value"),
        ("id_provider", "id_@provider", "invalid character in id_provider"),
        ("domain/local", "domain/local@", "invalid character in domain section"),
        (".sssd.", "[sssdx]", "invalid section name"),
        ("id_provider = ", "id_provider ", "missing equals sign and value"),
        (".nss.", "[nssx", "unclosed bracket in section"),
        (".domain/local.", "domain/local]", "unmatched bracket in domain section"),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__invalid_config_patterns(client: Client, pattern: str, repl: str, description: str):
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
    client.sssd.common.local()
    client.sssd.start()
    conf = re.sub(pattern, repl, client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for {description}: '{pattern}' -> '{repl}'"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__invalid_permissions(client: Client):
    """
    :title: sssctl config-check fails with invalid file permissions
    :setup:
        1. Start with valid SSSD config
        2. Set improper permissions on config file
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()

    client.fs.chmod("0777", "/etc/sssd/sssd.conf")

    result = client.sssctl.config_check()
    assert result.rc != 0, "config-check should fail for invalid permissions"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__missing_config(client: Client):
    """
    :title: sssctl config-check fails with missing config file
    :setup:
        1. Start with valid SSSD config
        2. Remove config file
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Configuration check fails
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()

    client.fs.rm("/etc/sssd/sssd.conf")

    result = client.sssctl.config_check()
    assert result.rc != 0, "config-check should fail for missing config file"


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
    client.sssd.common.local()
    client.sssd.domain["ldap_host_object_class"] = "ipService"
    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc == 0, f"Expected success for ldap_host_object_class in domain section, got {result.stderr}!"


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
    client.sssd.common.local()
    getattr(client.sssd, section)[option] = value
    client.sssd.config_apply(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc != 0, f"config-check should fail for {section}.{option}={value}!"


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
    client.sssd.common.local()
    client.sssd.section("prompting/2fa/sshd")["first_prompt"] = "Enter OTP Token Value:"
    client.sssd.section("prompting/2fa/sshd")["single_prompt"] = "True"
    client.sssd.section("prompting/2fa")["first_prompt"] = "prompt1"
    client.sssd.section("prompting/2fa")["second_prompt"] = "prompt2"
    client.sssd.section("prompting/2fa")["single_prompt"] = "True"
    client.sssd.start(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc == 0, "config-check failed with 2FA!"


@pytest.mark.ticket(bz=1791892)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl_check_with_auto_private_groups_configured_with_subdomains(client: Client):
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
    client.sssd.common.local()
    client.sssd.sssd["domains"] = "example.com"
    client.sssd.subdom("example.com", "child1.example.com")["auto_private_groups"] = "True"
    client.sssd.subdom("example.com", "child2.example.com")["auto_private_groups"] = "False"
    client.sssd.start(check_config=False, debug_level=None)
    result = client.sssctl.config_check()
    assert result.rc == 0, "config-check failed with auto_private_groups!"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_missing_snippet_dir(client: Client):
    """
    :title: sssctl config-check fails for non-default config with missing snippet directory
    :setup:
        1. Copy config to non-default location without snippet directory
    :steps:
        1. Run sssctl config-check with --config
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.config_apply()
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc != 0, "config-check should fail for missing snippet directory!"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_invalid_permissions(client: Client):
    """
    :title: sssctl config-check fails for non-default config with invalid permissions
    :setup:
        1. Copy config to non-default location with invalid permissions
    :steps:
        1. Run sssctl config-check with --config
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.config_apply()
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/sssd.conf", mode="777")

    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc != 0, "config-check should fail for invalid permissions!"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_invalid_option(client: Client):
    """
    :title: sssctl config-check fails for non-default config with invalid option
    :setup:
        1. Configure SSSD with invalid option in non-default config
    :steps:
        1. Run sssctl config-check with --config
    :expectedresults:
        1. Configuration check fails
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.domain["search_base"] = "True"
    client.sssd.config_apply(check_config=False)
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc != 0, "config-check should fail for invalid option!"


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
    client.sssd.common.local()
    client.sssd.config_apply(check_config=False)
    client.fs.mkdir("/tmp/test/")
    client.fs.mkdir("/tmp/test/conf.d", mode="700")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    rc = client.sssctl.config_check(config="/tmp/test/sssd.conf").rc
    assert rc == 0, "config-check failed for valid non-default config!"


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
    client.sssd.common.local()
    client.sssd.start()
    result = client.sssctl.config_check(snippet="/does/not/exist")
    assert result.rc != 0, "config-check should fail for non-existing snippet!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1294670)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_list(client: Client, provider: GenericProvider):
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
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    assert client.tools.getent.group("group1") is None, "Unexpectedly found group 'group1'!"
    assert client.tools.id("user1"), "User 'user1' not in id output!"
    result = client.sssctl.analyze_request("list")
    assert result.rc == 0, "analyze list failed!"
    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    result = client.sssctl.analyze_request("list")
    assert result.rc == 0, "analyze list failed after restart!"


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
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    client.tools.id(f"user1@{provider.domain}")
    client.ssh("user1", "Secret123").connect()
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.sssd.stop()
    client.sssd.clear(config=True, logs=True)
    result = client.sssctl.analyze_request(command="show 1 --pam", logdir="/tmp/copy/")
    assert result.rc == 0, "analyze failed with non-default logs!"


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
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0, f"analyze pam failed (rc={res.rc})!"
    assert "CID #1" in res.stdout, f"Expected 'CID #1' in output: {res.stdout}!"


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
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    client.ssh("user1", "Secret123").connect()
    res = client.sssctl.analyze_request("show 1 --pam")
    assert res.rc == 0, f"analyze failed (rc={res.rc})!"
    assert "RID#" in res.stdout, f"Expected 'RID#' in output: {res.stdout}!"


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
def test_sssctl__analyze_with_logdir_and_non_root_privileges(client: Client, provider: GenericProvider):
    """
    :title: sssctl analyze works with --logdir without root privileges
    :description: |
        Verify that sssctl analyze can process logs from alternate locations
        using --logdir parameter, and works correctly when run by non-root users
        who have read access to the log files.
    :setup:
        1. Add user and generate logs
        2. Copy logs to alternate location and change ownership to non-root user
    :steps:
        1. Run sssctl analyze --logdir as root
        2. Run sssctl analyze --logdir as non-root user
    :expectedresults:
        1. Both runs succeed with identical output
        2. Non-root user can analyze logs when they have read access to them
    :customerscenario: True
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.start()
    client.tools.id("user1")

    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.fs.chown("/tmp/copy", "user1", args=["--recursive"])

    result_root = client.sssctl.analyze_request(command="show 1", logdir="/tmp/copy")

    result_user = client.host.conn.run('su user1 -c "sssctl analyze --logdir /tmp/copy request show 1"')

    assert result_root.rc == 0, "analyze failed as root with --logdir"
    assert result_user.rc == 0, "analyze failed as user with --logdir"
    assert result_root.stdout == result_user.stdout, "Root and user output mismatch with --logdir"


@pytest.mark.parametrize(
    "use_fqdn,case_sensitive",
    [
        (False, True),
        (True, True),
        (True, False),
    ],
    ids=["shortnames", "fqdn", "fqdn_case_insensitive"],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__user_show(client: Client, provider: GenericProvider, use_fqdn: bool, case_sensitive: bool):
    """
    :title: sssctl user-show displays user information
    :setup:
        1. Add users to provider
        2. Configure SSSD with fqdn and case_sensitive options
        3. Start SSSD
        4. Populate cache
    :steps:
        1. Run sssctl user-show for users
        2. Run sssctl user-show for non-existent user
    :expectedresults:
        1. User information is displayed correctly
        2. Command fails for non-existent user
    :customerscenario: True
    """
    provider.user("user1").add()
    provider.user("CamelCaseUser1").add()
    client.sssd.domain["use_fully_qualified_names"] = use_fqdn
    client.sssd.domain["case_sensitive"] = case_sensitive
    client.sssd.start()

    domain_suffix = f"@{provider.domain}" if use_fqdn else ""
    user1_name = f"user1{domain_suffix}"
    cc_user_name = f"CamelCaseUser1{domain_suffix}"

    # Populate cache
    client.tools.getent.passwd(user1_name)
    client.tools.getent.passwd(cc_user_name)

    result = client.sssctl.user_show(user1_name)
    assert result.rc == 0
    assert f"Name: {user1_name}" in result.stdout

    result = client.sssctl.user_show(cc_user_name)
    assert result.rc == 0
    expected_name = cc_user_name if case_sensitive else cc_user_name.lower()
    assert f"Name: {expected_name}" in result.stdout

    # Test case sensitivity for lookups
    lc_user_name = f"camelcaseuser1{domain_suffix}"
    result = client.sssctl.user_show(lc_user_name)
    if case_sensitive:
        assert result.rc != 0
        assert f"User {lc_user_name} is not present in cache" in result.stderr
    else:
        assert result.rc == 0
        assert f"Name: {lc_user_name}" in result.stdout


@pytest.mark.parametrize(
    "use_fqdn,case_sensitive",
    [
        (False, True),
        (True, True),
        (True, False),
    ],
    ids=["shortnames", "fqdn", "fqdn_case_insensitive"],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__group_show(client: Client, provider: GenericProvider, use_fqdn: bool, case_sensitive: bool):
    """
    :title: sssctl group-show displays group information
    :setup:
        1. Add groups and users to provider
        2. Configure SSSD with fqdn and case_sensitive options
        3. Start SSSD
        4. Populate cache
    :steps:
        1. Run sssctl group-show for groups
        2. Run sssctl group-show for non-existent group
    :expectedresults:
        1. Group information is displayed correctly
        2. Command fails for non-existent group
    :customerscenario: True
    """
    provider.user("user1").add()
    provider.user("CamelCaseUser1").add()
    provider.group("group1", members=["user1"]).add()
    provider.group("CamelCaseGroup1", members=["CamelCaseUser1"]).add()
    client.sssd.domain["use_fully_qualified_names"] = use_fqdn
    client.sssd.domain["case_sensitive"] = case_sensitive
    client.sssd.start()

    domain_suffix = f"@{provider.domain}" if use_fqdn else ""
    group1_name = f"group1{domain_suffix}"
    cc_group_name = f"CamelCaseGroup1{domain_suffix}"

    # Populate cache
    client.tools.getent.group(group1_name)
    client.tools.getent.group(cc_group_name)

    result = client.sssctl.group_show(group1_name)
    assert result.rc == 0
    assert f"Name: {group1_name}" in result.stdout

    result = client.sssctl.group_show(cc_group_name)
    assert result.rc == 0
    expected_name = cc_group_name if case_sensitive else cc_group_name.lower()
    assert f"Name: {expected_name}" in result.stdout

    # Test case sensitivity for lookups
    lc_group_name = f"camelcasegroup1{domain_suffix}"
    result = client.sssctl.group_show(lc_group_name)
    if case_sensitive:
        assert result.rc != 0
        assert f"Group {lc_group_name} is not present in cache" in result.stderr
    else:
        assert result.rc == 0
        assert f"Name: {lc_group_name}" in result.stdout


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__netgroup_show(client: Client, provider: GenericProvider):
    """
    :title: sssctl netgroup-show displays netgroup information
    :setup:
        1. Add netgroup to provider
        2. Start SSSD
    :steps:
        1. Run sssctl netgroup-show for a non-cached netgroup
        2. Populate cache by running getent
        3. Run sssctl netgroup-show again
    :expectedresults:
        1. Command fails as netgroup is not in cache
        2. getent succeeds
        3. Command succeeds and displays netgroup information
    :customerscenario: True
    """
    provider.netgroup("netgroup1", nis_triples=[("host", "user", "domain")]).add()
    client.sssd.start()

    result = client.sssctl.netgroup_show("netgroup1")
    assert result.rc != 0

    assert client.tools.getent.netgroup("netgroup1") is not None

    result = client.sssctl.netgroup_show("netgroup1")
    assert result.rc == 0
    assert "Name: netgroup1" in result.stdout


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__debug_level(client: Client, provider: GenericProvider):
    """
    :title: sssctl debug-level sets and gets debug levels
    :setup:
        1. Start SSSD
    :steps:
        1. Set debug level for all components
        2. Get debug level for all components and verify
        3. Set debug level for sssd and verify
        4. Set debug level for nss and verify
        5. Set debug level for domain and verify
        6. Try to get debug level for a non-existent domain
        7. Try to set debug level for a non-existent domain
        8. Try to get debug level for an unreachable service
    :expectedresults:
        1. Command succeeds
        2. Debug levels are set correctly
        3. sssd debug level is set correctly
        4. nss debug level is set correctly
        5. domain debug level is set correctly
        6. Command fails with "Unknown domain"
        7. Command fails
        8. Command fails with "Unreachable service"
    :customerscenario: True
    """
    domain_name = provider.domain
    client.sssd.domain["debug_level"] = "0"  # make sure we start from a known state
    client.sssd.start()

    result = client.sssctl.debug_level("0x00F0")
    assert result.rc == 0

    result = client.sssctl.debug_level()
    assert result.rc == 0
    expected_components = {"sssd", "nss", f"domain/{domain_name}", "domain/implicit_files"}
    lines = result.stdout.strip().splitlines()

    found_components = set()
    for line in lines:
        component, level = line.split()
        found_components.add(component)
        if component in expected_components:
            assert level == "0x00f0"
    assert expected_components.issubset(found_components)

    result = client.sssctl.debug_level("--sssd", "0x0270")
    assert result.rc == 0
    result = client.sssctl.debug_level("--sssd")
    assert result.rc == 0
    assert "sssd 0x0270" in result.stdout

    result = client.sssctl.debug_level("--nss", "0x0370")
    assert result.rc == 0
    result = client.sssctl.debug_level("--nss")
    assert result.rc == 0
    assert "nss 0x0370" in result.stdout

    result = client.sssctl.debug_level(f"--domain={domain_name}", "0x1234")
    assert result.rc == 0
    result = client.sssctl.debug_level(f"--domain={domain_name}")
    assert result.rc == 0
    assert f"domain/{domain_name} 0x1234" in result.stdout

    result = client.sssctl.debug_level("--domain=FAKE")
    assert result.rc != 0
    assert "Unknown domain" in result.stderr

    result = client.sssctl.debug_level("--domain=FAKE", "8")
    assert result.rc != 0
    assert result.stdout.strip() == ""

    # For unreachable service, pac is a good candidate if not using IPA
    result = client.sssctl.debug_level("--pac")
    assert result.rc != 0
    assert "Unreachable service" in result.stderr


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__cache_expire_missing_entry(client: Client):
    """
    :title: sssctl cache-expire fails for non-existent entries
    :setup:
        1. Start SSSD
    :steps:
        1. Run sssctl cache-expire for non-existent user
        2. Run sssctl cache-expire for non-existent group
        3. Run sssctl cache-expire for non-existent user in non-existent domain
        4. Run sssctl cache-expire for non-existent group in non-existent domain
    :expectedresults:
        1. Command fails for all non-existent entries
    :customerscenario: True
    """
    client.sssd.start()

    result = client.host.conn.run("sssctl cache-expire -u non-existing")
    assert result.rc != 0

    result = client.host.conn.run("sssctl cache-expire -g non-existing")
    assert result.rc != 0

    result = client.host.conn.run("sssctl cache-expire -d non-existing -u dummy")
    assert result.rc != 0

    result = client.host.conn.run("sssctl cache-expire -d non-existing -g dummy")
    assert result.rc != 0


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__config_check_snippets_only(client: Client):
    """
    :title: sssctl config-check works with only snippet files
    :setup:
        1. Ensure no main sssd.conf exists
        2. Create a config snippet file
    :steps:
        1. Run sssctl config-check
    :expectedresults:
        1. Command succeeds and prints the parsed config
    :customerscenario: True
    """
    if client.fs.exists("/etc/sssd/sssd.conf"):
        client.fs.rm("/etc/sssd/sssd.conf")
    if client.fs.exists("/etc/sssd/conf.d"):
        client.fs.rm("/etc/sssd/conf.d", recursive=True)
    client.fs.mkdir("/etc/sssd/conf.d", mode=0o700)

    client.fs.write(
        "/etc/sssd/conf.d/test.conf",
        "[sssd]\nservices = nss, pam, ssh\n",
        mode=0o600,
    )

    result = client.sssctl.config_check()
    assert result.rc == 0
    assert "[sssd]" in result.stdout
    assert "services = nss, pam, ssh" in result.stdout

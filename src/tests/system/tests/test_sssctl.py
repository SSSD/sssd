"""
SSSCTL tests.

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import re
import time

import pytest
from pytest_mh.conn.ssh import SSHAuthenticationError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1902280)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__reset_cached_timestamps_to_reflect_changes(client: Client, ldap: LDAP):
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


@pytest.mark.parametrize(
    "test_data,expected",
    [
        # Invalid option name
        (
            {"section": "domain", "domain": "test", "option": "wrong_option", "value": "true"},
            "Attribute 'wrong_option' is not allowed",
        ),
        # Missing domain name
        (
            {"section": "domain", "domain": "", "option": "debug_level", "value": "9"},
            "Section [domain/] is not allowed. Check for typos",
        ),
        # Invalid permission
        ({"permission": "0777"}, "File ownership and permissions check failed"),
        # Missing config
        ({"remove_config": True}, "File /etc/sssd/sssd.conf does not exist"),
    ],
)
@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__config_check_errors(client: Client, test_data: dict, expected: str):
    """
    :title: sssctl config-check detects various configuration errors
    :setup:
        1. Prepare basic SSSD local configuration
        2. Modify the config to introduce specific errors
    :steps:
        1. Apply malformed or incomplete config
        2. Run 'sssctl config-check'
    :expectedresults:
        1. 'sssctl config-check' returns a non-zero code
        2. Relevant error message is printed in stdout/stderr
    :customerscenario: False
    """
    client.sssd.common.local()

    if "remove_config" in test_data:
        client.fs.rm("/etc/sssd/sssd.conf")
    elif "permission" in test_data:
        client.sssd.start()
        client.fs.chmod(test_data["permission"], "/etc/sssd/sssd.conf")
    else:
        # Handle domain section configuration
        domain_section = client.sssd.dom(test_data["domain"]) if test_data["domain"] else client.sssd.dom("")
        domain_section[test_data["option"]] = test_data["value"]
        client.sssd.config_apply(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert expected in (result.stdout or "") + (
        result.stderr or ""
    ), f"Expected error '{expected}' not found in output"


@pytest.mark.parametrize(
    "pattern,repl,expected,output",
    [
        # Invalid semantic in section name
        (
            "id_provider.*",
            "id_provider = invalid",
            "Attribute 'id_provider' in section 'domain/local' has an invalid value: invalid",
            "stdout",
        ),
        ("id_provider.*", "", "Attribute 'id_provider' is missing in section 'domain/local'.", "stdout"),
        ("id_provider", "id_@provider", "Attribute 'id_@provider' is not allowed in section", "stdout"),
        ("domain/local", "domain/local@", "Section [domain/local@] is not allowed", "stdout"),
        (".sssd.", "[sssdx]", "Section [sssdx] is not allowed", "stdout"),
        # Invalid syntax
        ("id_provider = ", "id_provider ", "Equal sign is missing", "stderr"),
        (".nss.", "[nssx", "No closing bracket", "stderr"),
        (".domain/local.", "domain/local]", "Equal sign is missing", "stderr"),
    ],
)
@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_config_semantic_and_syntax(client: Client, pattern: str, repl: str, expected: str, output: str):
    """
    :title: sssctl prints appropriate error message for invalid config
    :setup:
        1. Prepare local SSSD configuration
        2. Apply semantic/syntax errors to config using pattern replacement
    :steps:
        1. Modify sssd.conf with invalid values or structure
        2. Run 'sssctl config-check'
    :expectedresults:
        1. 'sssctl config-check' detects issues and fails
        2. Relevant error messages appear in the correct output stream
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()
    conf = re.sub(pattern, repl, client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config!"
    assert expected in getattr(result, output), "Wrong error message was returned"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_invalid_options_in_two_domains(client: Client):
    """
    :title: Verify typo in option name with multiple domains
    :setup:
        1. Define two SSSD domains with invalid option names
        2. Apply SSSD config without validation
    :steps:
        1. Run 'sssctl config-check'
        2. Check error message
    :expectedresults:
        1. Configuration issues are detected in both domains
        2. Error messages list both domain-specific typos
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.dom("ldap1")["ldap_ri"] = "ldaps://invalid"
    client.sssd.dom("ldap1")["id_provider"] = "ldap"
    client.sssd.dom("ldap2")["ldap_ri"] = "ldaps://invalid"
    client.sssd.dom("ldap2")["id_provider"] = "ldap"
    client.sssd.sssd["domains"] = "ldap1, ldap2"
    client.sssd.config_apply(check_config=False)

    res = client.sssctl.config_check()
    assert res.rc != 0, "Config-check did not detect misconfigured config"
    assert "Issues identified by validators: 2" in res.stdout, "Wrong number of issues found"
    assert "Attribute 'ldap_ri' is not allowed in section 'domain/ldap1'" in res.stdout
    assert "Attribute 'ldap_ri' is not allowed in section 'domain/ldap2'" in res.stdout


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1677994)
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


@pytest.mark.parametrize(
    "section,option,value,expected",
    [
        ("domain", "services", "nss, pam", "Attribute 'services' is not allowed in section 'domain/local'"),
        (
            "sssd",
            "ldap_host_object_class",
            "ipService",
            "Attribute 'ldap_host_object_class' is not allowed in section 'sssd'",
        ),
    ],
)
@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1677994)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_attribute_not_allowed_in_section(
    client: Client, section: str, option: str, value: str, expected: str
):
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
    client.sssd.common.local()
    getattr(client.sssd, section)[option] = value
    client.sssd.config_apply(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config!"
    assert expected in result.stdout, "Wrong error message on stdout!"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1856861)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_enabling_2fa_prompting(client: Client):
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
    client.sssd.common.local()
    client.sssd.section("prompting/2fa/sshd")["first_prompt"] = "Enter OTP Token Value:"
    client.sssd.section("prompting/2fa/sshd")["single_prompt"] = "True"

    client.sssd.section("prompting/2fa")["first_prompt"] = "prompt1"
    client.sssd.section("prompting/2fa")["second_prompt"] = "prompt2"
    client.sssd.section("prompting/2fa")["single_prompt"] = "True"

    client.sssd.start(check_config=False)
    result = client.sssctl.config_check()
    assert result.rc == 0, "Config-check failed"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1791892)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_auto_private_groups_in_child_domains(client: Client):
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
    client.sssd.common.local()
    client.sssd.sssd["domains"] = "td5f4f77.com"
    client.sssd.subdom("td5f4f77.com", "one5f4f77.td5f4f77.com")["auto_private_groups"] = "True"
    client.sssd.subdom("td5f4f77.com", "two5f4f77.td5f4f77.com")["auto_private_groups"] = "False"

    client.sssd.start(check_config=False, debug_level=None)
    result = client.sssctl.config_check()
    assert result.rc == 0, "Config-check failed"


@pytest.mark.parametrize(
    "test_data,expected",
    [
        ({"mkdir": False}, "Directory /tmp/test/conf.d does not exist"),
        ({"permission": "0777"}, "File ownership and permissions check failed"),
        ({"invalid_option": True}, "Attribute 'search_base' is not allowed in section 'domain/local'"),
        ({"mkdir": True, "permission": "0700"}, None),  # Success case
    ],
)
@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_location(client: Client, test_data: dict, expected: str | None):
    """
    :title: sssctl config-check with non-default config locations
    :setup:
        1. Create or modify config in non-standard directory
        2. Optionally introduce config errors or permission issues
    :steps:
        1. Run 'sssctl config-check' using --config option
    :expectedresults:
        1. Valid config passes; invalid ones return correct error
    :customerscenario: True
    """
    client.sssd.common.local()
    if test_data.get("invalid_option"):
        client.sssd.default_domain = "local"
        client.sssd.domain["search_base"] = "True"

    client.sssd.config_apply(check_config=False)
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    if test_data.get("mkdir"):
        client.fs.mkdir("/tmp/test/conf.d", mode=test_data.get("permission", "700"))
    if test_data.get("permission") and not test_data.get("mkdir"):
        client.fs.chmod(test_data["permission"], "/tmp/test/sssd.conf")

    result = client.sssctl.config_check(config="/tmp/test/sssd.conf")

    if expected is None:
        assert result.rc == 0, "Config-check failed"
    else:
        assert result.rc != 0, "Config-check should have failed"
        assert expected in result.stdout, "Wrong error message on stdout"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_non_existing_snippet(client: Client):
    """
    :title: sssctl config-check detects non existing snippet directory
    :setup:
        1. Start SSSD, so default config is autimatically created
    :steps:
        1. Call sssctl config-check with non existing snippet
        2. Check error message
    :expectedresults:
        1. config-check failed
        2. Error message is properly set
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.start()
    result = client.sssctl.config_check(snippet="/does/not/exist")
    assert result.rc != 0, "Config-check successfully finished"
    assert "Directory /does/not/exist does not exist" in result.stdout, "Wrong error message on stdout"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1294670)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_list(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze request list" show captured nss related requests from sssd log
    :setup:
        1. Add user and group
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
    :steps:
        1. Call id user1 and getent group group1
        2. Call sssctl analyze request list, also with -v
        3. Find "getent" and " id" in result
        4. Clear cache
        5. Call getent passwd user
        6. Call sssctl analyze request list, also with -v
        7. Find "CID #1" and "getent" in result
    :expectedresults:
        1. Called successfully, information is stored in logs
        2. Called successfully
        3. Strings found
        4. Cache cleared
        5. Called successfully
        6. Called successfully
        7. Strings found
    :customerscenario: True
    """
    ldap.user("user1").add()
    ldap.group("group1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    assert client.tools.getent.group("group1"), "getent group1 failed"
    assert client.tools.id("user1"), "id user1 failed"

    res = client.sssctl.analyze_request("list")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "getent" in res.stdout, "'getent' not found in analyze list output"
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list output"
    res = client.sssctl.analyze_request("list -v")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "getent" in res.stdout, "'getent' not found in analyze list -v output"
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list -v output"

    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()

    assert client.tools.getent.passwd("user1")
    res = client.sssctl.analyze_request("list")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "CID #1" in res.stdout, "CID #1 not found in analyze list -v output"
    assert "getent" in res.stdout, "getent not found in analyze list -v output"
    res = client.sssctl.analyze_request("list -v")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "CID #1" in res.stdout, "CID #1 not found in analyze list -v output"
    assert "getent" in res.stdout, "getent not found in analyze list -v output"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1294670, gh=6298)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_non_default_log_location(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze" parse sssd logs from non-default location when SSSD is not running
    :setup:
        1. Add user
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
    :steps:
        1. Call id user1 and login user via ssh
        2. Copy sssd logs to diferent location
        3. Stop sssd and remove config, logs and cache
        4. sssctl analyze --logdir PATH parse logs from PATH location
    :expectedresults:
        1. Information is stored in logs
        2. Copied successfully
        3. Stopped and cleared successfully
        4. Output is correct
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    assert client.tools.id("user1@test"), "call 'id user1@test' failed"
    client.ssh("user1", "Secret123").connect()

    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.sssd.stop()
    client.sssd.clear(config=True, logs=True)

    res = client.sssctl.analyze_request(command="show 1 --pam", logdir="/tmp/copy/")
    assert "SSS_PAM_AUTHENTICATE" in res.stdout
    assert "SSS_PAM_ACCT_MGMT" in res.stdout
    assert "SSS_PAM_SETCRED" in res.stdout

    res = client.sssctl.analyze_request(command="list", logdir="/tmp/copy/")
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list output"
    assert "sshd" in res.stdout or "coreutils" in res.stdout, "sshd or coreutils not found in output"

    res = client.sssctl.analyze_request(command="list -v", logdir="/tmp/copy/")
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list -v output"
    assert "sshd" in res.stdout or "coreutils" in res.stdout, "sshd or coreutils not found in output"


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"pam": True}, ["SSS_PAM_AUTHENTICATE", "SSS_PAM_ACCT_MGMT", "SSS_PAM_SETCRED"]),
        ({"child": True}, ["user1@test"]),
    ],
)
@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=[1294670, 2013259, 2013260])
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_logs(client: Client, ldap: LDAP, options: dict, expected: list[str]):
    """
    :title: "sssctl analyze" parses different log types
    :setup:
        1. Add user to LDAP
        2. Enable debugging for relevant services
        3. Connect user via SSH
    :steps:
        1. Run 'sssctl analyze' with relevant options (--pam, --child)
    :expectedresults:
        1. Expected entries are present in output
    :customerscenario: True
    """
    ldap.user("user1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    client.ssh("user1", "Secret123").connect()

    command = "show 1"
    if options.get("pam"):
        command += " --pam"
    if options.get("child"):
        command += " --child"

    result = client.sssctl.analyze_request(command)
    assert result.rc == 0
    for item in expected:
        assert item in result.stdout, f"{item} was not found in the output"
    if options.get("pam"):
        assert "RID#" in result.stdout, "RID# was not found in the output"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=2013260)
@pytest.mark.topology(KnownTopology.IPA)
def test_sssctl__analyze_child_logs(client: Client, ipa: IPA):
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
    ipa.user("user1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    client.ssh("user1", "Secret123").connect()

    result = client.sssctl.analyze_request("show --pam --child 1")
    assert result.rc == 0
    assert "user1@test" in result.stdout
    assert "SSS_PAM_AUTHENTICATE" in result.stdout

    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    time.sleep(5)

    with pytest.raises(SSHAuthenticationError):
        client.ssh("user1", "Wrong").connect()
    result = client.sssctl.analyze_request("show --pam --child 1")
    assert "Preauthentication failed" in result.stdout, "'Preauthentication failed' was not found!"


@pytest.mark.importance("medium")
@pytest.mark.tools
@pytest.mark.ticket(bz=[2142960, 2142794, 2142961])
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_without_root_privileges(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze" command does not require "root" privileges
    :setup:
        1. Add user with proper password
        2. Start SSSD
        3. Fetch information about user
        4. Copy logs to different location
        5. Change ownership of copied file to user
    :steps:
        1. Call "sssctl analyze --logdir /tmp/copy request show 1" as root
        2. Call "sssctl analyze --logdir /tmp/copy request show 1" as user
        3. Check that outputs match
        4. Username is stored in outputs
    :expectedresults:
        1. Called successfully
        2. Called successfully
        3. Outputs are the same
        4. Username is stored in outputs
    :customerscenario: True
    """
    ldap.user("user1").add(password="Secret123")
    client.sssd.start()
    client.tools.id("user1")
    client.fs.copy("/var/log/sssd", "/tmp/copy/")
    client.fs.chown("/tmp/copy", "user1", args=["--recursive"])

    result_root = client.sssctl.analyze_request(command="show 1", logdir="/tmp/copy")
<<<<<<< HEAD
    result_user = client.host.conn.run('su user1 -c "sssctl analyze --logdir /tmp/copy request show 1"')
=======
    result_user = client.ssh("user1", "Secret123").run("sssctl analyze --logdir " "/tmp/copy request show 1")

>>>>>>> 35b71bb21 (Tests: Refactor sssctl tests: consolidate and fix config-check)
    assert result_root.rc == 0, "sssctl analyze call failed as root"
    assert result_user.rc == 0, "sssctl analyze call failed as user1"
    assert result_root.stdout == result_user.stdout, "the outputs are different"
    assert "user1" in result_user.stdout, "user1 is not in the outputs"

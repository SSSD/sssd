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
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


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
        assert cmd.rc == 0, "Command call failed!"
        assert "Cache entry expiration time: Never" in cmd.stdout, "Wrong output!"


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
        assert client.tools.getent.passwd(user, service="sss") is not None, f"{user} doesn't exist"
        cmd = client.sssctl.user_show(user=user)
        assert cmd.rc == 0, "Command call failed!"
        assert "Cache entry creation date" in cmd.stdout, "Wrong output!"


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
    assert res1 is not None, f"{res1} has not been found!"
    assert "user1" in res1.members, "user1 has not been found!"

    ldap.group("group1", rfc2307bis=True).remove_member(ldap.user("user1"))
    client.sssctl.cache_expire(everything=True)

    res1 = client.tools.getent.group("group1")
    assert res1 is not None, f"{res1} has not been found!"
    assert "user1" not in res1.members, f"User 'user1' should not have been found!"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_missing_domain_name(client: Client):
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

    with pytest.raises(ProcessError) as ex:
        client.sssd.start(raise_on_error=True, check_config=True)

    assert ex.match(r"Section \[domain\/\] is not allowed. Check for typos.*"), "Wrong error message was returned"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize(
    "contents,expected",
    [
        ("[domain/local]\ninvalid_option = True", "Attribute 'invalid_option' is not allowed"),
        ("[invalid/local]\ninvalid_option = True", "Section [invalid/local] is not allowed"),
    ],
)
def test_sssctl__check_invalid_option_name_in_snippet(client: Client, contents: str, expected: str):
    """
    :title: sssctl config-check validates configuration snippet
    :setup:
        1. Create a config snippet with an invalid option
    :steps:
        1. Check the configuration using sssctl
    :expectedresults:
        1. The config check fails with the appropriate output
    :customerscenario: True
    """
    client.sssd.common.local()
    client.fs.write("/etc/sssd/conf.d/01_snippet.conf", contents, mode="640")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config snippet"
    assert expected in result.stdout, "Wrong error message was returned"


@pytest.mark.parametrize(
    "pattern,repl,expected",
    [
        ("id_provider = ", "id_provider ", ("Equal sign is missing", "stderr")),
        pytest.param(
            "id_provider.*",
            "id_provider = invalid",
            ("Attribute 'id_provider' in section 'domain/local' has an invalid value: invalid", "stdout"),
            marks=[pytest.mark.ticket(bz=2100789), pytest.mark.importance("high")],
        ),
        pytest.param(
            "id_provider.*",
            "",
            ("Attribute 'id_provider' is missing in section 'domain/local'.", "stdout"),
            marks=[pytest.mark.ticket(bz=2100789), pytest.mark.importance("high")],
        ),
        ("id_provider", "id_@provider", ("Attribute 'id_@provider' is not allowed in section", "stdout")),
        ("domain/", "d$main/", ("Section [d$main/local] is not allowed", "stdout")),
        ("domain/local", "domain/local@", ("Section [domain/local@] is not allowed", "stdout")),
        ("domain/local", "domainlocal", ("Section [domainlocal] is not allowed", "stdout")),
        (".sssd.", "[sssdx]", ("Section [sssdx] is not allowed", "stdout")),
        (".nss.", "[nssx", ("No closing bracket", "stderr")),
        (".domain/local.", "domain/local]", ("Equal sign is missing", "stderr")),
    ],
)
@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_invalid_section_name(client: Client, pattern: str, repl: str, expected: tuple[str, str]):
    """
    :title: sssctl prints appropriate error message with invalid configurations
    :setup:
        1. Start SSSD
        2. Edit sssd.conf with invalid value
    :steps:
        1. Validate configuration file using sssctl config-check
    :expectedresults:
        1. sssctl configuration check fails with the correct output
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()
    conf = re.sub(pattern, repl, client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config!"
    assert expected[0] in getattr(result, expected[1]), "Wrong error message on stderr!"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_invalid_options_in_two_domains(client: Client):
    """
    :title: Verify typo in option name with multiple domains in default configuration file
    :setup:
        1. Configure two ldap domains
        2. Make typo in both domains
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error
        2. Error messages are properly set
    :customerscenario: False
    : with other invalid option tests?
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
    assert "Issues identified by validators: 2" in res.stdout, "Wrong number of issues found by validators"
    assert "Attribute 'ldap_ri' is not allowed in section 'domain/ldap1'" in res.stdout, "Wrong error message"
    assert "Attribute 'ldap_ri' is not allowed in section 'domain/ldap2'" in res.stdout, "Wrong error message"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_config_does_not_exist(client: Client):
    """
    :title: sssctl detects missing config
    :setup:
        1. Start SSSD, so default config is automatically created
        2. Remove config
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()
    client.fs.rm("/etc/sssd/sssd.conf")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "File /etc/sssd/sssd.conf does not exist" in result.stdout, "Wrong error message on stdout!"


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
    assert result.rc == 0, "Config-check failed!"


@pytest.mark.importance("high")
@pytest.mark.tools
@pytest.mark.ticket(bz=1677994)
@pytest.mark.topology(KnownTopology.Client)
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
def test_sssctl__check_attribute_not_allowed_in_sssd(
    client: Client, section: str, option: str, value: str, expected: str
):
    """
    :title: sssctl config-check validates attributes in specific sections
    :setup:
        1. Add an invalid option to a section in the configuration and start SSSD
    :steps:
        1. Check the configuration using sssctl
    :expectedresults:
        1. The config check succeed with the warning in the output
    :customerscenario: True
    """
    client.sssd.default_domain = "local"
    client.sssd.common.local()
    getattr(client.sssd, section)[option] = value
    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config!"
    assert expected in result.stdout, "Wrong error message on stdout!"


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
    assert result.rc == 0, "Config-check failed!"


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
    assert result.rc == 0, "Config-check failed!"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize(
    "option,default_conf_mode,dstpath,config,snippet,expected",
    [
        ("enabled", "0600", ("/tmp/test/", None), None, "/does/not/exist", "Directory /does/not/exist does not exist"),
        (
            "enabled",
            "0600",
            ("/tmp/test/", None),
            "/tmp/test/sssd.conf",
            None,
            "Directory /tmp/test/conf.d does not exist",
        ),
        (
            "enabled",
            "0600",
            ("/tmp/test/sssd.conf", "777"),
            "/tmp/test/sssd.conf",
            None,
            "File ownership and permissions check failed",
        ),
        ("enabled", "0777", ("/tmp/test/", None), None, None, "File ownership and permissions check failed"),
        (
            "search_base",
            "0600",
            ("/tmp/test/", None),
            "/tmp/test/sssd.conf",
            None,
            "Attribute 'search_base' is not allowed in section 'domain/local'",
        ),
    ],
)
def test_sssctl__check_config_location_permissions(
    client: Client,
    option: str,
    default_conf_mode: str,
    dstpath: tuple[str, str | None],
    config: str | None,
    snippet: str | None,
    expected: str,
):
    """
    :title: sssctl config-checks validates configuration file path and permissions
    :setup:
        1. Copy the configuration to a new path with different permissions
    :steps:
        1. sssctl validates the copy of the configuration
    :expectedresults:
        1. sssctl configuration check fails with the correct output
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.domain[option] = "true"
    client.sssd.config_apply(check_config=False)

    client.fs.mkdir("/tmp/test/")
    client.fs.chmod(default_conf_mode, "/etc/sssd/sssd.conf")
    client.fs.copy("/etc/sssd/sssd.conf", dstpath[0], mode=dstpath[1])

    result = client.sssctl.config_check(config=config, snippet=snippet)
    assert result.rc != 0, "Config-check successfully finished!"
    assert expected in result.stdout, "Wrong error message on stdout!"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_non_default_config_location_with_snippet_directory(client: Client):
    """
    :title: sssctl config-check does not complain about missing snippet directory after adding with proper permission
    :setup:
        1. Copy sssd.conf file to different directory and create conf.d directory
    :steps:
        1. Call sssctl config-check on that different directory
        2. Check error message
    :expectedresults:
        1. config-check failed
        2. Error message is properly set
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.config_apply(check_config=False)

    client.fs.mkdir("/tmp/test/")
    client.fs.mkdir("/tmp/test/conf.d", mode="700")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    result = client.sssctl.config_check(config="/tmp/test/sssd.conf")
    assert result.rc == 0, "Config-check failed!"
    assert "Directory /tmp/test/conf.d does not exist" not in result.stdout, "Wrong error message on stdout!"


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

    assert client.tools.getent.passwd("user1"), "getent passwd user1 failed"
    res = client.sssctl.analyze_request("list")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "CID #1" in res.stdout, "CID #1 not found in analyze list -v output"
    assert "getent" in res.stdout, "getent not found in analyze list -v output"
    res = client.sssctl.analyze_request("list -v")
    assert res.rc == 0, "sssctl analyze call failed"
    assert "CID #1" in res.stdout, "CID #1 not found in analyze list -v output"
    assert "getent" in res.stdout, "getent not found in analyze list -v output"


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
    assert "SSS_PAM_AUTHENTICATE" in res.stdout, "SSS_PAM_AUTHENTICATE is not in 'show 1 --pam'"
    assert "SSS_PAM_ACCT_MGMT" in res.stdout, "SSS_PAM_ACCT_MGMT is not in 'show 1 --pam'"
    assert "SSS_PAM_SETCRED" in res.stdout, "SSS_PAM_SETCRED is not in 'show 1 --pam'"

    res = client.sssctl.analyze_request(command="list", logdir="/tmp/copy/")
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list output"
    assert "sshd" in res.stdout or "coreutils" in res.stdout, "sshd or coreutils not found in output"

    res = client.sssctl.analyze_request(command="list -v", logdir="/tmp/copy/")
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list -v output"
    assert "sshd" in res.stdout or "coreutils" in res.stdout, "sshd or coreutils not found in output"


@pytest.mark.tools
@pytest.mark.ticket(bz=1294670)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_pam_logs(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze" to parse pam authentication requests from logs
    :setup:
        1. Add user
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
        4. Log in as user via ssh
    :steps:
        1. sssctl analyze with --pam option
        2. Result of command is login related
    :expectedresults:
        1. Called successfully
        2. Output is login related
    :customerscenario: True
    """
    ldap.user("user1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.start()

    client.ssh("user1", "Secret123").connect()

    result = client.sssctl.analyze_request("show 1 --pam")
    assert result.rc == 0, "Command call failed!"
    assert "CID #1" in result.stdout, "CID #1 is not in 'show 1 --pam'"

    assert "SSS_PAM_AUTHENTICATE" in result.stdout, "SSS_PAM_AUTHENTICATE is not in 'show 1 --pam'"
    assert "SSS_PAM_ACCT_MGMT" in result.stdout, "SSS_PAM_ACCT_MGMT is not in 'show 1 --pam'"
    assert "SSS_PAM_SETCRED" in result.stdout, "SSS_PAM_SETCRED is not in 'show 1 --pam'"


@pytest.mark.tools
@pytest.mark.ticket(bz=2013259)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl__analyze_tevent_id(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze" to parse tevent chain IDs from logs
    :setup:
        1. Add user
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
        4. Log in as user via ssh
    :steps:
        1. Call sssctl analyze request show 1 --pam
        2. Confirm tevent chain IDs(RID) is showing in logs
    :expectedresults:
        1. Called successfully
        2. Output is correct
    :customerscenario: True
    """
    ldap.user("user1").add()
    client.sssd.nss["debug_level"] = "9"
    client.sssd.pam["debug_level"] = "9"
    client.sssd.domain["debug_level"] = "9"
    client.sssd.start()

    client.ssh("user1", "Secret123").connect()

    result = client.sssctl.analyze_request("show 1 --pam")
    assert result.rc == 0, "Command call failed!"
    assert "RID#" in result.stdout, "RID# was not found in the output"
    assert "user1@test" in result.stdout, "user1@test was not found in the output"


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
    assert result.rc == 0, "Command call failed!"
    assert "user1@test" in result.stdout, "user1@test was not found!"
    assert "SSS_PAM_AUTHENTICATE" in result.stdout, "SSS_PAM_AUTHENTICATE is not in 'show --pam --child 1'"

    client.sssd.stop()
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.start()
    time.sleep(5)

    with pytest.raises(SSHAuthenticationError):
        client.ssh("user1", "Wrong").connect()
    result = client.sssctl.analyze_request("show --pam --child 1")
    assert "Preauthentication failed" in result.stdout, "'Preauthentication failed' was not found!"


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
    result_user = client.ssh("user1", "Secret123").run("sssctl analyze --logdir /tmp/copy request show 1")
    assert result_root.rc == 0, "sssctl analyze call failed as root"
    assert result_user.rc == 0, "sssctl analyze call failed as user1"
    assert result_root.stdout == result_user.stdout, "the outputs are different"
    assert "user1" in result_user.stdout, "user1 is not in the outputs"

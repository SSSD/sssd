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
        2. Apply config
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
    client.sssd.config_apply(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config, when SSSD is running"
    assert "Attribute 'wrong_option' is not allowed" in result.stdout, "Wrong error message was returned"


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


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_invalid_option_name_in_snippet(client: Client):
    """
    :title: sssctl config-check detects invalid option name in snippet
    :setup:
        1. Create new conf snippet with invalid option name
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config snippet
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.fs.write("/etc/sssd/conf.d/01_snippet.conf", "[domain/local]\ninvalid_option = True", mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config snippet"
    assert "Attribute 'invalid_option' is not allowed" in result.stdout, "Wrong error message was returned"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_invalid_domain_name_in_snippet(client: Client):
    """
    :title: sssctl config-check detects invalid domain name in snippet
    :setup:
        1. Create new conf snippet with invalid domain name
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config snippet
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.fs.write("/etc/sssd/conf.d/01_snippet.conf", "[invalid/local]\ninvalid_option = True", mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config snippet"
    assert "Section [invalid/local] is not allowed" in result.stdout, "Wrong error message was returned"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__missing_equal_sign(client: Client):
    """
    :title: sssctl config-check detects missing equals sign
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file so "=" is missing
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error
        2. Error messages are properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.start()
    conf = re.sub("id_provider = ", "id_provider ", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Equal sign is missing" in result.stderr, "Wrong error message on stderr"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__special_character_option_name(client: Client):
    """
    :title: option name contains special character
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that it contains special character
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
    conf = re.sub("id_provider", "id_@provider", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Attribute 'id_@provider' is not allowed in section" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__special_character_section_name(client: Client):
    """
    :title: section name contains special character
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that it contains special character
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
    conf = re.sub("domain/", "d$main/", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [d$main/local] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__special_character_domain_name(client: Client):
    """
    :title: domain name contains special character
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that it contains special character
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
    conf = re.sub("domain/local", "domain/local@", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [domain/local@] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__forward_slash_missing(client: Client):
    """
    :title: Forward slash is not present between domain name and section name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that forward slash is missing in section name
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
    conf = re.sub("domain/local", "domainlocal", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [domainlocal] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__sssd_section_name_typo(client: Client):
    """
    :title: Typo in sssd section name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that there is typo in sssd section name
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
    conf = re.sub(".sssd.", "[sssdx]", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [sssdx] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__pam_section_name_typo(client: Client):
    """
    :title: Typo in pam section name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that there is typo in sssd section name
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
    conf = re.sub(".pam.", "[pamx]", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [pamx] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__nss_section_name_typo(client: Client):
    """
    :title: Typo in nss section name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that there is typo in sssd section name
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
    conf = re.sub(".nss.", "[nssx]", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Section [nssx] is not allowed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__verify_permission(client: Client):
    """
    :title: Verify the permission of default configuration file
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Change permission of default config file
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
    client.fs.chmod("0777", "/etc/sssd/sssd.conf")
    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "File ownership and permissions check failed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__verify_missing_closing_bracket(client: Client):
    """
    :title: Missing closing bracket in sssd section name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that there is missing closing bracket
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
    conf = re.sub(".nss.", "[nssx", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "No closing bracket" in result.stderr, "Wrong error message on stderr"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__verify_missing_opening_bracket(client: Client):
    """
    :title: Missing opening bracket in domain name
    :setup:
        1. Start SSSD, so default config is autimatically created
        2. Edit config file in a way that there is missing opening bracket
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
    conf = re.sub(".domain/local.", "domain/local]", client.fs.read("/etc/sssd/sssd.conf"))
    client.fs.write("/etc/sssd/sssd.conf", conf, mode="600")

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert "Equal sign is missing" in result.stderr, "Wrong error message on stderr"
    assert "Failed to parse configuration" in result.stderr, "Wrong error message on stderr"


@pytest.mark.tools
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__verify_typo_in_config_with_two_domains(client: Client):
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
def test_sssctl__config_does_not_exist(client: Client):
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
    assert "File /etc/sssd/sssd.conf does not exist" in result.stdout, "Wrong error message on stdout"


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


@pytest.mark.tools
@pytest.mark.ticket(bz=1677994)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__check_ldap_host_object_class_in_sssd(client: Client):
    """
    :title: sssctl config-check do not allow ldap_host_object_class in sssd section
    :setup:
        1. Add ldap_host_object_class to sssd section
        2. Start SSSD
    :steps:
        1. Call sssctl config-check
    :expectedresults:
        1. config-check succeed
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.sssd["ldap_host_object_class"] = "ipService"
    client.sssd.start(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert (
        "Attribute 'ldap_host_object_class' is not allowed in section 'sssd'" in result.stdout
    ), "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.ticket(bz=1856861)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__enabling_2FA(client: Client):
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


@pytest.mark.tools
@pytest.mark.ticket(bz=1791892)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__auto_private_groups_in_child_domain(client: Client):
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


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_location_snippet_directory(client: Client):
    """
    :title: sssctl config-check complains about non existing snippet directory when config is non default
    :setup:
        1. Copy sssd.conf file to different directory
    :steps:
        1. Call sssctl config-check on that different directory
        2. Check error message
    :expectedresults:
        1. config-check failed
        2. Error message is properly set
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.config_apply()
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    result = client.sssctl.config_check(config="/tmp/test/sssd.conf")
    assert result.rc != 0, "Config-check successfully finished"
    assert "Directory /tmp/test/conf.d does not exist" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_location_permission(client: Client):
    """
    :title: sssctl config-check complains about proper permission when config is non default
    :setup:
        1. Copy sssd.conf file to different directory and set it wrong permission
    :steps:
        1. Call sssctl config-check on that different directory
        2. Check error message
    :expectedresults:
        1. config-check failed
        2. Error message is properly set
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.config_apply()
    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/sssd.conf", mode="777")

    result = client.sssctl.config_check(config="/tmp/test/sssd.conf")
    assert result.rc != 0, "Config-check successfully finished"
    assert "File ownership and permissions check failed" in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_location_option_name_typo(client: Client):
    """
    :title: sssctl config-check detects typo in option name when config is non default
    :setup:
        1. Copy sssd.conf file to different directory and mistype option name
    :steps:
        1. Call sssctl config-check on that different directory
        2. Check error message
    :expectedresults:
        1. config-check failed
        2. Error message is properly set
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.domain["search_base"] = "True"
    client.sssd.config_apply(check_config=False)

    client.fs.mkdir("/tmp/test/")
    client.fs.copy("/etc/sssd/sssd.conf", "/tmp/test/")

    result = client.sssctl.config_check(config="/tmp/test/sssd.conf")
    assert result.rc != 0, "Config-check successfully finished"
    assert (
        "Attribute 'search_base' is not allowed in section 'domain/local'" in result.stdout
    ), "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_default_config_location_snippet_is_present(client: Client):
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
    assert result.rc == 0, "Config-check failed"
    assert "Directory /tmp/test/conf.d does not exist" not in result.stdout, "Wrong error message on stdout"


@pytest.mark.tools
@pytest.mark.ticket(bz=1723273)
@pytest.mark.topology(KnownTopology.Client)
def test_sssctl__non_existing_snippet(client: Client):
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

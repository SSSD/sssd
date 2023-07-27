"""
sssctl config-check Test Cases

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import re

import pytest
from pytest_mh.ssh import SSHProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Client)
def test_sssctl_config_check__typo_option_name(client: Client):
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


@pytest.mark.topology(KnownTopology.Client)
def test_sssctl_config_check__typo_domain_name(client: Client):
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


@pytest.mark.topology(KnownTopology.Client)
def test_sssctl_config_check__misplaced_option(client: Client):
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


@pytest.mark.topology(KnownTopology.Client)
def test_sssctl_config_check__typo_option_value(client: Client):
    """
    :title: sssctl config-check detects incorrect value
    :setup:
        1. In local domain set "id_provider" to wrong value
        2. Apply config without config check
    :steps:
        1. Call sssctl config-check
        2. Check error message
    :expectedresults:
        1. config-check detects an error in config
        2. Error message is properly set
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.dom("local")["id_provider"] = "wrong value"
    client.sssd.config_apply(check_config=False)

    result = client.sssctl.config_check()
    assert result.rc != 0, "Config-check did not detect misconfigured config"
    assert (
        "Attribute 'id_provider' in section 'domain/local' has an invalid value: wrong value" in result.stdout_lines[1]
    )

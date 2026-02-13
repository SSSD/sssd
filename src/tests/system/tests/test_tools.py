"""
Tools Tests.

Tests pertaining to command line tools, some tools will have their own file.

* sssctl: test_sssctl.py
* sss_cache
* sss_obfuscate
* sss_seed
* sss_debuglevel
* sss_override: sss_override.py
* sss_ssh_authorizedkeys
* sss_ssh_knownhostsproxy

:requirement: Tools
"""

from __future__ import annotations

import pytest
from pytest_mh.conn import ProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1661182)
@pytest.mark.topology(KnownTopology.Client)
def test_tools__sss_cache_expired_does_not_print_unrelated_message(client: Client):
    """
    :title: Usermod command does not print unrelated sss_cache messages
    :setup:
        1. Configure SSSD without any domain
        2. Set to sssd section "enable_files_domain" to "false"
        3. Create local user
    :steps:
        1. Restart SSSD
        2. Modify existing local user
        3. Expire cache with specific options
    :expectedresults:
        1. Error is raised, SSSD is not running
        2. Modified successfully
        3. Output did not contain wrong messages
    :customerscenario: True
    """
    client.sssd.sssd["enable_files_domain"] = "false"
    client.local.user("user1").add()

    with pytest.raises(ProcessError):
        client.sssd.restart()

    res = client.host.conn.run("usermod -a -G wheel user1")
    assert (
        "No domains configured, fatal error!" not in res.stdout
    ), "'No domains configured, fatal error!' printed to stdout!"

    for cmd in ("sss_cache -U", "sss_cache -G", "sss_cache -E", "sss_cache --user=nonexisting"):
        res = client.host.conn.run(cmd)
        assert (
            "No domains configured, fatal error!" not in res.stdout
        ), "'No domains configured, fatal error!' printed to stdout!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.ticket(gh=7664)
@pytest.mark.parametrize(
    "host",
    [("sssd.io", True), ("1.1.1.1", True), ("client.test", True), ("asdf.test", False), ("super.bad.hostname", False)],
    ids=["sssd.io", "1.1.1.1", "client.test", "asdf.test", "super.bad.hostname"],
)
def test_tools__sss_ssh_knownhosts_resolves_hostnames_and_ips(client: Client, host: tuple[str, bool]):
    """
    :title: sss_ssh_knownhosts resolution of hostnames and IP addresses.
    :setup:
    :steps:
        1. Look up parameterized hosts using sss_ssh_knownhosts
    :expectedresults:
        1. Host is found or not found without errors
    :customerscenario: True
    """
    result = client.host.conn.run(f"sss_ssh_knownhosts --debug=5 {host[0]}")
    assert result is not None, "sss_ssh_knownhosts did not run properly!"
    assert result.stderr_lines is not None, "sss_ssh_knownhosts did not print any debug output!"

    _result = "\n".join(result.stderr_lines)
    _search_value = "getaddrinfo() failed (-2): Name or service not known"

    if host[1]:
        assert _search_value not in _result, f"Looking up {host[0]} should have succeeded!"
    else:
        assert _search_value in _result, f"Looking up {host[0]} should not have succeeded!"

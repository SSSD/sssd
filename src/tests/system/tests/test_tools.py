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
from pytest_mh.ssh import SSHProcessError
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

    with pytest.raises(SSHProcessError):
        client.sssd.restart()

    res = client.host.ssh.run("usermod -a -G wheel user1")
    assert (
        "No domains configured, fatal error!" not in res.stdout
    ), "'No domains configured, fatal error!' printed to stdout!"

    for cmd in ("sss_cache -U", "sss_cache -G", "sss_cache -E", "sss_cache --user=nonexisting"):
        res = client.host.ssh.run(cmd)
        assert (
            "No domains configured, fatal error!" not in res.stdout
        ), "'No domains configured, fatal error!' printed to stdout!"

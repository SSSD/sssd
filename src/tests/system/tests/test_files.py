"""
Files Provider Test Cases

The files provider allows SSSD to use system users to authenticate.
This feature has been removed in SSSD 2.9.0 for the proxy provider.

:requirement: IDM-SSSD-REQ :: SSSD is default for local resolution
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__get_entry_using_sss_service_should_not_work_looking_for_root(client: Client):
    """
    :title: Get entry using sss service should not work looking for root
    :setup:
        1. Configure SSSD with files provider
        2. Start SSSD
    :steps:
        1. Lookup root user using sss service
        2. Lookup root user without the sss service
    :expectedresults:
        1. The root user is not found
        2. The root user is found
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    assert client.tools.getent.passwd("root", service="sss") is None, "Root user is found!"
    assert client.tools.getent.passwd("root"), "Root is not found!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_user(client: Client):
    """
    :title: Lookup user
    :setup:
        1. Create user
        2. Configure SSSD with files provider
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Check results
    :expectedresults:
        1. User is found
        2. The uid matches
    :customerscenario: False
    """
    client.local.user("user1").add(uid=10001)
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.uid == 10001, "UID does not match!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__enumeration_should_not_work(client: Client):
    """
    :title: Enumeration should not work
    :description: Enumeration pulls down the directory data and stores it locally.
    Running an unspecified getent will return all users or groups.
    :setup:
        1. Configure SSSD with files provider
        2. Start SSSD
    :steps:
        1. Run getent with nothing specified
    :expectedresults:
        1. Nothing found
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    assert not client.host.ssh.run("getent passwd -s sss").stdout, "Entries found!"


@pytest.mark.importance("low")
@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_returns_the_latest_data(client: Client):
    """
    :title: Looking up a user returns the latest data
    :setup:
        1. Create user and specify home directory
        2. Configure SSSD with files provider
        3. Start SSSD
    :steps:
        1. Lookup user
        2. Check results
        3. Change user's home directory
        4. Lookup user again
        5. Check results
    :expectedresults:
        1. User is found
        2. The homedir matches
        3. Home directory is changed
        4. User is found
        5. Home directory reflects the new value
    :customerscenario: False
    """
    client.local.user("user1").add(password="Secret123", home="/home/user1-tmp")
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.home == "/home/user1-tmp", "User's homedir is not correct!"

    client.local.user("user1").modify(home="/home/user1")

    time.sleep(1)
    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "User not found!"
    assert result.home == "/home/user1", "User's homedir is not correct!"

"""
SSSD File Provider Test Case

:requirement: IDM-SSSD-REQ :: SSSD is default for local resolution
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_root(client: Client):
    """
    :title: Getent call doesnt work on root, when service specified as "sss"
    :setup:
        1. Enable files domain
        2. Start SSSD
    :steps:
        1. getent passwd -s sss root
    :expectedresults:
        1. Call failed
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("root", service="sss")
    assert result is None, "Getent call was successful, which is not expected"


@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_user(client: Client):
    """
    :title: Simple getent call
    :setup:
        1. Add local user "user1"
        2. Enable files domain
        3. Start SSSD
    :steps:
        1. getent passwd -s sss user1
        2. Check uid of result
    :expectedresults:
        1. Call was successful
        2. Uid is correct
    :customerscenario: False
    """
    client.local.user("user1").add(uid=10001)
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None, "Getent failed"
    assert result.uid == 10001, "Uid is not correct"


@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_should_not_enumerate_users(client: Client):
    """
    :title: Files provider should not enumerate
    :setup:
        1. Enable files domain
        2. Start SSSD
    :steps:
        1. getent passwd -s sss without specified user
    :expectedresults:
        1. Output is empty
    :customerscenario: False
    """
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.host.ssh.run("getent passwd -s sss")
    assert not result.stdout


@pytest.mark.builtwith("files-provider")
@pytest.mark.topology(KnownTopology.Client)
def test_files__lookup_user_shows_updated_user_info(client: Client):
    """
    :title: User have his homedir updated, after passwd
    :setup:
        1. Add local user "user1" with specified homedir
        2. Enable files domain
        3. Start SSSD
    :steps:
        1. getent passwd -s sss user1
        2. Check that homedir is correct
        3. Modify user1's homedir
        4. Wait for changes to be propagated
        5. Check that homedir is correct
    :expectedresults:
        1. Call is successful
        2. homedir is correct
        3. homedir modified successfully
        4. Slept well
        5. homedir is updated correctly
    :customerscenario: False
    """
    client.local.user("user1").add(password="Secret123", home="/home/user1-tmp")
    client.sssd.sssd["enable_files_domain"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None
    assert result.home == "/home/user1-tmp"

    client.local.user("user1").modify(home="/home/user1")

    time.sleep(1)
    result = client.tools.getent.passwd("user1", service="sss")
    assert result is not None
    assert result.home == "/home/user1"

"""
Automation tests for sssctl analyze

:requirement: sssctl analyze
"""

from __future__ import annotations

import time

import pytest
from pytest_mh.ssh import SSHAuthenticationError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.tools
@pytest.mark.ticket(bz=1294670)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__list(client: Client, ldap: LDAP):
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


@pytest.mark.tools
@pytest.mark.ticket(bz=1294670, gh=6298)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__non_default_log_location(client: Client, ldap: LDAP):
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
    res = client.sssctl.analyze_request(command="list --pam", logdir="/tmp/copy/")
    assert "sshd" in res.stdout, "sshd not found in list --pam output"

    res = client.sssctl.analyze_request(command="list -v", logdir="/tmp/copy/")
    assert " id" in res.stdout or "coreutils" in res.stdout, "' id' or 'coreutils' not found in analyze list -v output"
    res = client.sssctl.analyze_request(command="list -v --pam", logdir="/tmp/copy/")
    assert "sshd" in res.stdout, "sshd not found in list -v --pam output"


@pytest.mark.tools
@pytest.mark.ticket(bz=1294670)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__pam_logs(client: Client, ldap: LDAP):
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
    assert result.rc == 0
    assert "CID #1" in result.stdout

    assert "SSS_PAM_AUTHENTICATE" in result.stdout
    assert "SSS_PAM_ACCT_MGMT" in result.stdout
    assert "SSS_PAM_SETCRED" in result.stdout


@pytest.mark.tools
@pytest.mark.ticket(bz=2013259)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__tevent_id(client: Client, ldap: LDAP):
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
    assert result.rc == 0
    assert "RID#" in result.stdout, "RID# was not found in the output"
    assert "user1@test" in result.stdout, "user1@test was not found in the output"


@pytest.mark.tools
@pytest.mark.ticket(bz=2013260)
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__parse_child_logs(client: Client, ldap: LDAP):
    """
    :title: "sssctl analyze" to parse child logs
    :setup:
        1. Add user
        2. Enable debug_level to 9 in the 'nss', 'pam' and domain section
        3. Start SSSD
    :steps:
        1. Log in as user via ssh
        2. Call sssctl analyze to check logs
        3. Clear cache and restart SSSD
        4. Log in as user via ssh with wrong password
        5. Call sssctl analyze to check logs
    :expectedresults:
        1. Logged in successfully
        2. Logs contain login related logs
        3. Succesfully
        4. Failed to login
        5. Logs contain info about failed login
    :customerscenario: True
    """
    ldap.user("user1").add()
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
    assert (
        "Authentication failure to the client" in result.stdout
    ), "'Authentication failure to the client' was not found"


@pytest.mark.tools
@pytest.mark.ticket(bz=[2142960, 2142794, 2142961])
@pytest.mark.topology(KnownTopology.LDAP)
def test_sssctl_analyze__root_privileges(client: Client, ldap: LDAP):
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

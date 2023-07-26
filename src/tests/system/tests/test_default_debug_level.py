"""
Automation for default debug level

:requirement: SSSD - Default debug level
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Client)
def test_default_debug_level__check(client: Client):
    """
    :title: Check default debug level when sssd started successfully
    :setup:
        1. Clear logs and cache
        2. Start SSSD with default debug level
    :steps:
        1. Check log files
    :expectedresults:
        1. "Starting with debug level = 0x0070" is in each file and
            if log contains more than one line, log message with number "0x3f7c0" is stored
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"

    client.sssd.clear(db=True, memcache=True, logs=True, config=False)
    client.sssd.start(debug_level=None)

    for file in [client.sssd.logs.monitor, client.sssd.logs.domain(), client.sssd.logs.nss, client.sssd.logs.pam]:
        log_str = client.fs.read(file)
        assert "Starting with debug level = 0x0070" in log_str, f"Log file has wrong format: {log_str}"

        if len(log_str.split("\n")) > 1:
            assert "(0x3f7c0)" in log_str, f"Log file has wrong format: {log_str}"


@pytest.mark.topology(KnownTopology.Client)
def test_default_debug_level__check_with_login(client: Client):
    """
    :title: Successful login with default debug level doesn't generate any logs
    :setup:
        1. Add local user, set its password
        2. Add fallback_homedir (generates extra logs on user auth if not specified)
        3. Clear cache and logs
    :steps:
        1. Start SSSD with default debug level
        2. Authenticate with user
        3. Check that logs were not generated
    :expectedresults:
        1. SSSD started successfully
        2. User is authenticated
        3. Diff of copy and logs is empty
    :customerscenario: False
    """

    client.local.user("user1").add(password="Secret123")
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.domain["fallback_homedir"] = "/home/%%u"

    client.sssd.clear(db=True, memcache=True, logs=True, config=False)
    client.sssd.start(debug_level=None)

    client.fs.copy("/var/log/sssd", "/tmp/copy")
    assert client.auth.ssh.password("user1", "Secret123"), "Authentication failed"
    assert not client.host.ssh.run("diff /var/log/sssd /tmp/copy").stdout, "Debug messages were generated"


@pytest.mark.ticket(bz=1893159)
@pytest.mark.topology(KnownTopology.Client)
def test_default_debug_level__fatal_and_critical_failures(client: Client):
    """
    :title: Check that messages with levels 0 and 1 are logged for fatal or critical failures
    :setup:
        1. Start SSSD with default debug level (config file is created)
        2. Restrict sssd.conf permissions
    :steps:
        1. Restart sssd
        2. Check logs
    :expectedresults:
        1. SSSD failed to start
        2. Fatal failures (level 0) and Critical failures (level 1) are in log file
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.start(debug_level=None)
    client.fs.chmod(mode="444", path="/etc/sssd/sssd.conf")

    assert (
        client.sssd.restart(debug_level=None, raise_on_error=False, apply_config=False).rc != 0
    ), "SSSD started successfully, which is not expected"

    log_str = client.fs.read(client.sssd.logs.monitor)
    assert "0x0010" in log_str, "Fatal failures were not found in log"
    assert "0x0020" in log_str, "Critical failures were not found in log"


@pytest.mark.ticket(bz=1893159)
@pytest.mark.topology(KnownTopology.Client)
def test_default_debug_level__cannot_load_sssd_config(client: Client):
    """
    :title: Check that messages with level 2 are logged when SSSD can't load config
    :setup:
        1. Set 'domains' to 'non_existing_domain' in sssd section
    :steps:
        1. Try to start SSSD with default debug level
        2. Check logs
    :expectedresults:
        1. SSSD failed to start
        2. Correct error message is in log file
    :customerscenario: True
    """
    client.sssd.sssd["domains"] = "non_existing_domain"
    assert (
        client.sssd.start(debug_level=None, raise_on_error=False).rc != 0
    ), "SSSD started successfully, which is not expected"
    assert "SSSD couldn't load the configuration database" in client.fs.read(client.sssd.logs.monitor)


@pytest.mark.ticket(bz=1893159)
@pytest.mark.topology(KnownTopology.LDAP)
def test_default_debug_level__nonexisting_ldap_server(client: Client):
    """
    :title: Check that messages with level 2 are logged when LDAP server doesn't exist
    :setup:
        1. Set ldap_uri to a non-existing ldap-server
        2. Start sssd with default debug level
        3. Enable ifp responder
    :steps:
        1. Check logs
        2. Check default domain status
    :expectedresults:
        1. Domain logs should contain a log related to 'going offline'
        2. LDAP is not connected
    :customerscenario: True
    """
    client.sssd.domain["ldap_uri"] = "ldap://typo.invalid"
    client.sssd.enable_responder("ifp")
    client.sssd.start(debug_level=None, raise_on_error=False)

    logs = client.fs.read(client.sssd.logs.domain())
    assert "Failed to connect, going offline" in logs, "String was not found in the logs"

    assert client.sssd.default_domain, "default_domain is None"
    res = client.sssctl.domain_status(client.sssd.default_domain)
    assert "LDAP: not connected" in res.stdout


@pytest.mark.ticket(bz=1915319)
@pytest.mark.topology(KnownTopology.Client)
def test_default_debug_level__sbus(client: Client):
    """
    :title: SBUS doesn't trigger failure message at modules startup
    :setup:
        1. Start sssd with default debug level
    :steps:
        1. Check logs
    :expectedresults:
        1. "Unable to remove key" is not in the logs
    :customerscenario: True
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.start(debug_level=None)

    for file in [client.sssd.logs.monitor, client.sssd.logs.domain(), client.sssd.logs.nss, client.sssd.logs.pam]:
        assert "Unable to remove key" not in client.fs.read(file), f"'Unable to remove key' was found in file: {file}"

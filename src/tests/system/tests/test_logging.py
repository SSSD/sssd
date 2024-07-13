"""
SSSD Logging Tests.

client.sssd.start(debug_level=None), means no configuration. It is the same as if
the parameter is omitted from 'sssd.conf'.

:requirement: SSSD - Default debug level
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging__default_settings_logs_debug_level(client: Client):
    """
    :title: Default settings writes the debug level to logs
    :setup:
        1. Configure SSSD for local system authentication
        2. Clear logs and start SSSD with default debug level
    :steps:
        1. Check log files
    :expectedresults:
        1. Logs messages contain default debug level 0x0070
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.default_domain = "local"

    client.sssd.clear(logs=True)
    client.sssd.start(debug_level=None)

    for file in [client.sssd.logs.monitor, client.sssd.logs.domain(), client.sssd.logs.nss, client.sssd.logs.pam]:
        log_str = client.fs.read(file)
        assert "level = 0x0070" in log_str, "Logs should contain debug_level = 0x0070!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging__default_settings_does_not_log_user_logins(client: Client):
    """
    :title: Default debug level does not log user logins
    :setup:
        1. Create user
        2. Configure SSSD for local system authentication
        3. Clear cache and logs and start SSSD with default debug level
    :steps:
        1. Store current logs and authenticate as a local user.
        2. Compare stored logs with the current ones.
    :expectedresults:
        1. Login was successful
        2. Before event did not generate any new logs lines
    :customerscenario: False
    """

    client.local.user("user1").add()
    client.sssd.common.local()
    client.sssd.default_domain = "local"
    client.sssd.domain["fallback_homedir"] = "/home/%%u"

    client.sssd.clear(logs=True, config=False)
    client.sssd.start(debug_level=None)

    client.fs.copy("/var/log/sssd", "/tmp/copy")
    assert client.auth.ssh.password("user1", "Secret123"), "Login failed!"
    assert not client.host.conn.run("diff /var/log/sssd /tmp/copy").stdout, "Debug messages were generated!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1893159)
@pytest.mark.topology(KnownTopology.Client)
def test_logging__default_settings_logs_domain_configuration_errors(client: Client):
    """
    :title: Default debug_level logs domain configuration errors
    :setup:
        1. Configure SSSD with an invalid domain
    :steps:
        1. Start SSSD with default debug level
        2. Check logs
    :expectedresults:
        1. SSSD failed to start
        2. Logs contain error message
    :customerscenario: True
    """
    client.sssd.sssd["domains"] = "non_existing_domain"
    assert client.sssd.start(debug_level=None, raise_on_error=False).rc != 0, "SSSD erroneously started!"
    assert "No properly configured domains, fatal error!" in client.fs.read(
        client.sssd.logs.monitor
    ), "Domain is configured!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1893159)
@pytest.mark.topology(KnownTopology.LDAP)
def test_logging__default_settings_logs_offline_errors(client: Client):
    """
    :title: Default debug_level logs offline errors
    :setup:
        1. Configure SSSD with an invalid uri and enable ifp responder
        2. Start SSSD with default debug level
        3. Enable infopipe responder
    :steps:
        1. Check logs
        2. Check default domain status
    :expectedresults:
        1. Logs contain connection errors
        2. SSSD is not connected
    :customerscenario: True
    """
    client.sssd.domain["ldap_uri"] = "ldap://typo.invalid"
    client.sssd.enable_responder("ifp")
    client.sssd.start(debug_level=None, raise_on_error=False)

    logs = client.fs.read(client.sssd.logs.domain())
    assert "Failed to connect, going offline" in logs, "Offline error messages are not in logs!"

    assert client.sssd.default_domain is not None, "Failed to load default domain!"
    result = client.sssctl.domain_status(client.sssd.default_domain)
    assert result is not None
    assert "LDAP: not connected" in result.stdout, "LDAP is connected!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1416150)
@pytest.mark.topology(KnownTopology.LDAP)
def test_logging__default_settings_logs_to_syslog_when_ldap_is_offline(client: Client):
    """
    :title: Log to syslog when sssd cannot contact ldap servers and the servers go offline
    :setup:
        1. Configure SSSD with an invalid uri and start SSSD
    :steps:
        1. Check domain status using sssctl
        2. Clear syslog and restart SSSD and check syslog
    :expectedresults:
        1. Domain is offline
        2. Logs contain SSSD errors
    :customerscenario: True
    """
    client.sssd.domain["ldap_uri"] = "ldaps://typo.invalid"
    client.sssd.start()

    assert client.sssd.default_domain is not None, "Failed to load default domain!"
    status = client.sssctl.domain_status(client.sssd.default_domain)
    assert status is not None
    assert "Offline" in status.stdout or "Unable to get online status" in status.stderr, "Domain is not offline!"

    client.journald.clear()
    client.sssd.restart()
    time.sleep(1)

    log = client.journald.journalctl(grep="Backend is offline", unit="sssd")
    assert log.rc == 0, "Offline error messages are not in logs!"

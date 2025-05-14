"""
SSSD Logging Tests.

client.sssd.start(debug_level=None), means no configuration. It is the same as if
the parameter is omitted from 'sssd.conf'.

The default debug level 2.
It is handled and reported as a bitmask.
See: https://github.com/SSSD/sssd/blob/master/src/util/debug.h#L101


:requirement: SSSD - Default debug level
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging__default_debug_level(client: Client):
    """
    :title: Default log level 0x0070 is written to logs
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
    client.sssd.clear(logs=True)
    client.sssd.start(debug_level=None)

    for file in [client.sssd.logs.monitor, client.sssd.logs.domain(), client.sssd.logs.nss, client.sssd.logs.pam]:
        log_str = client.fs.read(file)
        assert "level = 0x0070" in log_str, "Logs should contain debug_level = 0x0070!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging_debug_level_is_written_to_logs(client: Client):
    """
    :title: Domain log level from configuration is honored
    :setup:
        1. Configure SSSD for local system authentication
        2. Clear logs and start SSSD with debug level 9
    :steps:
        1. Check log files
    :expectedresults:
        1. Logs messages contain configured debug level 0x4000
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.domain["debug_level"] = "9"
    client.sssd.clear(logs=True)
    client.sssd.start(debug_level=None)
    log_str = client.fs.read(client.sssd.logs.domain())

    assert "level = 0x2f7f0" in log_str, "Logs should contain debug level = 0x2f7f0!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging_change_debug_level_during_runtime(client: Client):
    """
    :title: Domain log level set in runtime is honored
    :setup:
        1. Configure SSSD for local system authentication
        2. Clear logs and start SSSD with defaut level
    :steps:
        1. Check log file
        2. Change domain debug level in runtime using sssctl debug-level
        3. Check log file again
    :expectedresults:
        1. Logs messages contain default debug level 0x0070
        2. Debug level change command succeeds
        3. Logs messages contain default debug level 0x2f7f0
    :customerscenario: False
    """
    client.sssd.common.local()
    client.sssd.clear(logs=True)
    client.sssd.start(debug_level=None)

    log_str = client.fs.read(client.sssd.logs.domain())
    sssctl_set = client.host.conn.run("sssctl debug-level --domain local 9")
    sssctl_get = client.host.conn.run("sssctl debug-level --domain local")

    assert "level = 0x0070" in log_str, "Logs should contain debug level = 0x0070!"
    assert sssctl_set.rc == 0, "'sssctl debug-level' command failed!"
    assert sssctl_get.rc == 0, "'sssctl debug-level' command failed!"
    assert "0x2f7f0" in sssctl_get.stdout, "sssctl debug-level output should contain 0x2f7f0!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_logging__user_logins_are_not_written_to_logs(client: Client, provider: GenericProvider):
    """
    :title: Default debug level does not log user logins
    :setup:
        1. Create user
        2. Configure SSSD for system authentication
        3. Clear cache and logs and start SSSD with default debug level
    :steps:
        1. Store current logs and authenticate as an user.
        2. Compare stored logs with the current ones.
    :expectedresults:
        1. Login was successful
        2. Before event did not generate any new logs lines
    :customerscenario: False
    """
    provider.user("user1").add(password="Secret123")
    client.sssd.domain["fallback_homedir"] = "/home/%%u"
    client.sssd.sssd["services"] = "nss, pam, ssh"
    client.sssd.clear(logs=True, config=False)
    client.sssd.start(debug_level=None)
    time.sleep(30)

    client.fs.copy("/var/log/sssd", "/tmp/copy")
    assert client.auth.parametrize("ssh").password("user1", "Secret123"), "User failed login!"
    assert not client.host.conn.run("diff /var/log/sssd /tmp/copy").stdout, "Debug messages were generated!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_logging__domain_configuration_errors(client: Client):
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
    :customerscenario: False
    """
    client.sssd.sssd["domains"] = "non_existing_domain"

    assert client.sssd.start(debug_level=None, raise_on_error=False).rc != 0, "SSSD erroneously started!"
    assert "No properly configured domains, fatal error!" in client.fs.read(
        client.sssd.logs.monitor
    ), "Domain is configured!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_logging_dns_resolution_issue_in_logs(client: Client):
    """
    :title: Default debug_level logs backend dns resolution issue
    :setup:
        1. Configure SSSD with an invalid uri
        2. Enable infopipe responder
        3. Start SSSD with default debug level

    :steps:
        1. Check logs
        2. Check default domain status
    :expectedresults:
        1. Logs contain dns name resolution error message
        2. SSSD is not connected
    :customerscenario: False
    """
    client.sssd.domain["ldap_uri"] = "ldap://typo.invalid"
    client.sssd.enable_responder("ifp")
    client.sssd.start(debug_level=None, raise_on_error=False)
    if not client.sssd.default_domain:
        client.sssd.default_domain = "ldap.test"

    logs = client.fs.read(client.sssd.logs.domain())
    assert (
        "Failed to resolve server 'typo.invalid': Domain name not found" in logs
    ), "'Domain name not found' error message are not in logs!"
    result = client.sssctl.domain_status(client.sssd.default_domain)
    assert result is not None
    assert "LDAP: not connected" in result.stdout, "LDAP is connected!"


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
def test_logging_offline_errors_are_written_to_logs_and_syslog(client: Client, ldap: LDAP):
    """
    :title: Default debug_level logs offline errors also to syslog
    :setup:
        1. Configure SSSD with ifp responder and LDAP backend
        2. Reduce ldap_network_timeout to 1 second
        3. Block LDAP access using firewall
        4. Start SSSD with default debug level
    :steps:
        1. Check default domain status
        2. Check domain log
        3. Check syslog/journal
    :expectedresults:
        1. SSSD is not connected
        2. Logs contain connection/timout errors
        3. Syslog contains offline message
    :customerscenario: False
    """
    client.sssd.stop()
    client.firewall.outbound.reject_host(ldap)
    client.sssd.domain["ldap_network_timeout"] = "1"
    client.sssd.enable_responder("ifp")
    client.sssd.start(debug_level=None, raise_on_error=False)
    if not client.sssd.default_domain:
        client.sssd.default_domain = "ldap.test"

    for _ in range(1, 10):
        result = client.sssctl.domain_status(client.sssd.default_domain)
        if result is not None and "Online status: Offline" in result.stdout:
            break
        time.sleep(10)
    else:
        pytest.fail("Could not get domain status or sssd is not offline!")

    logs = client.fs.read(client.sssd.logs.domain())
    assert "Failed to connect, going offline" in logs, "Offline error messages is not in domain log!"
    assert (
        "No available servers for service 'LDAP'" in logs
    ), "'No available servers for service' error message is not in logs!"
    assert (
        "Connection timed out [ldap_network_timeout]" in logs
    ), "'Connection timed out [ldap_network_timeout]' error message is not in logs!"

    for _ in range(1, 10):
        log = client.journald.journalctl(grep="Backend is offline", unit="sssd")
        if log.rc == 0:
            break
        time.sleep(10)
    else:
        pytest.fail("Offline error message is not in syslog!")

"""
SSSD LDAP/KRB5 Tests.

Tests where the ``id_provider`` is set to ``ldap`` and the ``auth_provider``
is set to ``krb5``. They use ``KnownTopology.LDAP_KRB5`` (client + LDAP + KDC,
host keytab provisioned by the topology controller).

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=773660)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__clock_skew_errors_logged_to_syslog(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: Clock skew errors are logged to syslog

    This test requires a working ``chronyd``/``chronyc`` pair. The test is skipped
    if ``chronyc`` is missing, or if :meth:`client.chrony.time_skew` cannot enable
    chronyd manual mode (for example ``506 Cannot talk to daemon`` on restricted
    images).

    :setup:
        1. Create user and kerberos principal
        2. Configure SSSD
        3. Disable time sync and start SSSD
    :steps:
        1. Log in as user
        2. Skew clock one day ahead
        3. Log in again
        4. Check syslog
    :expectedresults:
        1. Login successful
        2. System time has changed
        3. Login fails
        4. Logs contain a time skew message
    :customerscenario: True
    """
    if not client.chrony.is_available():
        pytest.skip("chronyc not available")

    provider.user("a1m2user").add(uid=10341, gid=10341, password="Secret123")
    kdc.principal("a1m2user").add(password="Secret123", requires_preauth=True)

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["chpass_provider"] = "krb5"
    client.sssd.domain["cache_credentials"] = "true"

    krb5_conf = client.fs.read("/etc/krb5.conf")
    krb5_conf = krb5_conf.replace(
        "forwardable = yes",
        "forwardable = yes\nkdc_timesync = 0",
    )
    client.fs.write("/etc/krb5.conf", krb5_conf)

    client.sssd.restart(clean=True)

    with client.chrony.time_skew(86400):  # +1 day; skips if chronyd manual mode fails
        auth_ok = client.auth.ssh.password("a1m2user", "Secret123")
        assert not auth_ok, "Auth should fail due to clock skew!"

    result = client.host.conn.run(
        "journalctl -b -o cat 2>/dev/null | grep -i 'Clock skew too great' || true",
        raise_on_error=False,
    )
    assert "Clock skew" in result.stdout, f"'Clock skew too great' not found in syslog: {result.stdout}!"


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=869150)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__ldap_child_handles_missing_keytab_without_segfault(
    client: Client, provider: GenericProvider, kdc: KDC
):
    """
    :title: LDAP child does not segfault when keytab file is missing

    :setup:
        1. Create user and kerberos principal
        2. Configure SSSD
        3. Configure ``ldap_krb5_keytab`` to ``/etc/krb5.keytab`` (topology default path
           and SELinux context), remove that file via :meth:`client.fs.rm` (backed up for
           teardown), then start SSSD
    :steps:
        1. Trigger user lookup
        2. Check journal for segfault messages
        3. Check coredumpd for ldap_child core files
    :expectedresults:
        1. Lookup completes without crash
        2. No segfault in journal
        3. No ldap_child core dumps
    :customerscenario: True
    """
    provider.user("puser1").add(uid=1001, gid=1001, password="12345678")
    kdc.principal("puser1").add(password="12345678")

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["ldap_sasl_mech"] = "GSSAPI"

    # Use the real keytab path (correct SELinux type); avoid /tmp copies. fs.rm backs up
    # and restores /etc/krb5.keytab after the test.
    client.sssd.domain["ldap_krb5_keytab"] = "/etc/krb5.keytab"
    client.fs.rm("/etc/krb5.keytab")

    client.sssd.restart(clean=True)

    client.tools.id("puser1")

    result = client.host.conn.run(
        "journalctl -b -o cat 2>/dev/null | grep -i segfault || true",
        raise_on_error=False,
    )
    assert "segfault" not in result.stdout, f"LDAP child segfaulted when keytab was missing: {result.stdout}!"

    core_files = client.coredumpd.list_core_files()
    ldap_child_cores = [f for f in core_files if "ldap_child" in f]
    assert not ldap_child_cores, f"ldap_child produced core dumps when keytab was missing: {ldap_child_cores}!"


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=805281)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__keytab_selects_correct_principal_with_multiple_realms(
    client: Client, provider: GenericProvider, kdc: KDC
):
    """
    :title: SSSD uses correct key when keytab has multiple realms

    This test requires ``ktutil`` on the client; the test will skip if mixed
    keytab creation fails.

    :setup:
        1. Create user and kerberos principal
        2. Build mixed keytab (wrong nfs principal first, then host principal)
        3. Install keytab and configure SSSD with LDAP+KRB5 and GSSAPI
        4. Start SSSD
    :steps:
        1. Trigger user lookup
        2. Truncate ldap_child.log
        3. Trigger user lookup again
        4. Read ldap_child.log for selected principal
    :expectedresults:
        1. First user lookup completes
        2. ldap_child.log is truncated
        3. Second user lookup completes
        4. Wrong nfs principal is not selected; correct host principal is in the log
    :customerscenario: True
    """
    provider.user("puser1").add(uid=1001, gid=1001, password="12345678")
    kdc.principal("puser1").add(password="12345678")

    # Topology provisions host keytab at /etc/krb5.keytab; copy for ktutil input.
    valid_keytab = "/tmp/sssd_client_valid.keytab"
    client.fs.copy("/etc/krb5.keytab", valid_keytab)

    wrong_principal = f"nfs/{client.host.hostname}@TEST.EXAMPLE.COM"
    mixed_keytab = "/tmp/first_invalid.keytab"
    result = client.auth.kerberos().ktutil_create_mixed_keytab(
        wrong_principal=wrong_principal,
        valid_keytab=valid_keytab,
        output_keytab=mixed_keytab,
        raise_on_error=False,
    )
    if result.rc != 0:
        pytest.skip(f"ktutil failed to create mixed keytab: {result.stderr or result.stdout}")

    client.fs.rm("/etc/krb5.keytab")
    client.fs.copy(mixed_keytab, "/etc/krb5.keytab")

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_realm"] = "TEST.EXAMPLE.COM"
    client.sssd.domain["ldap_sasl_mech"] = "GSSAPI"
    client.sssd.domain["ldap_krb5_keytab"] = "/etc/krb5.keytab"
    client.sssd.domain["debug_level"] = "0xFFF0"

    client.sssd.restart(clean=True)

    client.tools.id("puser1")

    client.host.conn.run("truncate -s 0 /var/log/sssd/ldap_child.log", raise_on_error=False)

    client.tools.id("puser1")

    ldap_child_log = "/var/log/sssd/ldap_child.log"
    wrong_pattern = f"nfs/{client.host.hostname}@TEST.EXAMPLE.COM"
    correct_pattern = f"host/{client.host.hostname}@{kdc.realm}"
    selected_ok = f"Selected principal: {correct_pattern}"

    # `id` can return before ldap_child finishes appending to ldap_child.log.
    time.sleep(2)
    log_content = client.fs.read(ldap_child_log)

    assert f"Selected principal: {wrong_pattern}" not in log_content, f"SSSD incorrectly selected {wrong_pattern}!"
    assert f"Principal name is: [{wrong_pattern}]" not in log_content, f"SSSD incorrectly used {wrong_pattern}!"
    assert (
        selected_ok in log_content
    ), f"SSSD should select {correct_pattern}; log missing line after wait: {log_content[:500]!r}"

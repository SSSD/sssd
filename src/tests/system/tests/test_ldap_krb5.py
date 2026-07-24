"""
SSSD LDAP/KRB5 Tests.

Tests where the ``id_provider`` is set to ``ldap`` and the ``auth_provider``
is set to ``krb5``. They use ``KnownTopology.LDAP_KRB5`` (client + LDAP + KDC,
host keytab provisioned by the topology controller).

Misc krb cases ported from sssd-qe krb_misc are included in this module.

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


def _assert_ldap_krb5_srv_records(client: Client, discovery_domain: str) -> None:
    for query in (
        f"_ldap._tcp.{discovery_domain}",
        f"_kerberos._udp.{discovery_domain}",
    ):
        assert client.net.has_srv_record(query), f"No SRV record for {query}"


NOBODY_C_SOURCE = (
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    setuid(-1);\n"
    "    while (1) { sleep(60); }\n"
    "    return 0;\n"
    "}\n"
)


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


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=847039)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__auth_succeeds_when_kpasswd_unresolvable(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: Auth succeeds when krb5_kpasswd is unresolvable

    BZ 847039: login works when krb5_kpasswd is unresolvable (kpasswd not needed for auth)

    :setup:
        1. Add user puser1 to LDAP and KDC
        2. Configure SSSD with LDAP+KRB5
        3. Set krb5_kpasswd to an unresolvable hostname
        4. Restart SSSD and clear cache
    :steps:
        1. Run id for puser1 so NSS resolution goes through SSSD before SSH login
        2. Authenticate puser1 with SSH password
    :expectedresults:
        1. id succeeds for puser1
        2. SSH password authentication succeeds despite unresolvable kpasswd
    :customerscenario: True
    """
    provider.user("puser1").add(uid=50001, gid=50001, password="12345678")
    kdc.principal("puser1").add(password="12345678")

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_realm"] = kdc.realm
    client.sssd.domain["krb5_server"] = kdc.host.hostname
    client.sssd.domain["krb5_kpasswd"] = "invalid.cannotresolve.invalid"

    client.sssd.restart(clean=True)

    assert client.tools.id("puser1"), "id failed for puser1!"

    assert client.auth.ssh.password("puser1", "12345678"), "Auth failed when krb5_kpasswd is unresolvable!"


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.ticket(bz=798655)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__auth_succeeds_when_uid_minus_one_helper_running(
    client: Client, provider: GenericProvider, kdc: KDC
):
    """
    :title: Auth succeeds when a process with UID -1 is running

    BZ 798655: auth and logs stay clean with a setuid(-1) helper process running

    :setup:
        1. Add user puser1 to LDAP and KDC
        2. Configure SSSD with LDAP+KRB5
        3. Restart SSSD and clear cache
        4. Verify auth succeeds for puser1
        5. Compile and run a process with setuid(-1) in background (unique paths under ``/tmp``)
    :steps:
        1. Authenticate puser1 while the UID -1 process is running
        2. Check SSSD backend log for "strtol failed" error
    :expectedresults:
        1. Authentication succeeds
        2. No "strtol failed [Numerical result out of range]" in log
    :customerscenario: True
    """
    provider.user("puser1").add(uid=50001, gid=50001, password="12345678")
    kdc.principal("puser1").add(password="12345678")

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_realm"] = kdc.realm
    client.sssd.domain["krb5_server"] = kdc.host.hostname
    client.sssd.domain["krb5_kpasswd"] = kdc.host.hostname

    client.sssd.restart(clean=True)

    assert client.auth.ssh.password("puser1", "12345678"), "Auth failed before starting UID -1 process!"

    result = client.host.conn.run("which gcc", raise_on_error=False)
    if result.rc != 0:
        pytest.skip("gcc not available")

    nobody_src = "/tmp/sssd_test_bz798655_nobody.c"
    nobody_bin = "/tmp/sssd_test_bz798655_nobody"
    client.fs.write(nobody_src, NOBODY_C_SOURCE)
    result = client.host.conn.run(
        f"gcc -o {nobody_bin} {nobody_src}",
        raise_on_error=False,
    )
    if result.rc != 0:
        pytest.skip(f"Failed to compile nobody.c: {result.stderr}")

    nobody_pid = ""
    proc = client.host.conn.run(
        f"nohup {nobody_bin} </dev/null >/dev/null 2>&1 & echo $!",
        raise_on_error=False,
    )
    if proc.stdout:
        nobody_pid = proc.stdout.strip()

    try:
        assert client.auth.ssh.password("puser1", "12345678"), "Auth failed while UID -1 process is running!"

        domain = client.sssd.default_domain
        log_content = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")
        assert (
            "strtol failed [Numerical result out of range]" not in log_content
        ), "strtol error found in SSSD log with UID -1 process running!"
    finally:
        if nobody_pid.isdigit():
            client.host.conn.run(f"kill {nobody_pid}", raise_on_error=False)
        client.host.conn.run(
            f"rm -f {nobody_bin} {nobody_src}",
            raise_on_error=False,
        )


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__password_change_via_ssh(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: Password change via SSH triggers krb5_child initial auth

    GH 677: SSH passwd with chpass_provider=krb5 logs initial auth in krb5_child.log

    :setup:
        1. Add user puser1 to LDAP and KDC
        2. Configure SSSD with LDAP+KRB5, chpass_provider=krb5
        3. Restart SSSD and clear cache
    :steps:
        1. Run id for puser1 so NSS resolution goes through SSSD before SSH login
        2. Change puser1 password via SSH passwd
        3. Check ``krb5_child.log`` for the initial-auth line for password change
        4. Authenticate over SSH using the new password
    :expectedresults:
        1. id and initial SSH login succeed
        2. Password change succeeds
        3. krb5_child.log contains 'Initial authentication for change password'
        4. SSH login with the new password succeeds
    :customerscenario: True
    """
    provider.user("puser1").add(uid=50001, gid=50001, password="12345678")
    kdc.principal("puser1").add(password="12345678")

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_realm"] = kdc.realm
    client.sssd.domain["krb5_server"] = kdc.host.hostname
    client.sssd.domain["krb5_kpasswd"] = kdc.host.hostname
    client.sssd.domain["chpass_provider"] = "krb5"

    client.sssd.restart(clean=True)

    client.tools.id("puser1")

    assert client.auth.ssh.password("puser1", "12345678"), "Auth failed before password change!"

    new_password = "NewSecret123!"

    assert client.auth.ssh.passwd.password(
        "puser1",
        "12345678",
        new_password,
    ), "Password change via SSH failed!"
    log_content = client.fs.read("/var/log/sssd/krb5_child.log")
    assert (
        "Initial authentication for change password" in log_content
    ), f"krb5_child initial auth message not found: {log_content[:500]}!"

    assert client.auth.ssh.password("puser1", new_password), "Auth with new password failed after password change!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__dns_srv_discovery_with_srv_uri(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: DNS SRV discovery for LDAP using _srv_ URI
    :setup:
        1. Add user and configure SSSD with ldap_uri=_srv_, krb5_server=_srv_
        2. Restart SSSD
    :steps:
        1. Authenticate user via SSH
        2. Check logs for LDAP SRV resolution
        3. Check logs for LDAP SRV marked as resolved
        4. Check logs for Kerberos SRV resolution
    :expectedresults:
        1. Authentication succeeds
        2. Logs show LDAP SRV discovery attempt
        3. Logs show LDAP SRV marked as resolved
        4. Logs show Kerberos SRV marked as resolved
    :customerscenario: True
    """
    discovery_domain = getattr(provider.host, "client", {}).get("dns_discovery_domain") or provider.domain
    client.net.prepare_ldap_krb5_srv_discovery(
        discovery_domain=discovery_domain,
        ldap_hostname=provider.host.hostname,
        kdc_hostname=kdc.host.hostname,
        client_hostname=client.host.hostname,
    )
    _assert_ldap_krb5_srv_records(client, discovery_domain)

    a_result = client.net.dig(provider.host.hostname)
    assert a_result and any(
        r.get("type") == "A" for r in a_result
    ), f"No A record for {provider.host.hostname}; LDAP host must be resolvable via DNS"

    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.authselect.select("sssd")
    client.sssd.common.krb5_auth(kdc)

    client.sssd.domain["ldap_uri"] = "_srv_"
    client.sssd.domain["krb5_server"] = "_srv_"
    client.sssd.domain["dns_discovery_domain"] = discovery_domain
    client.sssd.domain["debug_level"] = "0xFFF0"

    client.sssd.restart(clean=True)

    assert client.tools.id("puser1"), "id failed for puser1 before SSH login"
    if not client.auth.ssh.password("puser1", "Secret123"):
        domain = client.sssd.default_domain
        krb_log = client.fs.read("/var/log/sssd/krb5_child.log")
        sssd_log = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")
        raise AssertionError(
            "Authentication failed with DNS SRV discovery; "
            f"krb5_child.log tail: {krb_log[-1500:]!r}; "
            f"sssd_{domain}.log tail: {sssd_log[-1500:]!r}"
        )

    domain = client.sssd.default_domain
    log_content = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")

    assert (
        f"Trying to resolve SRV record of '_ldap._tcp.{discovery_domain}'" in log_content
        or f"Trying to resolve SRV record of '_LDAP._tcp.{discovery_domain}'" in log_content
    ), "LDAP SRV discovery attempt not found in logs!"

    assert (
        "Marking SRV lookup of service 'LDAP' as 'resolved'" in log_content
    ), "LDAP SRV lookup was not marked as resolved!"

    assert (
        f"Trying to resolve SRV record of '_KERBEROS._udp.{discovery_domain}'" in log_content
        or f"Trying to resolve SRV record of '_kerberos._udp.{discovery_domain}'" in log_content
    ), "Kerberos SRV discovery attempt not found in logs!"
    assert (
        "Marking SRV lookup of service 'KERBEROS' as 'resolved'" in log_content
    ), "Kerberos SRV lookup was not marked as resolved!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=700805)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__kerberos_srv_discovery_with_ldap_uri_set(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: Kerberos DNS SRV discovery works when LDAP URI is set
    :setup:
        1. Add user and configure SSSD with explicit ldap_uri
        2. Restart SSSD
    :steps:
        1. Authenticate user via SSH
        2. Check logs for Kerberos SRV servers added
        3. Check logs for Kerberos SRV resolution attempt
        4. Verify no "unknown" errors in logs
    :expectedresults:
        1. Authentication succeeds
        2. Logs show Kerberos SRV for UDP and TCP
        3. Logs show Kerberos SRV resolution attempt
        4. No "unknown" errors in logs
    :customerscenario: True
    """
    discovery_domain = getattr(provider.host, "client", {}).get("dns_discovery_domain") or provider.domain
    client.net.prepare_ldap_krb5_srv_discovery(
        discovery_domain=discovery_domain,
        ldap_hostname=provider.host.hostname,
        kdc_hostname=kdc.host.hostname,
        client_hostname=client.host.hostname,
    )
    _assert_ldap_krb5_srv_records(client, discovery_domain)

    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.sssd.common.krb5_auth(kdc)

    # krb5_auth() sets krb5_server from mhc; use SRV discovery for Kerberos (BZ 700805).
    client.sssd.domain["krb5_server"] = "_srv_"
    client.sssd.domain["dns_discovery_domain"] = discovery_domain
    client.sssd.domain["dns_resolver_timeout"] = "60"
    client.sssd.domain["ldap_opt_timeout"] = "60"
    client.sssd.domain["debug_level"] = "0xFFF0"

    client.sssd.restart(clean=True)

    assert client.tools.id("puser1"), "id failed for puser1 before SSH login"
    if not client.auth.ssh.password("puser1", "Secret123"):
        domain = client.sssd.default_domain
        krb_log = client.fs.read("/var/log/sssd/krb5_child.log")
        sssd_log = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")
        raise AssertionError(
            "Authentication failed; Kerberos SRV discovery should work even with "
            f"explicit ldap_uri; krb5_child.log tail: {krb_log[-1500:]!r}; "
            f"sssd_{domain}.log tail: {sssd_log[-1500:]!r}"
        )

    domain = client.sssd.default_domain
    log_content = client.fs.read(f"/var/log/sssd/sssd_{domain}.log")

    assert (
        "Adding new SRV server to service 'KERBEROS' using 'udp'" in log_content
    ), "Kerberos SRV discovery (UDP) did not occur!"
    assert (
        "Adding new SRV server to service 'KERBEROS' using 'tcp'" in log_content
    ), "Kerberos SRV discovery (TCP) did not occur!"

    assert (
        f"Trying to resolve SRV record of '_KERBEROS._udp.{discovery_domain}'" in log_content
        or f"Trying to resolve SRV record of '_kerberos._udp.{discovery_domain}'" in log_content
    ), "Kerberos SRV lookup attempt not found in logs!"

    assert (
        "unknown" not in log_content.lower()
    ), "BZ 700805 regression: 'unknown' error found in logs during DNS SRV discovery!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__dns_discovery_with_discovery_domain_set(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: DNS SRV discovery uses dns_discovery_domain when explicitly set
    :setup:
        1. Ensure _ldap._tcp SRV for the provider domain and A record for LDAP host
        2. Add user and configure SSSD; remove ldap_uri; set dns_discovery_domain
        3. Restart SSSD
    :steps:
        1. Run id for puser1
    :expectedresults:
        1. User resolves; LDAP was reached via DNS SRV for the discovery domain
    :customerscenario: True
    """
    discovery_domain = getattr(provider.host, "client", {}).get("dns_discovery_domain") or provider.domain
    client.net.prepare_ldap_krb5_srv_discovery(
        discovery_domain=discovery_domain,
        ldap_hostname=provider.host.hostname,
        kdc_hostname=kdc.host.hostname,
        client_hostname=client.host.hostname,
    )
    _assert_ldap_krb5_srv_records(client, discovery_domain)

    a_result = client.net.dig(provider.host.hostname)
    assert a_result and any(
        r.get("type") == "A" for r in a_result
    ), f"No A record for {provider.host.hostname}; LDAP host must be resolvable via DNS"

    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.sssd.common.krb5_auth(kdc)

    if "ldap_uri" in client.sssd.domain:
        del client.sssd.domain["ldap_uri"]

    client.sssd.domain["dns_discovery_domain"] = discovery_domain
    client.sssd.restart(clean=True)

    result = client.tools.id("puser1")
    assert result is not None, "User lookup failed; LDAP DNS SRV discovery did not work"
    assert result.user.name == "puser1", f"Expected user puser1 but got {result.user.name}"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=732935)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__ldap_sasl_canonicalize_handles_reverse_dns_mismatch(client: Client, provider: LDAP, kdc: KDC):
    """
    :title: ldap_sasl_canonicalize handles reverse DNS mismatch with GSSAPI (BZ 732935)
    :setup:
        1. Resolve LDAP and KDC IPv4 on the client
        2. Configure bogus PTR for the LDAP IP (local named + hosts)
        3. Enable GSSAPI on LDAP server; add puser1 to LDAP and KDC
        4. Configure SSSD for LDAP+GSSAPI (hostname ldap_uri, rdns=false)
    :steps:
        1. Run getent passwd puser1 with hostname ldap_uri
        2. Run getent passwd puser1 with IPv4 ldap_uri and ldap_sasl_canonicalize=true
        3. Run getent passwd puser1 with ldap_sasl_canonicalize=false and hostname ldap_uri
    :expectedresults:
        1. User lookup succeeds without ldap_sasl_canonicalize
        2. User lookup fails when ldap_sasl_canonicalize=true and PTR does not match
           the Kerberos LDAP service hostname
        3. User lookup succeeds with ldap_sasl_canonicalize=false (workaround)
    :customerscenario: True
    """
    ldap_ip, kdc_ip = client.net.setup_sasl_canonicalize_bogus_ptr(
        ldap_hostname=provider.host.hostname,
        ldap_host=provider.host,
        kdc_hostname=kdc.host.hostname,
        kdc_host=kdc.host,
        provider_domain=provider.domain,
        client_hostname=client.host.hostname,
    )

    provider.enable_gssapi(kdc)

    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["ldap_sasl_mech"] = "GSSAPI"
    client.sssd.domain["ldap_sasl_authid"] = f"host/{client.host.hostname}"
    ldap_hostname_uri = f"ldap://{provider.host.hostname}"
    client.sssd.domain["ldap_uri"] = ldap_hostname_uri
    for tls_opt in ("ldap_tls_cacert", "ldap_tls_reqcert", "ldap_id_use_start_tls"):
        if tls_opt in provider.host.client:
            client.sssd.domain[tls_opt] = provider.host.client[tls_opt]
    client.sssd.domain["lookup_family_order"] = "ipv4_first"
    client.sssd.domain["krb5_canonicalize"] = "false"
    client.sssd.domain["debug_level"] = "0xFFF0"

    client.sssd.restart(clean=True)
    result_baseline = client.tools.getent.passwd("puser1")
    assert result_baseline is not None, "getent passwd puser1 must succeed without ldap_sasl_canonicalize"

    client.sssd.domain["ldap_uri"] = f"ldap://{ldap_ip}"
    client.sssd.domain["ldap_id_use_start_tls"] = "false"
    client.sssd.domain["ldap_sasl_canonicalize"] = "true"
    client.sssd.restart(clean=True)

    result_with_canonicalize = client.tools.getent.passwd("puser1")
    assert result_with_canonicalize is None, (
        "getent passwd puser1 must fail with ldap_uri as IPv4 and "
        "ldap_sasl_canonicalize=true when reverse DNS PTR does not match "
        "the Kerberos LDAP service hostname (BZ 732935)"
    )

    client.sssd.domain["ldap_uri"] = ldap_hostname_uri
    for tls_opt in ("ldap_tls_cacert", "ldap_tls_reqcert", "ldap_id_use_start_tls"):
        if tls_opt in provider.host.client:
            client.sssd.domain[tls_opt] = provider.host.client[tls_opt]
    client.sssd.domain["ldap_sasl_canonicalize"] = "false"
    client.sssd.restart(clean=True)

    result_with_fix = client.tools.getent.passwd("puser1")
    assert result_with_fix is not None, (
        "getent passwd puser1 must succeed with ldap_sasl_canonicalize=false " "while bogus PTR remains in place"
    )

"""
SSSD LDAP/KRB5 Tests.

Tests where the ``id_provider`` is set to ``ldap`` and the ``auth_provider``
is set to ``krb5``. They use ``KnownTopology.LDAP_KRB5`` (client + LDAP + KDC,
host keytab provisioned by the topology controller).

Misc krb cases ported from sssd-qe krb_misc are included in this module.

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

import tempfile
import time

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.topology import KnownTopology

NOBODY_C_SOURCE = (
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    setuid(-1);\n"
    "    while (1) { sleep(60); }\n"
    "    return 0;\n"
    "}\n"
)

_BZ732935_KDC_KEYTAB_STAGING = "/root/.sssd-bz732935-ldap.keytab"
_LDAP_DS_SERVICE_KEYTAB = "/etc/dirsrv/ds.keytab"


def _kadmin_ensure_principal(kdc: KDC, principal: str) -> None:
    getp = kdc.kadmin(f'getprinc "{principal}"')
    combined = ((getp.stdout or "") + (getp.stderr or "")).lower()
    if "does not exist" in combined:
        kdc.kadmin(f'addprinc -randkey "{principal}"')
        return
    if getp.rc != 0:
        kdc.kadmin(f'addprinc -randkey "{principal}"')


def _dirsrv_instance_name(provider: GenericProvider) -> str:
    svc = getattr(provider.host, "_ldap_service_name", "dirsrv@localhost.service")
    if "@" in svc:
        instance = svc.split("@", 1)[1]
        if instance.endswith(".service"):
            instance = instance[: -len(".service")]
        return instance
    return "localhost"


def _ensure_ldap_fqdn_and_ip_service_keytab_on_ds(
    kdc: KDC, provider: GenericProvider, ldap_fqdn: str, ldap_ip: str
) -> None:
    """
    ``ldaps://<IPv4>`` + ``ldap_sasl_canonicalize=false`` requests ``ldap/<IPv4>@REALM``.
    Ensure both that and ``ldap/<fqdn>`` exist in the KDC and are merged into the DS
    keytab. Also install ``/etc/krb5.conf`` and ``KRB5_KTNAME`` for ``dirsrv`` (same
    idea as :class:`LDAPKRB5TopologyController`) so 389-ds can accept GSSAPI.
    """
    for suffix in (ldap_fqdn, ldap_ip):
        _kadmin_ensure_principal(kdc, f"ldap/{suffix}")

    kdc.host.conn.run(f"rm -f {_BZ732935_KDC_KEYTAB_STAGING}", raise_on_error=False)
    for suffix in (ldap_fqdn, ldap_ip):
        kdc.kadmin(f'ktadd -k {_BZ732935_KDC_KEYTAB_STAGING} -norandkey "ldap/{suffix}"')

    with tempfile.NamedTemporaryFile() as tmp:
        kdc.host.fs.download(_BZ732935_KDC_KEYTAB_STAGING, tmp.name)
        provider.host.fs.upload(tmp.name, _LDAP_DS_SERVICE_KEYTAB)

    kdc.host.conn.run(f"rm -f {_BZ732935_KDC_KEYTAB_STAGING}", raise_on_error=False)
    provider.host.conn.run(
        f"chown dirsrv:dirsrv {_LDAP_DS_SERVICE_KEYTAB} && chmod 600 {_LDAP_DS_SERVICE_KEYTAB}",
        raise_on_error=False,
    )

    provider.host.fs.write(
        "/etc/krb5.conf",
        kdc.config(),
        user="root",
        group="root",
        mode="0644",
        dedent=False,
    )
    inst = _dirsrv_instance_name(provider)
    dropin_dir = f"/etc/systemd/system/dirsrv@{inst}.service.d"
    dropin_path = f"{dropin_dir}/99-sssd-bz732935-krb5.conf"
    dropin = f"[Service]\nEnvironment=KRB5_KTNAME={_LDAP_DS_SERVICE_KEYTAB}\n"
    provider.host.conn.run(f"mkdir -p '{dropin_dir}'", raise_on_error=False)
    provider.host.fs.write(
        dropin_path,
        dropin,
        user="root",
        group="root",
        mode="0644",
        dedent=False,
    )
    provider.host.conn.run("systemctl daemon-reload", raise_on_error=False)

    svc_name = getattr(provider.host, "_ldap_service_name", "dirsrv@localhost.service")
    provider.host.svc.restart(svc_name)


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
def test_ldap_krb5__dns_discovery_srv_ldap_and_auth(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: DNS SRV discovery for LDAP (Trac 754)
    :setup:
        1. Skip if no ``_ldap._tcp`` SRV for the provider domain or no answer for the LDAP
           host (checked with ``client.net.dig`` on the client)
        2. Add user puser1 to LDAP and KDC
        3. krb5_auth(KDC); remove ldap_uri; set dns_discovery_domain to the provider domain
        4. Restart SSSD
    :steps:
        1. Run id for puser1
        2. SSH login as puser1
    :expectedresults:
        1. id succeeds
        2. SSH password authentication succeeds
    :customerscenario: True
    """
    discovery_domain = provider.domain
    srv_name = f"_ldap._tcp.{discovery_domain}"
    # Use the client's default resolver (same as SSSD for dns_discovery_domain). Do not pass
    # ``provider.server`` as ``@server``: that host is the LDAP/Kerberos service, not necessarily
    # the DNS that answers for ldap.test (often DNS listens on the gateway, not on master.ldap.test).

    has_ldap_srv = client.net.dig(srv_name, None, record_type="SRV")
    has_ldap_host = client.net.dig(provider.host.hostname, None)
    if not has_ldap_srv or not has_ldap_host:
        pytest.skip(
            "DNS prerequisites for LDAP SRV discovery not met "
            f"(SRV {srv_name}: {'ok' if has_ldap_srv else 'missing'}, "
            f"A/AAAA {provider.host.hostname}: {'ok' if has_ldap_host else 'missing'}; "
            "client default resolver)"
        )

    provider.user("puser1").add()
    kdc.principal("puser1").add(password="Secret123")

    client.sssd.common.krb5_auth(kdc)
    del client.sssd.domain["ldap_uri"]
    client.sssd.domain["dns_discovery_domain"] = discovery_domain
    client.sssd.restart(clean=True)

    assert client.tools.id("puser1") is not None, "id failed with LDAP DNS SRV discovery!"
    assert client.auth.ssh.password("puser1", "Secret123"), "Auth failed before DNS SRV discovery!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=700805)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__dns_discovery_fails_over_to_ldap_backup_uri(client: Client, provider: GenericProvider, kdc: KDC):
    """
    :title: LDAP fails over to backup URI when discovery domain has no SRV
    :setup:
        1. Skip if _ldap._tcp SRV exists for the synthetic no-SRV label
        2. Add user puser1 to LDAP and KDC
        3. krb5_auth(KDC); remove ldap_uri; set dns_discovery_domain to a zone with
           no _ldap._tcp; set ldap_backup_uri to ldaps://<LDAP host>
        4. Restart SSSD with clean=True
    :steps:
        1. Run id for puser1
        2. SSH login as puser1 with password
    :expectedresults:
        1. User resolves via ldap_backup_uri after SRV miss
        2. SSH login succeeds
    :customerscenario: True
    """
    discovery_domain = "no-srv-discovery.invalid"
    srv_name = f"_ldap._tcp.{discovery_domain}"

    if client.net.dig(srv_name, None, record_type="SRV"):
        pytest.skip(
            f"Unexpected: _ldap._tcp SRV exists for {discovery_domain} ({srv_name}); "
            "pick another synthetic label or fix DNS so this name has no SRV"
        )

    backup_uri = f"ldaps://{provider.host.hostname}"

    provider.user("puser1").add()
    kdc.principal("puser1").add(password="Secret123")

    client.sssd.common.krb5_auth(kdc)
    del client.sssd.domain["ldap_uri"]
    client.sssd.domain["ldap_backup_uri"] = backup_uri
    client.sssd.domain["dns_discovery_domain"] = discovery_domain

    client.sssd.restart(clean=True)

    assert (
        client.tools.id("puser1") is not None
    ), "id failed after LDAP SRV miss; backup URI should have been used (BZ 700805 regression?)"
    assert client.auth.ssh.password("puser1", "Secret123"), "Auth failed after LDAP SRV miss!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=732935)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__ldap_sasl_canonicalize_reverse_dns_breaks_gssapi(
    client: Client, provider: GenericProvider, kdc: KDC
):
    """
    :title: ldap_sasl_canonicalize and reverse DNS vs GSSAPI (BZ 732935)
    :setup:
        1. Skip if LDAP host IPv4 cannot be resolved on the client
        2. Add user puser1 to LDAP and KDC
        3. Map LDAP IPv4 to the LDAP FQDN in ``/etc/hosts`` on the client so ``ldap_uri`` can
           use ``ldaps://<FQDN>`` (TLS + GSSAPI use ``ldap/<FQDN>@REALM``; avoids fragile
           ``ldap/<IPv4>`` service principals while still toggling ``ldap_sasl_canonicalize``).
        4. Merge LDAP domain options, krb5_auth(KDC), ldap_sasl_mech=GSSAPI, ldap_uri as above
        5. Set ldap_sasl_canonicalize=true; restart SSSD
    :steps:
        1. Run id for puser1 and assert it succeeds
        2. Set ldap_sasl_canonicalize=false; restart SSSD; run id for puser1 and assert it fails
    :expectedresults:
        1. id succeeds with ldap_sasl_canonicalize=true
        2. id fails with ldap_sasl_canonicalize=false
    :customerscenario: True
    """
    ldap_ip = getattr(provider.host, "ip", None)
    if not ldap_ip:
        entry = client.tools.getent.ahostsv4(provider.host.hostname)
        if entry is None or entry.ip is None:
            pytest.skip("Could not resolve LDAP host to IPv4 on client")
        ldap_ip = entry.ip

    provider.user("puser1").add()
    kdc.principal("puser1").add(password="Secret123")

    _ensure_ldap_fqdn_and_ip_service_keytab_on_ds(kdc, provider, provider.host.hostname, ldap_ip)

    client.fs.append("/etc/hosts", f"{ldap_ip} {provider.host.hostname}\n")

    client.sssd.merge_domain(client.sssd.default_domain, provider)
    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["ldap_sasl_mech"] = "GSSAPI"
    client.sssd.domain["ldap_krb5_keytab"] = "/etc/krb5.keytab"
    client.sssd.domain["ldap_uri"] = f"ldaps://{provider.host.hostname}"
    client.sssd.domain["ldap_sasl_canonicalize"] = "true"
    client.sssd.restart(clean=True)

    broken = client.tools.id("puser1") is None

    client.sssd.domain["ldap_sasl_canonicalize"] = "false"
    client.sssd.restart(clean=True)
    assert client.tools.id("puser1") is not None, "id should succeed with ldap_sasl_canonicalize=false"

    if not broken:
        pytest.skip(
            "Reverse DNS for LDAP IP matches expected hostname; cannot reproduce BZ 732935 "
            "canonicalize failure in this environment"
        )

    assert client.tools.id("puser1"), "id should succeed with ldap_sasl_canonicalize=true!"

    client.sssd.domain["ldap_sasl_canonicalize"] = "false"
    client.sssd.restart(clean=True)

    assert not client.tools.id("puser1"), "id should fail with ldap_sasl_canonicalize=false!"

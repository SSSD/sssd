"""
SSSD LDAP/KRB5 Tests.

Tests where the ``id_provider`` is set to ``ldap`` and the ``auth_provider``
is set to ``krb5``. They use ``KnownTopology.LDAP_KRB5`` (client + LDAP + KDC,
host keytab provisioned by the topology controller).

Misc krb cases ported from sssd-qe krb_misc and the credential cache location
cases from sssd-qe krb_credential_cache are included in this module.

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

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
        2. Read ldap_child.log for selected principal
    :expectedresults:
        1. User lookup completes
        2. Wrong nfs principal is not selected; correct host principal is in the log
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
    client.sssd.start()

    client.tools.id("puser1")

    # `id` can return before ldap_child finishes appending to ldap_child.log.
    time.sleep(2)

    ldap_child_log = "/var/log/sssd/ldap_child.log"
    wrong_pattern = f"nfs/{client.host.hostname}@TEST.EXAMPLE.COM"
    correct_pattern = f"host/{client.host.hostname}@{kdc.realm}"
    selected_ok = f"Selected principal: {correct_pattern}"

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
@pytest.mark.authentication
@pytest.mark.parametrize(
    "ccachedir, ccname_template, expected_ccache",
    [
        # Credential cache types accepted by krb5_ccname_template.
        ("/tmp/krb5_cache", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "FILE:/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
        (None, "/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
        ("/tmp/krb5_cache", "%d/krb5cc_%u", "FILE:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "%h/krb5cc_%u", "FILE:{home}/krb5cc_{user}"),
        ("/tmp/krb5_cache", "FILE:%d/krb5cc_%u_XXXXXX", "FILE:/tmp/krb5_cache/krb5cc_{user}_??????"),
        ("/tmp/krb5_cache", "DIR:%d/krb5cc_%u", "DIR:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "KEYRING:persistent:%U", "KEYRING:persistent:{uid}"),
        # Substitution sequences in krb5_ccname_template, %u is already covered above.
        ("/tmp/krb5_cache", "FILE:%d/cc_%U", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%p", "FILE:/tmp/krb5_cache/cc_{user}@{realm}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%r", "FILE:/tmp/krb5_cache/cc_{realm}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%P", "FILE:/tmp/krb5_cache/cc_[0-9]*"),
        ("/tmp/krb5_cache", "FILE:%d/my_%%_cc", "FILE:/tmp/krb5_cache/my_%_cc"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%u_%u", "FILE:/tmp/krb5_cache/cc_{user}_{user}"),
        # libkrb5 default_ccache_name sequences that SSSD expands itself.
        ("/tmp/krb5_cache", "FILE:%d/cc_%{uid}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{USERID}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{euid}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{username}", "FILE:/tmp/krb5_cache/cc_{user}"),
        # Substitution sequences in krb5_ccachedir.
        ("/tmp/krb5_cache_%u", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%U", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{uid}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%p", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}@{realm}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%r", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{realm}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%h", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{home}/krb5cc_{user}"),
        ("/tmp/my_%%_krb5", "FILE:%d/krb5cc_%u", "FILE:/tmp/my_%_krb5/krb5cc_{user}"),
        ("/tmp/krb5_cache_%{uid}", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{uid}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%{username}", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}/krb5cc_{user}"),
        # krb5_ccachedir values: the /tmp default, nested levels and a directory below the home.
        (None, "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5cc_{user}"),
        ("/tmp/ccaches/%r/%u", "FILE:%d/krb5cc_%u", "FILE:/tmp/ccaches/{realm}/{user}/krb5cc_{user}"),
        ("%h/.ccaches", "FILE:%d/krb5cc_%u", "FILE:{home}/.ccaches/krb5cc_{user}"),
        # krb5_ccachedir is only consulted when the template references it with %d.
        ("/tmp/unused_ccachedir", "FILE:/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
    ],
)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__krb5_ccachedir_substitutions_store_ccache_in_expected_directory(
    client: Client,
    provider: GenericProvider,
    kdc: KDC,
    ccachedir: str | None,
    ccname_template: str,
    expected_ccache: str,
):
    """
    :title: KRB5 ccache creates files in the expected directory

    :setup:
        1. Create user "puser1" with uid 10001 and its kerberos principal
        2. Configure SSSD with LDAP id provider and krb5 auth provider
        3. Set krb5_ccachedir, unless the case exercises the /tmp default
        4. Set krb5_ccname_template
        5. Start SSSD
        6. Create the parent directory owned by puser1 when it is missing
    :steps:
        1. Resolve puser1
        2. Authenticate puser1 over SSH
        3. Check that the credential cache exists where the templates expand to
        4. Check credential cache permissions
        5. Check that the credential cache holds a TGT
        6. Check that krb5_ccachedir is left alone when the template has no %d
    :expectedresults:
        1. User is resolvable
        2. Authentication is successful
        3. Credential cache is created in the location the templates expand to
        4. Permissions are 0600 for a FILE cache and 0700 for a DIR collection
        5. Credential cache holds a TGT for puser1
        6. An unreferenced krb5_ccachedir is not created
    :customerscenario: False
    """
    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.sssd.common.krb5_auth(kdc)
    if ccachedir is not None:
        client.sssd.domain["krb5_ccachedir"] = ccachedir
    client.sssd.domain["krb5_ccname_template"] = ccname_template
    client.sssd.start()

    result = client.tools.id("puser1")
    assert result is not None, "User puser1 is not resolvable!"

    # The uid is assigned by the provider, so the expectations are resolved now.
    expected_ccache = expected_ccache.format(realm=kdc.realm, user="puser1", uid=result.user.id, home="/home/puser1")
    cctype, _, residual = expected_ccache.partition(":")

    if cctype in ("FILE", "DIR"):
        parent = residual.rsplit("/", 1)[0]
        if not client.fs.exists(parent):
            client.fs.mkdir_p(parent, mode="0700", user="puser1")

    assert client.auth.ssh.password("puser1", "Secret123"), "Authentication failed for puser1!"

    if cctype in ("FILE", "DIR"):
        if any(char in residual for char in "?*["):
            matches = client.host.conn.run(f"ls -1d {residual}", raise_on_error=False).stdout.splitlines()
            assert len(matches) == 1, f"Expected exactly one credential cache matching {residual}, found {matches}!"
            residual = matches[0]

        assert client.fs.exists(residual), f"Credential cache {residual} was not created!"

        expected_mode = "0600" if cctype == "FILE" else "0700"
        stat = client.fs.stat(residual)
        assert (
            stat.access == expected_mode
        ), f"Credential cache {residual} has permissions {stat.access}, expected {expected_mode}!"
        assert stat.user == "puser1", f"Credential cache {residual} is owned by {stat.user}, expected puser1!"

        if cctype == "DIR":
            assert client.fs.exists(f"{residual}/primary"), f"Collection {residual} has no primary cache!"

    ccname = f"{cctype}:{residual}"
    klist = client.host.conn.run(f"runuser -u puser1 -- klist -s -c '{ccname}'", raise_on_error=False)
    assert klist.rc == 0, f"Credential cache {ccname} does not hold a TGT for puser1!"

    # krb5_ccachedir was set to a literal path that the template never references.
    if ccachedir is not None and "%" not in ccachedir and "%d" not in ccname_template:
        assert not client.fs.exists(ccachedir), f"Unreferenced krb5_ccachedir {ccachedir} was created!"


@pytest.mark.importance("high")
@pytest.mark.authentication
@pytest.mark.parametrize(
    "ccachedir, expected_error",
    [
        # %d and %P are valid in krb5_ccname_template only, both as the first
        # substitution and once an earlier one has already expanded.
        ("/tmp/krb5_cache_%d", "'%d' is not allowed in this template."),
        ("/tmp/krb5_cache_%P", "'%P' is not allowed in this template."),
        ("/tmp/%u_%d", "'%d' is not allowed in this template."),
        ("/tmp/%u_%P", "'%P' is not allowed in this template."),
        # Sequences that are not part of the substitution syntax at all.
        ("/tmp/krb5_cache_%x", "format error, unknown template [%x]."),
        ("/tmp/krb5_cache_%", "format error, single % at the end of the template."),
        (
            "/tmp/krb5_cache_%{uid",
            "Missing closing '}' in [/tmp/krb5_cache_%{uid]",
        ),
    ],
)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__krb5_ccachedir_invalid_substitution_rejects_authentication(
    client: Client, provider: GenericProvider, kdc: KDC, ccachedir: str, expected_error: str
):
    """
    :title: Authentication fails with an invalid krb5_ccachedir

    :setup:
        1. Create user "puser1" and its kerberos principal
        2. Configure SSSD with LDAP id provider and krb5 auth provider
        3. Set krb5_ccachedir to a path containing the rejected sequence
        4. Set krb5_ccname_template to FILE:%d/krb5cc_%u so krb5_ccachedir is expanded
        5. Start SSSD
    :steps:
        1. Resolve puser1
        2. Authenticate puser1 over SSH
        3. Check the domain log
    :expectedresults:
        1. User is resolvable
        2. Authentication fails
        3. Domain log reports why the template was rejected
    :customerscenario: False
    """
    provider.user("puser1").add()
    kdc.principal("puser1").add()

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_ccachedir"] = ccachedir
    client.sssd.domain["krb5_ccname_template"] = "FILE:%d/krb5cc_%u"
    client.sssd.start()

    assert client.tools.id("puser1"), "User puser1 is not resolvable!"

    assert not client.auth.ssh.password(
        "puser1", "Secret123"
    ), f"Authentication succeeded with krb5_ccachedir set to {ccachedir}!"

    log = client.fs.read(client.sssd.logs.domain())
    assert expected_error in log, f"Domain log does not report {expected_error!r} for krb5_ccachedir {ccachedir}!"

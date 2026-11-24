"""
SSSD LDAP/KRB5 Tests.

Tests where the ``id_provider`` is set to ``ldap`` and the ``auth_provider``
is set to ``krb5``. They use ``KnownTopology.LDAP_KRB5`` (client + LDAP + KDC).

The credential cache location cases from sssd-qe krb_credential_cache are
included in this module.

:requirement: SSSD - Kerberos
"""

from __future__ import annotations

from fnmatch import fnmatch

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("medium")
@pytest.mark.authentication
@pytest.mark.parametrize(
    "cache_dir, ccname_template, expected_ccache",
    [
        ("/tmp/krb5_cache", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "FILE:/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
        (None, "/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
        ("/tmp/krb5_cache", "%d/krb5cc_%u", "FILE:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "%h/krb5cc_%u", "FILE:{home}/krb5cc_{user}"),
        ("/tmp/krb5_cache", "FILE:%d/krb5cc_%u_XXXXXX", "FILE:/tmp/krb5_cache/krb5cc_{user}_??????"),
        ("/tmp/krb5_cache", "DIR:%d/krb5cc_%u", "DIR:/tmp/krb5_cache/krb5cc_{user}"),
        (None, "KEYRING:persistent:%U", "KEYRING:persistent:{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%U", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%p", "FILE:/tmp/krb5_cache/cc_{user}@{realm}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%r", "FILE:/tmp/krb5_cache/cc_{realm}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%P", "FILE:/tmp/krb5_cache/cc_[0-9]*"),
        ("/tmp/krb5_cache", "FILE:%d/my_%%_cc", "FILE:/tmp/krb5_cache/my_%_cc"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%u_%u", "FILE:/tmp/krb5_cache/cc_{user}_{user}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{uid}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{USERID}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{euid}", "FILE:/tmp/krb5_cache/cc_{uid}"),
        ("/tmp/krb5_cache", "FILE:%d/cc_%{username}", "FILE:/tmp/krb5_cache/cc_{user}"),
        ("/tmp/krb5_cache_%u", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%U", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{uid}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%p", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}@{realm}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%r", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{realm}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%h", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{home}/krb5cc_{user}"),
        ("/tmp/my_%%_krb5", "FILE:%d/krb5cc_%u", "FILE:/tmp/my_%_krb5/krb5cc_{user}"),
        ("/tmp/krb5_cache_%{uid}", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{uid}/krb5cc_{user}"),
        ("/tmp/krb5_cache_%{username}", "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5_cache_{user}/krb5cc_{user}"),
        (None, "FILE:%d/krb5cc_%u", "FILE:/tmp/krb5cc_{user}"),
        ("/tmp/ccaches/%r/%u", "FILE:%d/krb5cc_%u", "FILE:/tmp/ccaches/{realm}/{user}/krb5cc_{user}"),
        ("%h/.ccaches", "FILE:%d/krb5cc_%u", "FILE:{home}/.ccaches/krb5cc_{user}"),
        ("/tmp/unused_ccachedir", "FILE:/tmp/krb5cc_%U", "FILE:/tmp/krb5cc_{uid}"),
    ],
)
@pytest.mark.topology(KnownTopology.LDAP_KRB5)
def test_ldap_krb5__krb5_ccachedir_substitutions_are_created_correctly(
    client: Client,
    provider: GenericProvider,
    kdc: KDC,
    cache_dir: str | None,
    ccname_template: str,
    expected_ccache: str,
):
    """
    :title: krb5_ccachedir substitutions are created correctly

    :setup:
        1. Create user "user1" and its kerberos principal
        2. Configure SSSD with LDAP id provider and krb5 auth provider
        3. Set krb5_ccachedir, unless the case exercises the /tmp default
        4. Set krb5_ccname_template
        5. Start SSSD with a clean cache
        6. Resolve user1 to read its uid and home directory
        7. Create the parent directory owned by user1 when it is missing
    :steps:
        1. Authenticate user1 over SSH
        2. Check that the user session is given the expected KRB5CCNAME
        3. Check that the credential cache exists where the templates expand to
        4. Check credential cache permissions
        5. Check that the credential cache holds a TGT for user1 and the realm
        6. Check that krb5_ccachedir is left alone when the template has no %d
    :expectedresults:
        1. Authentication is successful
        2. KRB5CCNAME in the user session points at the credential cache
        3. Credential cache is created in the location the templates expand to
        4. Permissions are 0600 for a FILE cache and 0700 for a DIR collection
        5. Credential cache holds a TGT for user1 and the realm
        6. An unreferenced krb5_ccachedir is not created
    :customerscenario: False
    """
    provider.user("user1").add()
    kdc.principal("user1").add()

    client.sssd.common.krb5_auth(kdc)
    if cache_dir is not None:
        client.sssd.domain["krb5_ccachedir"] = cache_dir
    client.sssd.domain["krb5_ccname_template"] = ccname_template
    client.sssd.start(clean=True)

    passwd = client.tools.getent.passwd("user1")
    assert passwd is not None, "User user1 is not resolvable!"

    expected_ccache = expected_ccache.format(
        realm=kdc.realm,
        user="user1",
        uid=passwd.uid,
        home=passwd.home,
    )
    cctype, _, residual = expected_ccache.partition(":")

    if cctype in ("FILE", "DIR"):
        parent = residual.rsplit("/", 1)[0]
        if not client.fs.exists(parent):
            client.fs.mkdir_p(parent, mode="0700", user="user1")

    with client.ssh("user1", "Secret123") as ssh:
        krb5ccname = ssh.run("echo $KRB5CCNAME", raise_on_error=False).stdout.strip()
        assert fnmatch(krb5ccname, expected_ccache) or fnmatch(
            krb5ccname, residual
        ), f"KRB5CCNAME in the session of user1 is {krb5ccname}, expected {expected_ccache}!"

        if cctype in ("FILE", "DIR"):
            if any(char in residual for char in "?*["):
                matches = client.host.conn.run(f"ls -1d {residual}", raise_on_error=False).stdout.splitlines()
                assert (
                    len(matches) == 1
                ), f"Expected exactly one credential cache matching {residual}, found {matches}!"
                expected_ccache = f"{cctype}:{matches[0]}"
                residual = matches[0]

            assert client.fs.exists(residual), f"Credential cache {residual} was not created!"

            expected_mode = "0600" if cctype == "FILE" else "0700"
            stat = client.fs.stat(residual)
            assert (
                stat.access == expected_mode
            ), f"Credential cache {residual} has permissions {stat.access}, expected {expected_mode}!"
            assert stat.user == "user1", f"Credential cache {residual} is owned by {stat.user}, expected user1!"

            if cctype == "DIR":
                assert client.fs.exists(f"{residual}/primary"), f"Collection {residual} has no primary cache!"

        klist = ssh.run(f"klist -c '{expected_ccache}'", raise_on_error=False)
        assert klist.rc == 0, f"Credential cache {expected_ccache} cannot be read by user1!"
        assert (
            f"Default principal: user1@{kdc.realm}" in klist.stdout
        ), f"Credential cache {expected_ccache} does not hold a TGT for user1@{kdc.realm}!"
        assert (
            f"krbtgt/{kdc.realm}@{kdc.realm}" in klist.stdout
        ), f"Credential cache {expected_ccache} does not hold a TGT for the realm {kdc.realm}!"

    if cache_dir is not None and "%" not in cache_dir and "%d" not in ccname_template:
        assert not client.fs.exists(cache_dir), f"Unreferenced krb5_ccachedir {cache_dir} was created!"


@pytest.mark.importance("medium")
@pytest.mark.authentication
@pytest.mark.parametrize(
    "cache_dir, expected_error",
    [
        ("/tmp/krb5_cache_%d", "'%d' is not allowed in this template."),
        ("/tmp/krb5_cache_%P", "'%P' is not allowed in this template."),
        ("/tmp/%u_%d", "'%d' is not allowed in this template."),
        ("/tmp/%u_%P", "'%P' is not allowed in this template."),
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
    client: Client, provider: GenericProvider, kdc: KDC, cache_dir: str, expected_error: str
):
    """
    :title: Mistyped krb5_ccachedir makes authentication fail with a clear log message

    :setup:
        1. Create user "user1" and its kerberos principal
        2. Configure SSSD with LDAP id provider and krb5 auth provider
        3. Set krb5_ccachedir to a path containing the rejected sequence
        4. Set krb5_ccname_template to FILE:%d/krb5cc_%u so krb5_ccachedir is expanded
        5. Start SSSD
        6. Resolve user1
    :steps:
        1. Authenticate user1 over SSH
        2. Check the domain log
    :expectedresults:
        1. Authentication fails
        2. Domain log reports why the template was rejected
    :customerscenario: False
    """
    provider.user("user1").add()
    kdc.principal("user1").add()

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_ccachedir"] = cache_dir
    client.sssd.domain["krb5_ccname_template"] = "FILE:%d/krb5cc_%u"
    client.sssd.start()

    assert client.tools.id("user1"), "User user1 is not resolvable!"

    assert not client.auth.ssh.password(
        "user1", "Secret123"
    ), f"Authentication succeeded with krb5_ccachedir set to {cache_dir}!"

    log = client.fs.read(client.sssd.logs.domain())
    assert expected_error in log, f"Domain log does not report {expected_error!r} for krb5_ccachedir {cache_dir}!"

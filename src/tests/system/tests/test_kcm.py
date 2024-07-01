"""
KCM responder tests.

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
"""

from __future__ import annotations

import time

import pytest
from pytest_mh.ssh import SSHProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.kdc import KDC
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kinit_does_not_create_new_ccache(client: Client, kdc: KDC, ccache_storage: str):
    """
    :title: Second call to kinit with the same principal does not create new ccache.
    :setup:
        1. Add Kerberos principal "tuser" to KDC
        2. Add local user "tuser"
        3. Set ccache_storage in sssd.conf to @ccache_storage
        4. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Count existing credential caches
        3. Kinit as "tuser"
        4. Check that TGT was acquired
        5. Count existing credential caches
        6. Repeat steps 3-5
    :expectedresults:
        1. User is logged into the host
        2. Returns 0, no ccache is available
        3. User obtains TGT
        4. TGT is present
        5. Returns 1, single ccache is available
        6. Same results as for steps 3-5
    :customerscenario: False
    """
    kdc.principal("tuser").add(password="Secret123")
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm["ccache_storage"] = ccache_storage
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.cache_count() == 0, "KRB cache is not empty!"

            assert krb.kinit("tuser", password="Secret123").rc == 0, "kinit failed!"
            assert krb.has_tgt("tuser", kdc.realm), "No ticket found!"
            assert krb.cache_count() == 1, "KRB cache value is not 1!"

            assert krb.kinit("tuser", password="Secret123").rc == 0, "kinit failed!"
            assert krb.has_tgt("tuser", kdc.realm), "No ticket found!"
            assert krb.cache_count() == 1, "KRB cache value is not 1!"


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__ccache_holds_multiple_and_all_types_of_principals(client: Client, kdc: KDC, ccache_storage: str):
    """
    :title: Multiple principals and service tickets can be stored in a ccache collection.
    :setup:
        1. Add Kerberos principal "alice" to KDC
        2. Add Kerberos principal "bob" to KDC
        3. Add Kerberos principal "carol" to KDC
        4. Add Kerberos service principal "host/myhost" to KDC
        5. Add local user "tuser"
        6. Set ccache_storage in sssd.conf to @ccache_storage
        7. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Count existing credential caches
        3. Kinit as "alice"
        4. Kinit as "bob"
        5. Kinit as "carol"
        6. Obtain ticket for "host/myhost"
        7. Destroy current primary ccache
        8. Kinit as "carol"
        9. Kdestroy all ccaches
    :expectedresults:
        1. User is logged into the host
        2. Returns 0, no ccache is available
        3. 1 ccache exists, "alice" is the primary ccache, TGT is only ticket in "alice" ccache
        4. 2 ccaches exist, "bob" is the primary ccache, TGT is only ticket in "bob" ccache
        5. 3 ccaches exist, "carol" is the primary ccache, TGT is only ticket in "carol" ccache
        6. 3 ccaches exist, "carol" is the primary ccache, TGT is only ticket in "alice" and "bob" ccache,
           TGT and "host/myhost" are only tickets in "carol" ccache
        7. 2 ccaches exit
        8. 3 ccaches exist, "carol" is the primary ccache, TGT is only ticket in "alice", "bob" and "carol" ccache
        9. No ccache is available
    :customerscenario: False
    """
    kdc.principal("alice").add(password="Secret123")
    kdc.principal("bob").add(password="Secret123")
    kdc.principal("carol").add(password="Secret123")
    kdc.principal("host/myhost").add(password=None)
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm["ccache_storage"] = ccache_storage
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.cache_count() == 0, "KRB cache is not empty!"

            krb.kinit("alice", password="Secret123")
            assert krb.cache_count() == 1, "KRB cache value is not 1!"
            assert krb.has_primary_cache("alice", kdc.realm), "User 'alice' missing in cache!"
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt]), "No ticket for user 'alice' found!"

            krb.kinit("bob", password="Secret123")
            assert krb.cache_count() == 2, "KRB cache value is not 2!"
            assert krb.has_primary_cache("bob", kdc.realm), "User 'bob' missing in cache!"
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt]), "No ticket for user 'bob' found!"

            krb.kinit("carol", password="Secret123")
            assert krb.cache_count() == 3, "KRB cache value is not 3!"
            assert krb.has_primary_cache("carol", kdc.realm), "User 'carol' missing in cache!"
            assert krb.has_tickets("carol", kdc.realm, [kdc.tgt]), "No ticket for user 'carol' found!"

            krb.kvno("host/myhost")
            assert krb.cache_count() == 3, "KRB cache value is not 3!"
            assert krb.has_primary_cache("carol", kdc.realm), "User 'carol' missing in cache!"
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt]), "No ticket for user 'alice' found!"
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt]), "No ticket for user 'bob' found!"
            assert krb.has_tickets(
                "carol", kdc.realm, [kdc.tgt, kdc.qualify("host/myhost")]
            ), "No ticket for user 'carol' found!"

            # kdestroy 'carol' is the last primary cache
            krb.kdestroy()
            assert krb.cache_count() == 2, "KRB cache value is not 2!"

            # kinit 'carol' again
            krb.kinit("carol", password="Secret123")
            assert krb.cache_count() == 3, "KRB cache value is not 3!"
            assert krb.has_primary_cache("carol", kdc.realm), "User 'carol' missing in cache!"
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt]), "No ticket for user 'alice' found!"
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt]), "No ticket for user 'bob' found!"
            assert krb.has_tickets("carol", kdc.realm, [kdc.tgt]), "No ticket for user 'carol' found!"

            # kdestroy all
            krb.kdestroy(all=True)
            assert krb.cache_count() == 0


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kswitch_between_primary_ccaches(client: Client, kdc: KDC, ccache_storage: str):
    """
    :title: Switching between primary ccaches.
    :setup:
        1. Add Kerberos principal "alice" to KDC
        2. Add Kerberos principal "bob" to KDC
        3. Add Kerberos service principal "host/alice" to KDC
        4. Add Kerberos service principal "host/bob" to KDC
        5. Add local user "tuser"
        6. Set ccache_storage in sssd.conf to @ccache_storage
        7. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Count existing credential caches
        3. Kinit as "alice"
        4. Kinit as "bob"
        5. Kswitch to "alice"
        6. Obtain ticket for "host/alice"
        7. Kswitch to "bob"
        8. Obtain ticket for "host/bob"
    :expectedresults:
        1. User is logged into the host
        2. Returns 0, no ccache is available
        3. TGT for "alice" was obtained, "alice" is the primary ccache
        4. TGT for "bob" was obtained, "bob" is the primary ccache
        5. "alice" is the primary ccache
        6. 2 ccaches exit, "alice" has TGT and "host/alice" tickets, "bob" has only TGT
        7. "bob" is the primary ccache
        8. 2 ccaches exit, "alice" has TGT and "host/alice" tickets, "bob" has TGT and "host/bob"
    :customerscenario: False
    """
    kdc.principal("alice").add(password="Secret123")
    kdc.principal("bob").add(password="Secret123")
    kdc.principal("host/alice").add(password=None)
    kdc.principal("host/bob").add(password=None)
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm["ccache_storage"] = ccache_storage
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.cache_count() == 0, "KRB cache is not empty!"

            krb.kinit("alice", password="Secret123")
            assert krb.has_primary_cache("alice", kdc.realm), "User 'alice' missing in cache!"

            krb.kinit("bob", password="Secret123")
            assert krb.has_primary_cache("bob", kdc.realm), "User 'bob' missing in cache!"

            krb.kswitch("alice", kdc.realm)
            assert krb.has_primary_cache("alice", kdc.realm), "User 'alice' missing in cache!"

            krb.kvno("host/alice")
            assert krb.cache_count() == 2, "KRB cache value is not 2!"
            assert krb.has_tickets(
                "alice", kdc.realm, [kdc.tgt, kdc.qualify("host/alice")]
            ), "No ticket for user 'alice' found!"
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt]), "No ticket for user 'bob' found!"

            krb.kswitch("bob", kdc.realm)
            krb.kvno("host/bob")
            assert krb.cache_count() == 2, "KRB cache value is not 2!"
            assert krb.has_tickets(
                "alice", kdc.realm, [kdc.tgt, kdc.qualify("host/alice")]
            ), "No ticket for user 'alice' found!"
            assert krb.has_tickets(
                "bob", kdc.realm, [kdc.tgt, kdc.qualify("host/bob")]
            ), "No ticket for user 'bob' found!"


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__subsidiary_ccaches_are_used_by_the_kcm(client: Client, kdc: KDC, ccache_storage: str):
    """
    :title: Subsidiary ccaches are usable and KCM: without UID can identify the collection.
    :setup:
        1. Add Kerberos principal "alice" to KDC
        2. Add Kerberos principal "bob" to KDC
        3. Add Kerberos service principal "host/alice" to KDC
        4. Add Kerberos service principal "host/bob" to KDC
        5. Add local user "tuser"
        6. Set ccache_storage in sssd.conf to @ccache_storage
        7. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Count existing credential caches
        3. Kinit as "alice"
        4. Obtain ticket for "host/alice"
        5. Kinit as "bob"
        6. Obtain ticket for "host/bob"
        7. Count existing credential caches
        8. Iterate over ccaches using KRB5CCNAME environment variable
        9. List all principals with KRB5CCNAME=KCM:
    :expectedresults:
        1. User is logged into the host
        2. Returns 0, no ccache is available
        3. Is successful
        4. Is successful
        5. Is successful
        6. Is successful
        7. Returns 2
        8. "alice" ccache contains TGT and "host/alice", "bob" ccache contains TGT and "host/bob"
        9. "alice" and "bob" ccaches are available
    :customerscenario: False
    """
    kdc.principal("alice").add(password="Secret123")
    kdc.principal("bob").add(password="Secret123")
    kdc.principal("host/alice").add(password=None)
    kdc.principal("host/bob").add(password=None)
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm["ccache_storage"] = ccache_storage
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.cache_count() == 0, "KRB cache value is not 0!"

            krb.kinit("alice", password="Secret123")
            krb.kvno("host/alice")

            krb.kinit("bob", password="Secret123")
            krb.kvno("host/bob")

            expected = {
                kdc.qualify("alice"): [kdc.tgt, kdc.qualify("host/alice")],
                kdc.qualify("bob"): [kdc.tgt, kdc.qualify("host/bob")],
            }

            assert krb.cache_count() == 2, "KRB cache value is not 2!"
            for principal, ccache in krb.list_ccaches().items():
                principals = krb.list_principals(env={"KRB5CCNAME": ccache})
                assert len(principals) == 1, "Principals count is not 1!"
                assert principal in principals, f"{principal} not in {principals}!"
                assert principals[principal] == expected[principal], "Principal ccache contains incorrect data!"

            principals = krb.list_principals(env={"KRB5CCNAME": "KCM:"})
            assert len(principals) == 2, "KCM principals count is not 2!"
            assert kdc.qualify("alice") in principals, "'alice' not in principals!"
            assert kdc.qualify("bob") in principals, "'bob' not in principals!"
            assert (
                principals[kdc.qualify("alice")] == expected[kdc.qualify("alice")]
            ), "Principal 'alice' in KCM does not match 'alice' in ccache!"
            assert (
                principals[kdc.qualify("bob")] == expected[kdc.qualify("bob")]
            ), "Principal 'bob' in KCM does not match 'bob' in ccache!"


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kdestroy_nocache_throws_no_error(client: Client, kdc: KDC, ccache_storage: str):
    """
    :title: Destroying non-existing cache must not throw an error.
    :setup:
        1. Add local user "tuser"
        2. Set ccache_storage in sssd.conf to @ccache_storage
        3. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Count existing credential caches
        3. Run kdestroy
    :expectedresults:
        1. User is logged into the host
        2. Returns 0, no ccache is available
        3. Returns with return code 0
    :customerscenario: False
    """
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm["ccache_storage"] = ccache_storage
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.cache_count() == 0, "KRB cache value is not 0!"
            try:
                krb.kdestroy()
            except Exception as e:
                assert False, f"Destroying cache raised an error: {e}"


@pytest.mark.importance("critical")
@pytest.mark.authentication
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__tgt_renewal_updates_ticket_as_configured(client: Client, kdc: KDC):
    """
    :title: Automatic ticket-granting ticket renewal.
    :setup:
        1. Add Kerberos principal "tuser" to KDC
        2. Add local user "tuser"
        3. Enable TGT renewal in KCM
        4. Start SSSD
    :steps:
        1. Authenticate as "tuser" over SSH
        2. Kinit as "tuser" and request renewable ticket
        3. Wait until automatic renewal is triggered and check that it was renewed
    :expectedresults:
        1. User is logged into the host
        2. TGT is available
        3. TGT was renewed
    :customerscenario: False
    """
    kdc.principal("tuser").add(password="Secret123")
    client.local.user("tuser").add(password="Secret123")

    client.sssd.common.kcm(kdc)
    client.sssd.kcm.update(
        tgt_renewal="True",
        krb5_renew_interval="1s",
    )
    client.sssd.start()

    with client.ssh("tuser", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            krb.kinit("tuser", password="Secret123", args=["-r", "2s", "-l", "2s"])
            (init_start, _) = krb.list_tgt_times(kdc.realm)
            time.sleep(2)
            (renew_start, _) = krb.list_tgt_times(kdc.realm)

            assert init_start < renew_start, "Initial renewal times exceeds renewal interval!"


@pytest.mark.topology(KnownTopology.Client)
def test_kcm__kinit_user_after_login(client: Client, kdc: KDC):
    """
    :title: kinit is successful after user login
    :setup:
        1. Add 'user1' to kdc and set its password
        2. Add 'user1' to local and set its password
        3. Configure Kerberos to allow KCM tests
    :steps:
        1. Authenticate user with ssh
        2. Authenticate to kerberos
        3. Call "kinit" with correct password
        4. Call "kinit" with wrong password
        5. Call "klist"
    :expectedresults:
        1. User is authenticated
        2. User is authenticated
        3. Call is successful
        4. Call is not successful
        5. Call is successful
    :customerscenario: False
    """
    username = "user1"
    password = "Secret123"

    kdc.principal(username).add(password=password)
    client.local.user(username).add(password=password)
    client.sssd.common.kcm(kdc)

    with client.ssh(username, password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kinit(username, password=password).rc == 0, "kinit failed!"
            with pytest.raises(SSHProcessError):
                krb.kinit(username, password="wrong")
            assert krb.klist().rc == 0, "klist failed!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__debug_log_enabled(client: Client, kdc: KDC):
    """
    :title: Kcm debug is enabled after sssd-kcm restart, when
     "debug_level" in kcm section is set to 9
    :setup:
        1. Add Kerberos principal "user1" to KDC
        2. Add local user "user1"
        3. Remove log files
        4. Set "debug_level" in kcm config section to "0"
        5. Remove kcm log files
        6. Start SSSD
    :steps:
        1. Try to produce some debug messages e.g. kdestroy
        2. Check that kcm debug messages were not generated
        3. Set "debug_level" in kcm config section to "9"
        4. Restart kcm
        5. Try to produce some debug messages e.g. kdestroy
        6. Check that kcm debug messages were generated
    :expectedresults:
        1. No messages were generated
        2. Log file did not get bigger
        3. Successfully set
        4. Successfully restarted
        5. Some messages were generated
        6. Log file did get bigger
    :customerscenario: False
    """

    def kcm_log_length() -> int:
        try:
            output = client.fs.wc(kcm_log_file, lines=True).stdout
            return int(output.split()[0])
        except SSHProcessError:
            return 0

    user = "user1"
    password = "Secret123"
    kcm_log_file = "/var/log/sssd/sssd_kcm.log"

    kdc.principal(user).add(password=password)
    client.local.user(user).add(password=password)
    client.sssd.common.kcm(kdc)

    client.sssd.kcm["debug_level"] = "0"
    client.sssd.config_apply()

    client.ssh(user, password).exec(["rm", "-f", kcm_log_file], raise_on_error=False)
    client.sssd.start()

    start_log_length = kcm_log_length()

    with client.ssh(user, password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            krb.kdestroy()

    end_log_nodebug = kcm_log_length()
    assert start_log_length == end_log_nodebug, "Debug messages present!"

    client.sssd.kcm["debug_level"] = "9"
    client.sssd.config_apply()
    assert client.svc.restart("sssd-kcm").rc == 0, "KCM restart failed!"

    with client.ssh(user, password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            krb.kdestroy()

    end_log_debug = kcm_log_length()
    assert start_log_length + 100 < end_log_debug, "Debug messages missing!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
def test_kcm__ssh_login_creates_kerberos_ticket(client: Client, ldap: LDAP, kdc: KDC):
    """
    :title: kcm: Verify ssh login is successful with kcm as default
    :setup:
        1. Add user and principal
        2. Set kerberos as default auth provider
        3. Start SSSD
    :steps:
        1. Authenticate as "user1" over SSH using kcm
    :expectedresults:
        1. Authenticated successfully
    :customerscenario: False
    """
    ldap.user("user1").add()
    kdc.principal("user1").add()

    client.sssd.common.krb5_auth(kdc)
    client.sssd.domain["krb5_realm"] = kdc.realm
    client.sssd.domain["krb5_server"] = kdc.host.hostname
    client.sssd.start()

    with client.ssh("user1", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            res = krb.klist()
            assert res.rc == 0, "klist failed!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__configure_max_uid_ccaches_with_different_values(client: Client, kdc: KDC):
    """
    :title: "max_uid_ccaches" are enforced and limit only specific user
    :setup:
        1. Add local user "user0" and "user1"
        2. Add 66 Kerberos principals to KDC
        3. Start SSSD
    :steps:
        1. Authenticate as "user0" over SSH
        2. Set "max_uid_ccaches" to "1" and check its enforcement
        3. Remove "max_uid_ccaches" to use the default value
        4. Check the enforcement of quotas
        5. Set "max_uid_ccaches" to "65" and check its enforcement
        6. Kinit principal "user65" as "user1"
        7. Call kdestroy to destroy all caches as "user0"
        8. Kinit principal "user64" as "user0"
    :expectedresults:
        1. Authenticated successfully
        2. "max_uid_ccaches" are properly enforced
        3. Removed successfully
        4. "max_uid_ccaches" are properly enforced
        5. "max_uid_ccaches" are properly enforced
        6. Kinit is successful
        7. Kdestroy is successful
        8. Kinit is successful
    :customerscenario: False
    """
    user0 = "user0"
    user1 = "user1"
    password = "Secret123"
    client.local.user(user0).add(password=password)
    client.local.user(user1).add(password=password)

    for i in range(66):
        user = f"user{i}"
        kdc.principal(user).add(password=password)

    client.sssd.common.kcm(kdc)
    client.sssd.start()

    with client.ssh(user0, password) as ssh:
        with client.auth.kerberos(ssh) as krb:

            # max_uid_ccaches set to 1
            client.sssd.kcm["max_uid_ccaches"] = "1"
            client.sssd.config_apply()
            client.svc.restart("sssd-kcm")
            assert krb.kinit(user0, password=password).rc == 0, "max_uid_ccache = 1, kinit failed!"
            with pytest.raises(SSHProcessError):
                krb.kinit(user1, password=password)

            # max_uid_ccaches set to default (64)
            client.sssd.config.remove_option("kcm", "max_uid_ccaches")
            client.sssd.config_apply()
            client.svc.restart("sssd-kcm")
            for i in range(1, 64):
                user = f"user{i}"
                assert krb.kinit(user, password=password).rc == 0, "max_uid_ccache = 64, kinit failed!"
            with pytest.raises(SSHProcessError):
                krb.kinit("user64", password=password)

            # max_uid_ccaches set to 65
            client.sssd.kcm["max_uid_ccaches"] = "65"
            client.sssd.config_apply()
            client.svc.restart("sssd-kcm")
            assert krb.kinit("user64", password=password).rc == 0, "max_uid_ccache = 65, kinit failed!"
            with pytest.raises(SSHProcessError):
                krb.kinit("user65", password=password)

    # kinit as another user
    with client.ssh(user1, password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kinit("user65", password=password).rc == 0, "kinit failed!"

    # kdestroy and then kinit
    with client.ssh("user0", password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kdestroy(all=True).rc == 0, "kdestroy all tickets failed!"
            assert krb.kinit("user65", password=password).rc == 0, "kinit failed!"

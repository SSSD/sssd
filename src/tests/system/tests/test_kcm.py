"""
KCM responder tests.

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
"""

from __future__ import annotations

import re
import time

import pytest
from pytest_mh.conn import ProcessError
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
    client.sssd.config_apply()

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
            # KCM renews only after ~50% of ticket lifetime (kcm_creds_check_times),
            # and only while the ticket is still valid. Use renew_till > lifetime so
            # renew_till >= endtime holds, and leave a few renew_interval ticks after
            # half-life for the async krb5_child path.
            lifetime_s = 10
            renewable_s = 30
            krb.kinit(
                "tuser",
                password="Secret123",
                args=["-r", f"{renewable_s}s", "-l", f"{lifetime_s}s"],
            )
            init_start, init_end = krb.list_tgt_times(kdc.realm)

            # Half-life + a few renew_interval ticks + slack for child latency.
            deadline = time.monotonic() + (lifetime_s / 2) + 5.0
            renew_start, renew_end = init_start, init_end
            while time.monotonic() < deadline:
                time.sleep(0.5)
                renew_start, renew_end = krb.list_tgt_times(kdc.realm)
                if renew_start > init_start or renew_end > init_end:
                    break

            assert renew_start > init_start or renew_end > init_end, (
                "TGT was not renewed within timeout; "
                f"initial=({init_start}, {init_end}), last=({renew_start}, {renew_end})."
            )


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
            with pytest.raises(ProcessError):
                krb.kinit(username, password="wrong")
            assert krb.klist().rc == 0, "klist failed!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1643053)
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__debug_log_enabled(client: Client, kdc: KDC):
    """
    :title: Restarting only sssd-kcm reloads debug_level without a full SSSD restart
    :description:
        A restart of the sssd-kcm responder alone must pick up a new debug_level
        from the configuration, without restarting the whole SSSD service.
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
        4. Restart only sssd-kcm
        5. Try to produce some debug messages e.g. kdestroy
        6. Check that kcm debug messages were generated
    :expectedresults:
        1. No messages were generated
        2. Log file did not get bigger
        3. Successfully set
        4. sssd-kcm restarts and reloads the new debug_level
        5. Some messages were generated
        6. Log file did get bigger
    :customerscenario: True
    """

    def kcm_log_length() -> int:
        try:
            output = client.fs.wc(kcm_log_file, lines=True).stdout
            return int(output.split()[0])
        except ProcessError:
            return 0

    user = "user1"
    password = "Secret123"
    kcm_log_file = client.sssd.logs.kcm

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
    :title: kcm: Verify ssh login stores the ticket in a KCM ccache named after the user UID
    :setup:
        1. Add user and principal
        2. Set kerberos as default auth provider
        3. Start SSSD
    :steps:
        1. Authenticate as "user1" over SSH using kcm
        2. Run klist inside the SSH session
        3. Check that the ccache name matches "KCM:<uid>" of the logged in user
    :expectedresults:
        1. Authenticated successfully
        2. klist succeeds and shows "Ticket cache: KCM:"
        3. The ccache name contains the user UID
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
            assert "Ticket cache: KCM:" in res.stdout, "ccache is not stored in KCM!"

            uid = ssh.run("id -u").stdout.strip()
            assert f"KCM:{uid}" in res.stdout, "KCM ccache name does not match the user UID!"


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
            with pytest.raises(ProcessError):
                krb.kinit(user1, password=password)

            # max_uid_ccaches set to default (64)
            client.sssd.config.remove_option("kcm", "max_uid_ccaches")
            client.sssd.config_apply()
            client.svc.restart("sssd-kcm")
            for i in range(1, 64):
                user = f"user{i}"
                assert krb.kinit(user, password=password).rc == 0, "max_uid_ccache = 64, kinit failed!"
            with pytest.raises(ProcessError):
                krb.kinit("user64", password=password)

            # max_uid_ccaches set to 65
            client.sssd.kcm["max_uid_ccaches"] = "65"
            client.sssd.config_apply()
            client.svc.restart("sssd-kcm")
            assert krb.kinit("user64", password=password).rc == 0, "max_uid_ccache = 65, kinit failed!"
            with pytest.raises(ProcessError):
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


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__ccache_uid_assigned_to_caller_and_resets_on_kdestroy(client: Client, kdc: KDC):
    """
    :title: KCM ccache is keyed by the caller UID and the cache-id changes after kdestroy
    :setup:
        1. Add Kerberos principals "user1" and "user2"
        2. Add local users "user1" and "user2"
        3. Start SSSD with KCM
    :steps:
        1. Authenticate as "user1" over SSH
        2. Kinit principals "user1" and "user2" from within the "user1" session
        3. Check the primary ccache name is keyed by the caller ("user1") UID and note its cache-id
        4. Run kdestroy -A and kinit "user1" and "user2" again
        5. Check the new ccache is again keyed by the caller UID and its cache-id changed
    :expectedresults:
        1. Authentication succeeds
        2. Both kinit calls succeed
        3. The ccache name is "KCM:<user1_uid>:<cache_id>", keyed by the caller UID
        4. All commands succeed
        5. The ccache is again "KCM:<user1_uid>" and the cache-id differs from the earlier value
    :customerscenario: False
    """
    username1, username2 = "user1", "user2"
    password = "Secret123"
    kdc.principal(username1).add(password=password)
    kdc.principal(username2).add(password=password)
    client.local.user(username1).add(password=password)
    client.local.user(username2).add(password=password)
    client.sssd.common.kcm(kdc)
    client.sssd.start()

    id1 = client.tools.id(username1)
    assert id1 is not None and id1.user.id is not None, f"user '{username1}' not found!"
    uid1 = id1.user.id

    with client.ssh(username1, password) as ssh:
        with client.auth.kerberos(ssh) as krb:
            # Two principals so the KCM collection holds a subsidiary cache with a cache-id.
            assert krb.kinit(username1, password=password).rc == 0, "kinit failed!"
            assert krb.kinit(username2, password=password).rc == 0, "kinit failed!"

            first = krb.klist().stdout
            assert f"KCM:{uid1}" in first, "ccache is not keyed by the caller UID!"
            match = re.search(rf"KCM:{uid1}:(\S+)", first)
            assert match is not None, "ccache name has no cache-id field!"
            cache_id1 = match.group(1)

            krb.kdestroy(all=True)
            assert krb.kinit(username1, password=password).rc == 0, "kinit after kdestroy failed!"
            assert krb.kinit(username2, password=password).rc == 0, "kinit after kdestroy failed!"

            second = krb.klist().stdout
            assert f"KCM:{uid1}" in second, "new ccache is not keyed by the caller UID!"
            match = re.search(rf"KCM:{uid1}:(\S+)", second)
            assert match is not None, "new ccache name has no cache-id field!"
            cache_id2 = match.group(1)

            assert cache_id1 != cache_id2, "cache-id did not change after kdestroy and re-kinit!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__root_kinit_uses_root_uid_in_ccache_name(client: Client, kdc: KDC):
    """
    :title: KCM ccache uses the root UID (0) when root performs kinit
    :setup:
        1. Add Kerberos principal "user1" and local user "user1"
        2. Start SSSD with KCM
    :steps:
        1. As root, kinit as "user1" and run klist
    :expectedresults:
        1. kinit and klist succeed and the ccache name is "KCM:0"
    :customerscenario: False
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.sssd.common.kcm(kdc)
    client.sssd.start()

    result = client.host.conn.run("kinit user1 && klist", input="Secret123")
    assert result.rc == 0, "kinit/klist as root failed!"
    assert "KCM:0" in result.stdout, "root ccache is not keyed by UID 0!"


@pytest.mark.importance("critical")
@pytest.mark.ticket(bz=1441764)
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__cross_user_ccache_access_denied(client: Client, kdc: KDC):
    """
    :title: KCM enforces per-UID credential cache isolation
    :setup:
        1. Add Kerberos principal "user1"
        2. Add local users "user1" and "user2"
        3. Start SSSD with KCM
    :steps:
        1. Authenticate as "user1" and obtain a TGT
        2. As "user2", attempt to read "user1" KCM ccache
        3. As root, attempt to read "user1" KCM ccache
    :expectedresults:
        1. Authentication and kinit succeed
        2. Access is denied
        3. Access is denied (isolation is enforced for root too)
    :customerscenario: True
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.local.user("user2").add(password="Secret123")
    client.sssd.common.kcm(kdc)
    client.sssd.start()

    with client.ssh("user1", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kinit("user1", password="Secret123").rc == 0, "kinit failed!"

    uid = client.host.conn.run("id -u user1").stdout.strip()

    as_user2 = client.host.conn.run(f"su - user2 -s /bin/bash -c 'KRB5CCNAME=KCM:{uid} klist'", raise_on_error=False)
    assert as_user2.rc != 0, "user2 was able to read user1 KCM ccache!"

    as_root = client.host.conn.run(f"KRB5CCNAME=KCM:{uid} klist", raise_on_error=False)
    assert as_root.rc != 0, "root was able to read user1 KCM ccache!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__sssd_fails_to_start_when_kcm_in_services(client: Client, kdc: KDC):
    """
    :title: SSSD refuses to start when "kcm" is listed in the services directive
    :setup:
        1. Configure SSSD with KCM
        2. Add "kcm" to the [sssd] services list
    :steps:
        1. Start SSSD (without config-check, which would reject the config earlier)
    :expectedresults:
        1. SSSD fails to start (non-zero return code)
    :customerscenario: False
    """
    client.sssd.common.kcm(kdc)
    client.sssd.sssd["services"] = "nss, pam, kcm"

    # check_config is disabled so the framework does not raise on the invalid
    # services line before we can observe that the daemon itself fails to start.
    result = client.sssd.start(raise_on_error=False, check_config=False)
    assert result.rc != 0, "SSSD started even though 'kcm' was listed in services!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__socket_path_config_ignored_default_socket_used(client: Client, kdc: KDC):
    """
    :title: KCM [kcm] socket_path option is ignored; responder uses the default Heimdal socket
    :setup:
        1. Add principal "user1" and local user "user1"
        2. Create the custom socket directory and set socket_path in [kcm]
        3. Start SSSD with KCM
    :steps:
        1. Check the sssd-kcm.socket listen path
        2. Authenticate as "user1"
    :expectedresults:
        1. The listen path is the default Heimdal socket, not the configured path
        2. Authentication succeeds
    :customerscenario: False
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.sssd.common.kcm(kdc)

    client.host.conn.run("mkdir -p /var/run/kcm")
    client.sssd.kcm["socket_path"] = "/var/run/kcm/kcm.sock"
    client.sssd.start()
    client.svc.restart("sssd-kcm.socket")

    status = client.svc.status("sssd-kcm.socket")
    assert "/var/run/kcm/kcm.sock" not in status.stdout, "responder listened on the configured socket_path!"
    assert ".heim_org.h5l.kcm-socket" in status.stdout, "responder is not on the default Heimdal socket!"

    with client.ssh("user1", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kinit("user1", password="Secret123").rc == 0, "kinit failed!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__credentials_persist_across_sssd_restart(client: Client, kdc: KDC):
    """
    :title: KCM credential cache is not wiped when SSSD is restarted
    :setup:
        1. Add principal "user1" and local user "user1"
        2. Use the persistent (secdb) ccache storage
        3. Start SSSD with KCM
    :steps:
        1. Kinit as "user1" inside an SSH session
        2. Restart SSSD
        3. Run klist inside the same SSH session
    :expectedresults:
        1. kinit succeeds and a KCM ccache exists
        2. SSSD restarts
        3. klist still shows the same TGT with unchanged validity times
    :customerscenario: False
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.sssd.common.kcm(kdc)
    # secdb is the default backend, but set it explicitly: client.sssd.restart()
    # stops sssd-kcm, which would wipe an in-memory cache.
    client.sssd.kcm["ccache_storage"] = "secdb"
    client.sssd.start()

    with client.ssh("user1", "Secret123") as ssh:
        with client.auth.kerberos(ssh) as krb:
            assert krb.kinit("user1", password="Secret123").rc == 0, "kinit failed!"
            assert krb.has_tgt("user1", kdc.realm), "No TGT after kinit!"
            before = krb.list_tgt_times(kdc.realm)

            client.sssd.restart()

            after_klist = krb.klist()
            assert after_klist.rc == 0, "klist failed after restart!"
            assert "KCM:" in after_klist.stdout, "KCM ccache was wiped by the SSSD restart!"
            assert krb.has_tgt("user1", kdc.realm), "TGT missing after restart!"
            assert (
                krb.list_tgt_times(kdc.realm) == before
            ), "TGT validity times changed across the restart; the ccache was not preserved!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__responder_idle_timeout_shuts_down_responder(client: Client, kdc: KDC):
    """
    :title: KCM responder exits after responder_idle_timeout expires with no activity
    :setup:
        1. Add principal "user1" and local user "user1"
        2. Set responder_idle_timeout = 60 in [kcm] (60s is the enforced minimum)
        3. Start SSSD with KCM
    :steps:
        1. Trigger KCM start via kinit
        2. Wait for longer than the idle timeout (the internal timer ticks every timeout/2)
        3. Check that the sssd_kcm process has exited
    :expectedresults:
        1. kinit succeeds
        2. Timeout elapses with no KCM activity
        3. sssd_kcm is not running
    :customerscenario: False
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.sssd.common.kcm(kdc)
    # SSSD clamps responder_idle_timeout to a 60s minimum (responder_common.c),
    # so anything lower is silently raised to 60. Use the minimum and wait past it.
    client.sssd.kcm["responder_idle_timeout"] = "60"
    client.sssd.start()

    client.host.conn.exec(["kinit", "user1"], input="Secret123")
    time.sleep(90)

    result = client.host.conn.run("pidof sssd_kcm", raise_on_error=False)
    assert result.rc != 0 or not result.stdout.strip(), "sssd_kcm did not shut down after idle timeout!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1545424)
@pytest.mark.topology(KnownTopology.Client)
def test_kcm__activity_resets_idle_timeout(client: Client, kdc: KDC):
    """
    :title: KCM activity resets last_request_time, preventing premature shutdown
    :setup:
        1. Add principal "user1" and local user "user1"
        2. Set responder_idle_timeout = 60 in [kcm] (60s is the enforced minimum)
        3. Start SSSD with KCM
    :steps:
        1. Start sssd-kcm and kinit immediately (first activity)
        2. Wait 45 s (less than the 60s timeout) then kinit again to reset the idle timer
        3. Wait another 50 s
        4. Check that sssd_kcm is still running
    :expectedresults:
        1. kinit succeeds and sssd-kcm is running
        2. kinit succeeds and the idle timer is reset
        3. Total elapsed > 60 s but idle since last request < 60 s
        4. sssd_kcm is still running (without the reset it would have exited at ~60 s)
    :customerscenario: True
    """
    kdc.principal("user1").add(password="Secret123")
    client.local.user("user1").add(password="Secret123")
    client.sssd.common.kcm(kdc)
    # responder_idle_timeout has an enforced 60s minimum, so the reset must be
    # demonstrated across that window: the kinit at t=45s keeps sssd-kcm alive
    # past the t=90s idle tick that would otherwise shut it down.
    client.sssd.kcm["responder_idle_timeout"] = "60"
    client.sssd.start()

    # First activity right after start; no need to wait before the initial kinit.
    client.host.conn.exec(["kinit", "user1"], input="Secret123")
    time.sleep(45)
    client.host.conn.exec(["kinit", "user1"], input="Secret123")
    time.sleep(50)

    result = client.host.conn.run("pidof sssd_kcm", raise_on_error=False)
    assert result.rc == 0 and result.stdout.strip(), "sssd_kcm shut down despite recent activity!"


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1712875)
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.skip(reason="Needs a 2-client system-test topology; tracked as IDM-7741 follow-up")
def test_kcm__gssapi_ssh_credential_delegation(client: Client, kdc: KDC):
    """
    :title: KCM ccache is properly delegated via SSH GSSAPI to a second host
    :setup:
        1. Two client hosts with host keytabs, GSSAPI enabled
        2. LDAP user with KDC principal
        3. Start SSSD
    :steps:
        1. Obtain KCM TGT on host1
        2. SSH from host1 to host2 via GSSAPI
        3. Run klist on host2
    :expectedresults:
        1. TGT obtained
        2. SSH succeeds without password
        3. klist shows delegated ticket with same expiry
    :customerscenario: True
    """


@pytest.mark.importance("low")
@pytest.mark.ticket(bz=1741306)
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.skip(reason="Needs a 2-client system-test topology; tracked as IDM-7741 follow-up")
def test_kcm__sso_passwordless_login_via_keytab(client: Client, kdc: KDC):
    """
    :title: KCM enables SSO passwordless SSH when valid TGT and host keytab are present
    :setup:
        1. Two client hosts with host keytabs
        2. LDAP user with KDC principal
        3. Start SSSD with GSSAPI
    :steps:
        1. Obtain KCM TGT on host1
        2. SSH from host1 to host2 without password
        3. SSH from host1 to itself without password
    :expectedresults:
        1. TGT obtained
        2. Passwordless SSH to host2 succeeds
        3. Passwordless SSH to host1 succeeds
    :customerscenario: True
    """

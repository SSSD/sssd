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
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kinit_overwrite(client: Client, kdc: KDC, ccache_storage: str):
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
        4. Check that TGT was aquired
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
            assert krb.cache_count() == 0

            assert krb.kinit("tuser", password="Secret123").rc == 0
            assert krb.has_tgt("tuser", kdc.realm)
            assert krb.cache_count() == 1

            assert krb.kinit("tuser", password="Secret123").rc == 0
            assert krb.has_tgt("tuser", kdc.realm)
            assert krb.cache_count() == 1


@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kinit_collection(client: Client, kdc: KDC, ccache_storage: str):
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
        7. 2 cacches exit
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
            assert krb.cache_count() == 0

            krb.kinit("alice", password="Secret123")
            assert krb.cache_count() == 1
            assert krb.has_primary_cache("alice", kdc.realm)
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt])

            krb.kinit("bob", password="Secret123")
            assert krb.cache_count() == 2
            assert krb.has_primary_cache("bob", kdc.realm)
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt])

            krb.kinit("carol", password="Secret123")
            assert krb.cache_count() == 3
            assert krb.has_primary_cache("carol", kdc.realm)
            assert krb.has_tickets("carol", kdc.realm, [kdc.tgt])

            krb.kvno("host/myhost")
            assert krb.cache_count() == 3
            assert krb.has_primary_cache("carol", kdc.realm)
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt])
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt])
            assert krb.has_tickets("carol", kdc.realm, [kdc.tgt, kdc.qualify("host/myhost")])

            # kdestroy 'carol' is the last primary cache
            krb.kdestroy()
            assert krb.cache_count() == 2

            # kinit 'carol' again
            krb.kinit("carol", password="Secret123")
            assert krb.cache_count() == 3
            assert krb.has_primary_cache("carol", kdc.realm)
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt])
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt])
            assert krb.has_tickets("carol", kdc.realm, [kdc.tgt])

            # kdestroy all
            krb.kdestroy(all=True)
            assert krb.cache_count() == 0


@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kswitch(client: Client, kdc: KDC, ccache_storage: str):
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
            assert krb.cache_count() == 0

            krb.kinit("alice", password="Secret123")
            assert krb.has_primary_cache("alice", kdc.realm)

            krb.kinit("bob", password="Secret123")
            assert krb.has_primary_cache("bob", kdc.realm)

            krb.kswitch("alice", kdc.realm)
            assert krb.has_primary_cache("alice", kdc.realm)

            krb.kvno("host/alice")
            assert krb.cache_count() == 2
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt, kdc.qualify("host/alice")])
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt])

            krb.kswitch("bob", kdc.realm)
            krb.kvno("host/bob")
            assert krb.cache_count() == 2
            assert krb.has_tickets("alice", kdc.realm, [kdc.tgt, kdc.qualify("host/alice")])
            assert krb.has_tickets("bob", kdc.realm, [kdc.tgt, kdc.qualify("host/bob")])


@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__subsidiaries(client: Client, kdc: KDC, ccache_storage: str):
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
            assert krb.cache_count() == 0

            krb.kinit("alice", password="Secret123")
            krb.kvno("host/alice")

            krb.kinit("bob", password="Secret123")
            krb.kvno("host/bob")

            expected = {
                kdc.qualify("alice"): [kdc.tgt, kdc.qualify("host/alice")],
                kdc.qualify("bob"): [kdc.tgt, kdc.qualify("host/bob")],
            }

            assert krb.cache_count() == 2
            for principal, ccache in krb.list_ccaches().items():
                principals = krb.list_principals(env={"KRB5CCNAME": ccache})
                assert len(principals) == 1
                assert principal in principals
                assert principals[principal] == expected[principal]

            principals = krb.list_principals(env={"KRB5CCNAME": "KCM:"})
            assert len(principals) == 2
            assert kdc.qualify("alice") in principals
            assert kdc.qualify("bob") in principals
            assert principals[kdc.qualify("alice")] == expected[kdc.qualify("alice")]
            assert principals[kdc.qualify("bob")] == expected[kdc.qualify("bob")]


@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.parametrize("ccache_storage", ["memory", "secdb"])
def test_kcm__kdestroy_nocache(client: Client, kdc: KDC, ccache_storage: str):
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
            assert krb.cache_count() == 0
            try:
                krb.kdestroy()
            except Exception as e:
                assert False, f"kdestroy raised an error: {e}"


@pytest.mark.topology(KnownTopology.Client)
def test_kcm__tgt_renewal(client: Client, kdc: KDC):
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
        3. Wait until automatic renewal is triggered and check that is was renewed
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

            assert init_start < renew_start


@pytest.mark.topology(KnownTopology.Client)
def test_kcm__simple_kinit(client: Client, kdc: KDC):
    """
    :title: kinit is successfull after user login
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
            assert krb.kinit(username, password=password).rc == 0, "Kinit with correct password failed"
            with pytest.raises(SSHProcessError):
                krb.kinit(username, password="wrong")
            assert krb.klist().rc == 0, "Klist failed"

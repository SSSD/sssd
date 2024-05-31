"""
Passkey Tests.

:requirement: passkey

The passkey solution only enables to authenticate in a system where the
FIDO2 key is connected physically.This could be su login, the GUI,
or even ssh<user>@localhost.
Here, passkey support is tested with su, tests are running with
umockdev, not with a physical key.
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


def passkey_requires_root(client: Client) -> tuple[bool, str] | bool:
    if client.svc.get_property("sssd", "User") != "root":
        return False, "Passkey tests don't work if SSSD runs under non-root"

    return True


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="passkey")
def test_passkey__register_sssctl(client: Client, moduledatadir: str, testdatadir: str):
    """
    :title: Register a key with sssctl
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use sssctl to register a FIDO2 key.
        2. Check the output.
    :expectedresults:
        1. New key is registered.
        2. Output contains key mapping data.
    :customerscenario: False
    """
    mapping = client.sssctl.passkey_register(
        username="user1",
        domain="ldap.test",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script",
    )

    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip(), "Failed to register a key with sssctl"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
def test_passkey__register_ipa(ipa: IPA, moduledatadir: str, testdatadir: str):
    """
    :title: Register a passkey with the IPA command
    :setup:
        1. Setup IDM client with FIDO and umockdev setup
    :steps:
        1. Use ipa command to register a FIDO2 key.
        2. Check the output that contains the user key mapping data.
    :expectedresults:
        1. New key is registered with IPA command.
        2. Output contains key mapping data.
    :customerscenario: False
    """
    mapping = (
        ipa.user("user1")
        .add()
        .passkey_add_register(
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script",
        )
    )

    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip(), "Failed to register a key with the IPA command"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check su authentication of user with LDAP, IPA, AD and Samba
    :setup:
        1. Add a user in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user.
    :expectedresults:
        1. User su authenticates successfully.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_with_failed_pin(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check su authentication deny of user with LDAP, IPA, AD and Samba with incorrect pin
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user with incorrect PIN.
    :expectedresults:
        1. User failed to su authenticate.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert not client.auth.su.passkey(
        username="user1",
        pin=67890,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_with_incorrect_mapping(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check su authentication deny of user with LDAP, IPA, AD and Samba with incorrect mapping
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user with incorrect passkey mapping.
    :expectedresults:
        1. User failed to su authenticate.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "only"

    # Here, we are using passkey-mapping from the other FIDO2 key.

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert not client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_when_server_is_not_resolvable(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check su authentication of a user with LDAP, IPA, AD and Samba when server is not resolvable
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user.
        2. Update the server url and restart the sssd service to reflect the changes.
        3. Check su authentication of the user.
    :expectedresults:
        1. User su authenticates successfully.
        2. Successfully update the sssd.conf and restarted the sssd service.
        3. User su authenticates successfully due to cached data.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()
    if suffix == "ipa":
        server_url = "ipa_server"
    elif suffix == "ldap":
        server_url = "ldap_uri"
    elif suffix == "samba" or "ad":
        server_url = "ad_server"
    else:
        assert False, "provider not found"

    client.sssd.domain["local_auth_policy"] = "only"

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    # First time check authentication to cache the user
    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

    # Here we are making server/backend offline but not deleting cache and logs.
    client.sssd.config.remove_option("domain/test", server_url)
    client.sssd.domain[server_url] = "ldap://new.server.test"
    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_when_offline(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check offline su authentication of a user with LDAP, IPA, AD and Samba
    :setup:
        1. Add a LDAP, IPA, AD and Samba user with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user.
        2. Make server offline (by blocking traffic to the provider).
        3. Bring SSSD offline explicitly.
        4. Check su offline authentication of the user.
    :expectedresults:
        1. User su authenticated successfully.
        2. Firewall rule added, traffic is dropped.
        3. SSSD is offline.
        4. Offline su authentication is successful.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.domain["local_auth_policy"] = "only"

    client.sssd.start()

    # First time check authentication to cache the user
    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

    # Render the provider offline
    client.firewall.outbound.reject_host(provider)

    # There might be active connections that are not terminated by creating firewall rule.
    # We need to terminated it by bringing SSSD to offline state explicitly.
    client.sssd.bring_offline()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
def test_passkey__lookup_user_from_cache(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Fetch a user from cache for LDAP, IPA, AD and Samba server
    :setup:
        1. Add a user in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check a user lookup.
        2. Check a user from cache using ldbsearch command.
    :expectedresults:
        1. A user looked up successfully.
        2. Successfully get the user from ldbsearch command.
    :customerscenario: False
    """

    suffix = type(provider).__name__.lower()

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    result = client.tools.id("user1")
    output = client.ldb.search(
        path="/var/lib/sss/db/cache_test.ldb", basedn="name=user1@test,cn=users,cn=test,cn=sysdb", filter="userPasskey"
    )
    assert result is not None
    assert output["name=user1@test,cn=users,cn=test,cn=sysdb"] is not None
    assert "name=user1@test,cn=users,cn=test,cn=sysdb" in output.keys(), "user not find in cache"
    assert "userPasskey" in (list(output.values())[0].keys()), "passkey mapping is not found in cache"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_with_multiple_keys(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check su authentication of user when multiple keys added for same user with
            LDAP, IPA, AD and Samba server.
    :setup:
        1. Add a user with multiple mappings of passkey in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user.
    :expectedresults:
        1. User su authenticates successfully.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()
    user_add = provider.user("user1").add()

    client.sssd.domain["local_auth_policy"] = "only"

    for n in range(1, 5):
        with open(f"{testdatadir}/passkey-mapping.{suffix}{n}") as f:
            user_add.passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_same_key_for_other_users(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check su authentication of user when same key added for multiple user with LDAP, IPA, AD and Samba server.
    :setup:
        1. Add three users with same passkey mapping in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user1, user2 and user3.
    :expectedresults:
        1. User1, user2 and user3 su authenticates successfully with same mapping.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "only"

    client.sssd.start()

    for user in ["user1", "user2", "user3"]:
        user_add = provider.user(user).add()
        with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
            user_add.passkey_add(f.read().strip())

        assert client.auth.su.passkey(
            username=user,
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script.{suffix}.{user}",
        )


@pytest.mark.importance("high")
@pytest.mark.ticket(jira="SSSD-7011", gh=7066)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.builtwith(client="passkey", provider="passkey")
def test_passkey__check_passkey_mapping_token_as_ssh_key_only(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check passkey mapping with invalid ssh key with AD, Samba, and LDAP server.
    :setup:
        1. Add a users in AD, Samba and LDAP server and add ssh key as a passkey mapping.
        2. Setup SSSD client with FIDO, start SSSD service.
    :steps:
        1. Check su non-passkey authentication of the user.
        2. Required error message in pam log.
    :expectedresults:
        1. su authenticates the user with correct password.
        2. Get the expected message in pam log.
    :customerscenario: False
    """
    client.sssd.domain["local_auth_policy"] = "enable:passkey"

    with open(f"{testdatadir}/ssh-key") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    # We are running simple su not to check authentication with passkey but just to get
    # expected log message.
    assert client.auth.su.password("user1", "Secret123"), "Password authentication with correct password is failed"

    pam_log = client.fs.read(client.sssd.logs.pam)
    assert "Mapping data found is not passkey related" in pam_log, "String was not found in the logs"


@pytest.mark.importance("high")
@pytest.mark.ticket(jira="SSSD-7011", gh=7066)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_user_when_add_with_ssh_key_and_mapping(
    client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str
):
    """
    :title: Check authentication of user when ssh key and valid passkey mapping added with AD, Samba, and LDAP server.
    :setup:
        1. Add a users in AD, Samba and LDAP server and add ssh key and a passkey mapping.
        2. Setup SSSD client with FIDO, start SSSD service.
    :steps:
        1. Check su passkey authentication of the user.
        2. Required error message in pam log.
    :expectedresults:
        1. su authenticates the user successfully.
        2. Get the expected message in pam log.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "enable:passkey"

    user_add = provider.user("user1").add()
    for mapping in ["ssh-key", f"passkey-mapping.{suffix}"]:
        with open(f"{testdatadir}/{mapping}") as f:
            user_add.passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

    pam_log = client.fs.read(client.sssd.logs.pam)
    assert "Mapping data found is not passkey related" in pam_log, "String was not found in the logs"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.builtwith(client="passkey", provider="passkey")
@pytest.mark.require.with_args(passkey_requires_root)
def test_passkey__su_fips_fido_key(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    """
    :title: Check su authentication of user with LDAP, IPA, AD and Samba with FIPS Fido key
    :setup:
        1. Add a user in LDAP, IPA, AD and Samba with passkey_mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check su authentication of the user.
    :expectedresults:
        1. User su authenticates successfully.
    :customerscenario: False
    """
    suffix = type(provider).__name__.lower()

    client.sssd.domain["local_auth_policy"] = "enable:passkey"

    # Recording files are created in FIPS enabled host with
    # FIPS Fido key.

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

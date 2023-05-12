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


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
@pytest.mark.builtwith(client="passkey")
def test_passkey__register__sssctl(client: Client, moduledatadir: str, testdatadir: str):
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
def test_passkey__register__ipa(ipa: IPA, moduledatadir: str, testdatadir: str):
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
def test_passkey__su(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
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

    if suffix == "ldap":
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
def test_passkey__su_fail_pin(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
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

    if suffix == "ldap":
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
def test_passkey__su_fail_mapping(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
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

    if suffix == "ldap":
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
def test_passkey__su_srv_not_resolvable(
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
        client.sssd.domain["local_auth_policy"] = "only"
    elif suffix == "samba" or "ad":
        server_url = "ad_server"
    else:
        assert False, "provider not found"

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

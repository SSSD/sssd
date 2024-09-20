"""
Passkey Tests.

:requirement: passkey

Passkeys allow users to authenticate without having to enter a username or password,
or provide any additional authentication factor.
This technology aims to replace legacy authentication mechanisms such as passwords.

The objective is to use a passkey to locally authenticate a user against centralized identity management system.
For that purpose an integration with a server like AD/Samba or IPA or LDAP is needed.

The passkey solution only enables to authenticate in a system where the
FIDO2 key is connected physically.This could be su login, the GDM login.
The passkey is another way to authenticate as the user, using a physical token.

We can't support remote authentication (ssh) because there isn't any way of doing the remote authentication
when the key is attached to your laptop.
Here, passkey support is tested with su, tests are running with
umockdev, not with a physical key.

We are creating the recording files and reusing them in test without having passkey connected to host.
To create the recording files we have to connect passkey and need biometric
authentication such as pin and finger touch.

we use sssctl tool to create the passkey-mapping.
# sssctl passkey-register --username=<username> --domain=<domain name>
Next, it will ask for PIN and generate the passkey-mapping and token.

.. code-block::
    mapping = client.sssctl.passkey_register(
        username="user1",
        domain="ldap.test",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script",
    )

Once we add user along with passkey-mapping, we can test/assert the passkey authentication.
While authenticating we need to username, pin of passkey and some recording files which will use for authenticating
the user.

.. code-block::
    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

For IPA tests where we need to test commands after authentication of user, we the use following code.
Here, we have an extra argument as a command to test in session after authentication of user.
It returns returncode either 0 or 1 and output to fetch the console messages.

.. code-block::
    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="klist",
    )
"""

from __future__ import annotations

import re

import pytest
from pytest_mh import mh_fixture
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup
from sssd_test_framework.utils.authentication import PasskeyAuthenticationUseCases


@mh_fixture()
def umockdev_ipaotpd_update(ipa: IPA, request: pytest.FixtureRequest):
    """
    Update the ipa-optd@.service file from ipa server with
    'Environment=LD_PRELOAD=/opt/random.so' to avoid the data mismatch
    error while running the umockdev-run command while authenticating the user.
    """
    ipa.fs.append("/usr/lib/systemd/system/ipa-otpd@.service", "Environment=LD_PRELOAD=/opt/random.so")
    ipa.svc.restart("ipa")


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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

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

    client.sssd.start(service_user="root")

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
def test_passkey__check_tgt(client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update):
    """
    :title: Check the TGT of user after authentication.
    :setup:
        1. Add a user with --user-auth-type=passkey in the server with passkey mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user
        2. Check TGT after authenticates.
    :expectedresults:
        1. User authenticates successfully.
        2. Gets the TGT.
    :customerscenario: False
    """
    with open(f"{testdatadir}/passkey-mapping.ipa") as f:
        ipa.user("user1").add(user_auth_type="passkey").passkey_add(f.read().strip())

    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="klist",
    )

    assert rc == 0, "Authentication failed"
    assert "Ticket cache" in output, "Failed to get the TGT"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
def test_passkey__ipa_server_offline(
    client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update
):
    """
    :title: Check the authentication of user after kdestroy and when ipa service stop.
    :setup:
        1. Add a user with --user-auth-type=passkey in the server with passkey mapping.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user and TGT after authentication.
        2. Remove the tgt using #kdestroy -A and stop the IPA service.
        3. Check the authentication again.
        4. Check that the user has been informed that the TGT ticket has not been granted.
    :expectedresults:
        1. User authenticates successfully and gets the TGT.
        2. Successfully remove the TGT and IPA is not reachable.
        3. User authenticate successfully, did not get TGT of user.
        4.  User has been correctly informed.
    :customerscenario: False
    """
    with open(f"{testdatadir}/passkey-mapping.ipa") as f:
        ipa.user("user1").add(user_auth_type="passkey").passkey_add(f.read().strip())

    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="kdestroy -A",
    )

    assert rc == 0, "Authentication failed"
    ipa.svc.stop("ipa")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="klist",
    )

    assert rc == 0, "Authentication failed"
    assert (
        "No Kerberos TGT granted as the server does not support this method. "
        "Your single-sign on(SSO) experience will be affected"
    ) in output, "Failed to get console message"
    klist_check = re.search(r"klist: Credentials cache.* not found", output)
    assert klist_check, "Credential cache found"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
@pytest.mark.ticket(gh=6931)
def test_passkey__su_with_12_mappings(
    client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update
):
    """
    :title: Check authentication of user with IPA server when passkey mappings are 12 for a user
    :setup:
        1. Add a user with --user-auth-type=passkey in the server with 12 passkey mappings.
        2. Setup SSSD client with FIDO and umockdev, start SSSD service.
    :steps:
        1. Check authentication of the user.
        2. Check the TGT of user.
        3. Check that the user isn't informed about the degraded user experience due to not obtaining the TGT ticket.
    :expectedresults:
        1. User authenticates successfully.
        2. Get TGT after authentication of user.
        3. Not getting the message after authentication.
    :customerscenario: False
    """
    user_add = ipa.user("user1").add(user_auth_type="passkey")

    for n in range(1, 13):
        with open(f"{testdatadir}/passkey-mapping.ipa{n}") as f:
            user_add.passkey_add(f.read().strip())

    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="klist",
    )

    assert rc == 0, "Authentication failed"
    assert "Ticket cache" in output, "Failed to get the TGT"
    assert (
        not (
            "No Kerberos TGT granted as the server does not support this method. "
            "Your single-sign on(SSO) experience will be affected"
        )
        in output
    ), "Get the console message about TGT"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
@pytest.mark.ticket(gh=6931)
def test_passkey__su_no_pin_set(
    client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update
):
    """
    :title: Check authentication of user with IPA server when no pin set for the Passkey
    :setup:
        1. Add a user with --user-auth-type=passkey in the IPA server
        2. Modify Passkey configuration to set require user verification during authentication to false
        3. Setup SSSD client with FIDO and umockdev, start SSSD service
    :steps:
         1. Check authentication of the user when no pin set for the Passkey
         2. Check the TGT of user
    :expectedresults:
        1. User authenticates successfully
        2. Get TGT after authentication of user
    :customerscenario: False
    """
    with open(f"{testdatadir}/passkey-mapping.ipa") as f:
        ipa.user("user1").add(user_auth_type="passkey").passkey_add(f.read().strip())

    ipa.host.conn.run("ipa passkeyconfig-mod --require-user-verification=False", raise_on_error=False)
    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        command="klist",
        auth_method=PasskeyAuthenticationUseCases.PASSKEY_NO_PIN_NO_PROMPTS,
    )

    assert rc == 0, "Authentication failed"
    assert "Ticket cache" in output, "Failed to get the TGT"
    assert not (
        (
            "No Kerberos TGT granted as the server does not support this method. "
            "Your single-sign on(SSO) experience will be affected"
        )
        in output
    ), "Got the console message about No Kerberos TGT granted"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
@pytest.mark.ticket(gh=6931)
def test_passkey__prompt_options(
    client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update
):
    """
    :title: Check authentication of user with updated prompting options
    :setup:
        1. Add a user in the server with passkey mappings
        2. Add the prompting options to sssd.conf file
        3. Setup SSSD client with FIDO and umockdev, start SSSD service
    :steps:
        1. Check authentication of the user
        2. Check the updated prompt options
    :expectedresults:
        1. User authenticates successfully
        2. Got the updated prompt options
    :customerscenario: False
    """
    with open(f"{testdatadir}/passkey-mapping.ipa") as f:
        ipa.user("user1").add(user_auth_type="passkey").passkey_add(f.read().strip())

    client.sssd.section("prompting/passkey")["interactive"] = "True"
    client.sssd.section("prompting/passkey")["interactive_prompt"] = "Please, insert the passkey and press enter"
    client.sssd.section("prompting/passkey")["touch"] = "True"
    client.sssd.section("prompting/passkey")["touch_prompt"] = "Can you touch the passkey"
    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        pin=123456,
        interactive_prompt="Please, insert the passkey and press enter",
        touch_prompt="Can you touch the passkey",
        command="klist",
        auth_method=PasskeyAuthenticationUseCases.PASSKEY_PIN_AND_PROMPTS,
    )

    assert rc == 0, "Authentication failed"
    assert "Ticket cache" in output, "Failed to get the TGT"
    assert (
        not (
            "No Kerberos TGT granted as the server does not support this method."
            "Your single-sign on(SSO) experience will be affected"
        )
        in output
    ), "Got the console message about No Kerberos TGT granted"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.builtwith(client="passkey", ipa="passkey")
@pytest.mark.ticket(gh=7143)
def test_passkey__su_fallback_to_password(
    client: Client, ipa: IPA, moduledatadir: str, testdatadir: str, umockdev_ipaotpd_update
):
    """
    :title: Check password authentication of user with IPA server when sssd fall back to password authentication
    :setup:
        1. Add a user with --user-auth-type=passkey, password in the IPA server
        2. Setup SSSD client with FIDO and umockdev, start SSSD service
    :steps:
        1. Check authentication of the user with password
        2. Check the TGT of user
    :expectedresults:
        1. User authenticates successfully
        2. Get TGT after authentication of user
    :customerscenario: False
    """
    with open(f"{testdatadir}/passkey-mapping.ipa") as f:
        ipa.user("user1").add(user_auth_type=["passkey", "password"]).passkey_add(f.read().strip())

    client.sssd.start(service_user="root")

    rc, _, output, _ = client.auth.su.passkey_with_output(
        username="user1",
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.ipa",
        pin="\\n",
        command="klist",
        auth_method=PasskeyAuthenticationUseCases.PASSKEY_FALLBACK_TO_PASSWORD,
    )

    assert rc == 0, "Authentication failed"
    assert "Ticket cache" in output, "Failed to get the TGT"
    assert (
        not (
            "No Kerberos TGT granted as the server does not support this method."
            " Your single-sign on(SSO) experience will be affected"
        )
        in output
    ), "Got the console message about No Kerberos TGT granted"

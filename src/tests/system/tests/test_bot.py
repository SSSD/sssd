"""
Bot Account Tests

Tests for bot account lookups via SSSD. Bot accounts use the naming format
``BOT~UID~RANDOM`` and resolve to the underlying user by UID when
``bot_accounts_enabled`` is set.

:requirement: Bot Accounts
"""

from __future__ import annotations

from typing import Callable

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology

BOT_SHELL = "/usr/bin/sss-confined-shell"


def bot_short(ipa: IPA, bot_name: str) -> str:
    return bot_name


def bot_fqn(ipa: IPA, bot_name: str) -> str:
    return ipa.fqn(bot_name)


def bot_realm(ipa: IPA, bot_name: str) -> str:
    return f"{bot_name}@{ipa.realm}"


PARAMETRIZE_NAME = [bot_short, bot_fqn, bot_realm]


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("qualify", PARAMETRIZE_NAME)
def test_bot__lookup_with_bot_accounts_enabled(client: Client, ipa: IPA, qualify: Callable[[IPA, str], str]):
    """
    :title: Lookup bot account with bot_accounts_enabled
    :setup:
        1. Create user with specific UID
        2. Configure SSSD with "bot_accounts_enabled = true" and start SSSD
    :steps:
        1. Lookup user using bot name via getent passwd
        2. Check the result
    :expectedresults:
        1. User is found
        2. User has the bot name, correct UID and bot shell
    :customerscenario: False
    """
    uid = 10001
    gid = 10001
    ipa.user("user1").add(uid=uid, gid=gid)

    client.sssd.domain["bot_accounts_enabled"] = "true"
    client.sssd.start()

    bot_name = qualify(ipa, f"BOT~{uid}~random")
    result = client.tools.getent.passwd(bot_name)
    assert result is not None, f"Bot account '{bot_name}' was not found!"
    assert result.name == f"BOT~{uid}~random", f"Username '{result.name}' is incorrect!"
    assert result.uid == uid, f"UID {result.uid} is incorrect, {uid} expected!"
    assert result.gid == gid, f"GID {result.gid} is incorrect, {gid} expected!"
    assert result.shell == BOT_SHELL, f"Shell '{result.shell}' is incorrect, '{BOT_SHELL}' expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("qualify", PARAMETRIZE_NAME)
def test_bot__lookup_with_bot_accounts_disabled(client: Client, ipa: IPA, qualify: Callable[[IPA, str], str]):
    """
    :title: Lookup bot account with bot_accounts_enabled disabled
    :setup:
        1. Create user with specific UID
        2. Start SSSD without bot_accounts_enabled (default is false)
    :steps:
        1. Lookup user using bot name via getent passwd
    :expectedresults:
        1. User is not found
    :customerscenario: False
    """
    uid = 10001
    ipa.user("user1").add(uid=uid, gid=uid)

    client.sssd.domain["bot_accounts_enabled"] = "false"
    client.sssd.start()

    bot_name = qualify(ipa, f"BOT~{uid}~random")
    result = client.tools.getent.passwd(bot_name)
    assert result is None, f"Bot account '{bot_name}' should not be found when bot_accounts_enabled is false!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
@pytest.mark.parametrize("qualify", PARAMETRIZE_NAME)
def test_bot__lookup_initgroups(client: Client, ipa: IPA, qualify: Callable[[IPA, str], str]):
    """
    :title: Lookup bot account initgroups
    :setup:
        1. Create user and group, add user to the group
        2. Configure SSSD with "bot_accounts_enabled = true" and start SSSD
    :steps:
        1. Lookup initgroups using bot name via getent initgroups
        2. Check the result
    :expectedresults:
        1. User is found
        2. User is a member of the group
    :customerscenario: False
    """
    uid = 10001
    gid = 10001
    ipa.user("user1").add(uid=uid, gid=gid)
    ipa.group("group1").add(gid=20001).add_member(ipa.user("user1"))

    client.sssd.domain["bot_accounts_enabled"] = "true"
    client.sssd.start()

    bot_name = qualify(ipa, f"BOT~{uid}~random")

    result = client.tools.getent.passwd(bot_name)
    assert result is not None, f"Bot account '{bot_name}' was not found!"
    assert result.gid == gid, f"GID {result.gid} is incorrect, {gid} expected!"

    initgroups = client.tools.getent.initgroups(bot_name)
    assert initgroups is not None, f"Initgroups for bot account '{bot_name}' was not found!"
    assert initgroups.memberof([20001]), "User is not a member of 'group1'!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_bot__lookup_by_uid_returns_real_user(client: Client, ipa: IPA):
    """
    :title: Lookup by UID returns real user, not bot name
    :setup:
        1. Create user with specific UID
        2. Configure SSSD with "bot_accounts_enabled = true" and start SSSD
    :steps:
        1. Lookup user by UID via getent passwd
        2. Check the result
    :expectedresults:
        1. User is found
        2. User has the real username and correct UID
    :customerscenario: False
    """
    uid = 10001
    ipa.user("user1").add(uid=uid, gid=uid)

    client.sssd.domain["bot_accounts_enabled"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd(uid)
    assert result is not None, f"User with UID {uid} was not found!"
    assert result.name == "user1", f"Username '{result.name}' is incorrect, 'user1' expected!"
    assert result.uid == uid, f"UID {result.uid} is incorrect, {uid} expected!"
    assert result.shell != BOT_SHELL, "Shell should not be bot shell for direct UID lookup!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_bot__lookup_with_different_random_parts(client: Client, ipa: IPA):
    """
    :title: Bot accounts with different random parts resolve to the same user
    :setup:
        1. Create user with specific UID
        2. Configure SSSD with "bot_accounts_enabled = true" and start SSSD
    :steps:
        1. Lookup user using bot name with random part "aaa"
        2. Lookup user using bot name with random part "bbb"
        3. Check the results
    :expectedresults:
        1. User is found
        2. User is found
        3. Both lookups return the same UID
    :customerscenario: False
    """
    uid = 10001
    ipa.user("user1").add(uid=uid, gid=uid)

    client.sssd.domain["bot_accounts_enabled"] = "true"
    client.sssd.start()

    result_a = client.tools.getent.passwd(f"BOT~{uid}~aaa")
    assert result_a is not None, "Bot account 'BOT~10001~aaa' was not found!"
    assert result_a.name == f"BOT~{uid}~aaa"
    assert result_a.uid == uid

    result_b = client.tools.getent.passwd(f"BOT~{uid}~bbb")
    assert result_b is not None, "Bot account 'BOT~10001~bbb' was not found!"
    assert result_b.name == f"BOT~{uid}~bbb"
    assert result_b.uid == uid


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_bot__memcache_lookup_with_bot_accounts_enabled(client: Client, ipa: IPA):
    """
    :title: Bot account is found from memcache when bot_accounts_enabled is true
    :setup:
        1. Create user with specific UID
        2. Configure SSSD with "bot_accounts_enabled = true" and start SSSD
    :steps:
        1. Lookup user by name to populate memcache
        2. Stop SSSD so only memcache is available
        3. Lookup user using bot name via getent passwd
        4. Check the result
    :expectedresults:
        1. User is found and cached in memcache
        2. SSSD is stopped
        3. User is found from memcache
        4. User has the bot name, correct UID and bot shell
    :customerscenario: False
    """
    uid = 10001
    gid = 10001
    ipa.user("user1").add(uid=uid, gid=gid, gecos="User 1", home="/home/user1")

    client.sssd.domain["bot_accounts_enabled"] = "true"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User 'user1' was not found!"
    assert result.uid == uid

    client.sssd.stop()

    bot_name = f"BOT~{uid}~random"
    result = client.tools.getent.passwd(bot_name)
    assert result is not None, f"Bot account '{bot_name}' was not found in memcache!"
    assert result.name == bot_name, f"Username '{result.name}' is incorrect!"
    assert result.uid == uid, f"UID {result.uid} is incorrect, {uid} expected!"
    assert result.gid == gid, f"GID {result.gid} is incorrect, {gid} expected!"
    assert result.gecos == "User 1", f"Gecos '{result.gecos}' is incorrect, 'User 1' expected!"
    assert result.home == "/home/user1", f"Home '{result.home}' is incorrect, '/home/user1' expected!"
    assert result.shell == BOT_SHELL, f"Shell '{result.shell}' is incorrect, '{BOT_SHELL}' expected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.IPA)
def test_bot__memcache_lookup_with_bot_accounts_disabled(client: Client, ipa: IPA):
    """
    :title: Bot account is not found from memcache when bot_accounts_enabled is false
    :setup:
        1. Create user with specific UID
        2. Start SSSD without bot_accounts_enabled (default is false)
    :steps:
        1. Lookup user by name to populate memcache
        2. Stop SSSD so only memcache is available
        3. Lookup user using bot name via getent passwd
    :expectedresults:
        1. User is found and cached in memcache
        2. SSSD is stopped
        3. Bot account is not found
    :customerscenario: False
    """
    uid = 10001
    gid = 10001
    ipa.user("user1").add(uid=uid, gid=gid)

    client.sssd.domain["bot_accounts_enabled"] = "false"
    client.sssd.start()

    result = client.tools.getent.passwd("user1")
    assert result is not None, "User 'user1' was not found!"
    assert result.uid == uid

    client.sssd.stop()

    bot_name = f"BOT~{uid}~random"
    result = client.tools.getent.passwd(bot_name)
    assert result is None, f"Bot account '{bot_name}' should not be found when bot_accounts_enabled is false!"

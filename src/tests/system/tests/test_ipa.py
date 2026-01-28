"""
IPA Tests
"""

from __future__ import annotations


import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.IPA)
def test_ipa__subids_configured(client: Client, ipa: IPA):
    """
    :title: SSSD can read subid ranges configured in IPA
    :setup:
        1. Create a user with generated subids and one without
        2. Configure and start SSSD with subids
    :steps:
        1. Lookup the uid start range and range size for all users
        2. Lookup the gid start range and range size for all users
    :expectedresults:
        1. The values from the client matches the server values  when the user has subids
        2. The values from the client matches the server values when the user has subids
    :customerscenario: False
    :requirement: subids
    """
    user = ipa.user("user1").add()
    ipa.user("user2").add()
    ipa_sub = user.subid().generate()

    client.sssd.common.subid()
    client.sssd.start()

    subuid = client.tools.getsubid("user1")
    assert subuid is not None, "Found no subuids for User1!"
    assert (
        ipa_sub.uid_start == subuid.range_start
    ), f"User1 subordinate UID range start value {subuid.range_start} does not match: {ipa_sub.uid_start}!"
    assert (
        ipa_sub.uid_size == subuid.range_size
    ), f"User1 subordinate UID range size value {subuid.range_size} does not match: {ipa_sub.uid_size}!"
    assert client.tools.getsubid("user2") is None, "User2 has unexpected subuids configured!"

    subgid = client.tools.getsubid("user1", group=True)
    assert subgid is not None, "Found no subgids for User1"
    assert (
        ipa_sub.gid_start == subgid.range_start
    ), f"User1 subordinate GID range start value {subgid.range_start} does not match: {ipa_sub.gid_start}!"
    assert (
        ipa_sub.gid_size == subgid.range_size
    ), f"User1 subordinate GID range size value {subgid.range_size} does not match: {ipa_sub.gid_size}!"
    assert client.tools.getsubid("user2", group=True) is None, "User2 has unexpected subgids configured!"

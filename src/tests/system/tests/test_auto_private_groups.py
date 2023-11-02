"""
Automation of auto private groups

:requirement: IDM-SSSD-REQ: SSSD can automatically create\
 user private groups for users
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.ticket(bz=1695577)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_auto_private_groups__hybrid(client: Client, provider: GenericProvider):
    """
    :title: auto_private_groups set to hybrid
    :setup:
        1. Add user "user_same" with uid equals to gid
        2. Add user "user_different" with uid not equals to gid
        3. Set auto_private_groups in sssd.conf to hybrid and turn of ldap_id_mapping
        4. Start SSSD
    :steps:
        1. getent passwd "user_same"
        2. getent passwd "user_different"
    :expectedresults:
        1. Uid equals to gid
        2. Uid does not equal to gid
    :customerscenario: True
    """
    provider.user("user_same").add(uid=111111, gid=111111)
    provider.user("user_different").add(uid=111111, gid=100000)

    client.sssd.domain["auto_private_groups"] = "hybrid"
    client.sssd.domain["ldap_id_mapping"] = "false"

    client.sssd.start()

    result = client.tools.getent.passwd("user_same@test")
    assert result, "getent passwd failed on user_same"
    assert result.uid == result.gid, "gid and uid for user_same are not same"

    result = client.tools.getent.passwd("user_different@test")
    assert result, "getent passwd failed on user_different"
    assert result.uid != result.gid, "gid and uid for user_different are same"

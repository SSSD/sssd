"""
SSSD smart card authentication test

:requirement: smartcard_authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_smartcard__su_as_local_user(client: Client):
    """
    :title: Test smart card initialization for local user
    :setup:
        1. Setup and initialize smart card for user
    :steps:
        1. Authenticate as local user using smart card and issue command 'whoami'
    :expectedresults:
        1. Login successful and command returns local user
    :customerscenario: True
    """
    client.local.user("localuser1").add()
    client.smartcard.setup_local_card(client, "localuser1")
    result = client.host.conn.run("su - localuser1 -c 'su - localuser1 -c whoami'", input="123456")
    assert "PIN" in result.stderr, "String 'PIN' was not found in stderr!"
    assert "localuser1" in result.stdout, "'localuser1' not found in 'whoami' output!"

"""
SSSD Smart Card Authentication Test

:requirement: smartcard_authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_smart_card_setup(client: Client):
    """
    :title: Test Smart Card Initialization for Local User
    :setup:
        1. Setup and initialize a smart card for user 'localuser1'
        2. Ensure the smart card is properly associated with the user on the client
    :steps:
        1. Simulate smart card login using 'su' with user 'localuser1'
        2. Provide the PIN via stdin
    :expectedresults:
        1. Prompt for smart card PIN appears in stderr
        2. Successful authentication returns 'localuser1' in stdout
    :customerscenario: True
    """
    client.smart_card.setup_local_card(client, "localuser1")

    result = client.host.conn.run("su - localuser1 -c 'su - localuser1 -c whoami'", input="123456")
    assert "PIN" in result.stderr
    assert "localuser1" in result.stdout

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
    Test initialization of the smart card.
    """

    client.smart_card.setup_local_card(client, 'localuser1')

    pytest.set_trace()
    result = client.host.conn.run("su - localuser1 -c 'su - localuser1 -c whoami'", input="123456")
    assert "PIN" in result.stderr
    assert "localuser1" in result.stdout

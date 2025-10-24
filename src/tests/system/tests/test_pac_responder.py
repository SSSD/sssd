"""
Tests for SSSD's PAC responder.

:requirement: /opt/sss_pac_responder_client is available
"""

from __future__ import annotations

import pytest
from pytest_mh.conn import ProcessTimeoutError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("low")
@pytest.mark.ticket(gh=4544)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_multithreaded_pac_client(client: Client):
    """
    :title: Multithreaded PAC responder test
    :description: Test the PAC responder with a multithreaded client, if present
    :setup:
        1. Check if /opt/sss_pac_responder_client is present otherwise skip the test
        2. Start SSSD
    :steps:
        1. Run /opt/sss_pac_responder_client
    :expectedresults:
        1. Returns successfully in less than 10s
    :customerscenario: True
    """

    test_client = "/opt/sss_pac_responder_client"

    if not client.fs.exists(test_client):
        pytest.skip(f"{test_client} is not available, skipping test")

    client.sssd.restart()

    try:
        client.host.conn.run(test_client, timeout=10)
    except ProcessTimeoutError:
        assert False, f"{test_client} run into timeout, maybe one thread is locked."

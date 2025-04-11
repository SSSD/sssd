"""
SSSD Authentication Test Cases

:requirement: authentication
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopologyGroup
from unittest.mock import patch, MagicMock


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_smart_card_setup(client:Client):
    """
    Test initialization of the smart card.
    """
    client.setup_smart_card(label="TestToken", so_pin="123456", user_pin="1234")

@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_generate_ca_cert(client: Client):
    """
    Test that `generate_ca_cert()` creates a CA key and certificate.
    """
    # Mock the SSH connection to avoid real OpenSSL calls
    mock_exec = MagicMock()
    client.host.conn.exec = mock_exec

    # Call the method
    key_path, cert_path = client.smart_card.generate_ca_cert(
        key_path="/tmp/test_ca.key",
        cert_path="/tmp/test_ca.crt",
        subj="/CN=Test CA"
    )

    # Verify OpenSSL commands were called correctly
    mock_exec.assert_any_call([
        "openssl", "genrsa", "-out", "/tmp/test_ca.key", "2048"
    ])
    mock_exec.assert_any_call([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", "/tmp/test_ca.key",
        "-sha256", "-days", "365",
        "-out", "/tmp/test_ca.crt",
        "-subj", "/CN=Test CA"
    ])

    # Verify returned paths
    assert key_path == "/tmp/test_ca.key"
    assert cert_path == "/tmp/test_ca.crt"

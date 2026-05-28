"""
SSSD smart card pinpad authentication tests.

:requirement: smartcard_authentication
"""

from __future__ import annotations

import pytest
from pytest_mh.cli import CLIBuilderArgs
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology

OPENSC_MODULE = "/usr/lib64/pkcs11/opensc-pkcs11.so"
P11_CHILD_LOG = "/var/log/sssd/p11_child.log"
TOKEN_LABEL = "MyEID"


def detect_pinpad_reader(client: Client) -> None:
    """
    Skip the test if no smart card reader with the expected token is
    detected.

    The reader, card, pcscd, OpenSC pinpad support and the pinpad
    certificate must all be set up before the test runs.

    :param client: Client role object.
    :type client: Client
    """
    reader_result = client.host.conn.run("opensc-tool --list-readers", raise_on_error=False)
    if reader_result.rc != 0 or "no readers found" in reader_result.stdout.lower():
        pytest.skip("No smart card reader detected")

    args: CLIBuilderArgs = {
        "module": (client.host.cli.option.VALUE, OPENSC_MODULE),
        "list-slots": (client.host.cli.option.SWITCH, True),
    }
    slot_result = client.host.conn.run(client.host.cli.command("pkcs11-tool", args), raise_on_error=False)
    if slot_result.rc != 0 or "token" not in slot_result.stdout.lower():
        pytest.skip("Smart card reader found but no token present — insert a card")

    if TOKEN_LABEL.lower() not in slot_result.stdout.lower():
        pytest.skip(
            f"Token found but does not match expected label '{TOKEN_LABEL}' — "
            f"insert the correct card. Found: {slot_result.stdout}"
        )


def ensure_pcscd_accessible(client: Client) -> None:
    """
    Verify that ``p11_child`` (running as the sssd user) can reach the
    smart card reader through pcscd.

    :param client: Client role object.
    :type client: Client
    """
    args: CLIBuilderArgs = {
        "module": (client.host.cli.option.VALUE, OPENSC_MODULE),
        "list-slots": (client.host.cli.option.SWITCH, True),
    }
    verify = client.host.conn.run(
        f"runuser -u sssd -- {client.host.cli.command('pkcs11-tool', args)}",
        raise_on_error=False,
    )
    if verify.rc != 0 or "token" not in verify.stdout.lower():
        pytest.skip(
            "pcscd is not accessible to the sssd user — "
            f"rc={verify.rc}, out={verify.stdout}, err={verify.stderr}"
        )


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_smartcard_pinpad__su_as_local_user(client: Client):
    """
    :title: Local user smart card authentication with pinpad reader
    :setup:
        1. Verify that a pinpad smart card reader with the expected token is connected
        2. Create local user and configure SSSD for smart card authentication
    :steps:
        1. Authenticate as the local user via nested ``su``
        2. Check PAM responder log for protected authentication path detection
        3. Check p11_child log for login errors
    :expectedresults:
        1. PAM prompts with ``Use external keypad`` (not keyboard PIN), authentication
           succeeds, and ``whoami`` returns the local username
        2. PAM log contains ``protected authentication path [true]``
        3. No ``C_Login failed`` in the p11_child log
    :customerscenario: True
    """
    detect_pinpad_reader(client)
    username = "pinpadlocal1"
    client.local.user(username).add()

    ensure_pcscd_accessible(client)

    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.common.local()
    client.sssd.dom("local")["local_auth_policy"] = "only"
    client.sssd.section(f"certmap/local/{username}")["matchrule"] = "<SUBJECT>.*CN=MyEID User.*"
    client.sssd.pam["pam_cert_auth"] = "True"
    client.sssd.pam["p11_child_timeout"] = "60"
    client.sssd.start(debug_level="0xFFF0", check_config=False)

    result = client.host.conn.run(
        f"su - {username} -c 'su - {username} -c whoami'",
        raise_on_error=False,
    )

    output = result.stdout + result.stderr
    assert "Use external keypad" in output, (
        f"Expected 'Use external keypad' prompt but got: " f"stdout={result.stdout!r}, stderr={result.stderr!r}"
    )
    for line in output.splitlines():
        if "PIN for" in line:
            assert "Use external keypad" in line, f"Found keyboard-style PIN prompt instead of keypad prompt: {line}"
    assert result.rc == 0, (
        f"Authentication failed with rc={result.rc}, " f"stdout={result.stdout!r}, stderr={result.stderr!r}"
    )
    assert username in result.stdout, f"'{username}' not found in whoami output: {result.stdout}"

    pam_log = client.fs.read("/var/log/sssd/sssd_pam.log")
    assert "Found protected authentication path [true]" in pam_log, (
        "PAM responder did not find 'protected authentication path [true]' "
        "in p11_child response — CKF_PROTECTED_AUTHENTICATION_PATH may "
        "not be detected"
    )

    p11_log = client.fs.read(P11_CHILD_LOG)
    assert "C_Login failed" not in p11_log, f"p11_child logged a C_Login failure: {p11_log}"

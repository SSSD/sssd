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
TOKEN_LABEL = "SSSD Test Token"
TOKEN_PIN = "123456"
CERT_ID = "02"
CERT_SUBJ = "/CN=SSSD Test Cert"

USB_RESET_SCRIPT = (
    "import fcntl, os\n"
    "USBDEVFS_RESET = 21780\n"
    "for bus in os.listdir('/dev/bus/usb/'):\n"
    "    bus_path = f'/dev/bus/usb/{bus}'\n"
    "    for dev in os.listdir(bus_path):\n"
    "        path = f'{bus_path}/{dev}'\n"
    "        try:\n"
    "            fd = os.open(path, os.O_WRONLY)\n"
    "            fcntl.ioctl(fd, USBDEVFS_RESET, 0)\n"
    "            os.close(fd)\n"
    "        except: pass\n"
)


def _reset_usb_devices(client: Client) -> None:
    """
    Send ``USBDEVFS_RESET`` ioctl to all USB devices to recover from
    stale device state after pcscd restarts or topology teardowns.

    :param client: Client role object.
    :type client: Client
    """
    client.host.conn.run(f'python3 -c "{USB_RESET_SCRIPT}"', raise_on_error=False)


def detect_pinpad_reader(client: Client) -> None:
    """
    Skip the test if no pinpad smart card reader with the expected token
    is detected.  All checks are run as the ``sssd`` user to verify that
    ``p11_child`` will be able to reach the reader via pcscd.

    pcscd may lose track of the card after a topology teardown, so
    reset USB devices, restart pcscd, and recheck before giving up.

    :param client: Client role object.
    :type client: Client
    """
    _reset_usb_devices(client)
    client.svc.stop("virt_cacard.service", raise_on_error=False)

    for attempt in range(2):
        client.svc.restart("pcscd.socket", raise_on_error=False)
        client.svc.restart("pcscd.service", raise_on_error=False)
        client.host.conn.run("sleep 2", raise_on_error=False)

        args: CLIBuilderArgs = {
            "module": (client.host.cli.option.VALUE, OPENSC_MODULE),
            "list-slots": (client.host.cli.option.SWITCH, True),
        }
        result = client.host.conn.run(
            f"runuser -u sssd -- {client.host.cli.command('pkcs11-tool', args)}",
            raise_on_error=False,
        )
        if result.rc == 0 and "token" in result.stdout.lower():
            break

        if attempt == 0:
            client.host.conn.run("killall pcscd 2>/dev/null || true; sleep 1", raise_on_error=False)
            _reset_usb_devices(client)
            continue

        pytest.skip(
            "No smart card reader with token detected or not accessible to sssd user — "
            f"rc={result.rc}, out={result.stdout}, err={result.stderr}"
        )

    token_uri = f"token={TOKEN_LABEL.replace(' ', '%20')}"
    if token_uri not in result.stdout:
        pytest.skip(f"Token label does not match '{TOKEN_LABEL}' — " f"initialize the card with this label first")


def enable_opensc_pinpad(client: Client) -> None:
    """
    Enable pinpad support in ``/etc/opensc.conf``.

    OpenSC disables pinpad by default (``enable_pinpad = false``).
    Without this, the ``CKF_PROTECTED_AUTHENTICATION_PATH`` flag is
    never set on the PKCS#11 token, and ``p11_child`` falls back to
    keyboard PIN entry.

    :param client: Client role object.
    :type client: Client
    """
    client.host.fs.sed("s/enable_pinpad = false/enable_pinpad = true/", "/etc/opensc.conf", args=["-i"])


def enroll_card(client: Client) -> None:
    """
    Generate a self-signed certificate and private key, write them to the
    hardware smart card, and install the certificate as a trusted CA for
    ``p11_child``.

    :param client: Client role object.
    :type client: Client
    """
    key_path = "/tmp/pinpad_test.key"
    cert_path = "/tmp/pinpad_test.crt"

    for obj_type in ("privkey", "cert"):
        args: CLIBuilderArgs = {
            "module": (client.host.cli.option.VALUE, OPENSC_MODULE),
            "login": (client.host.cli.option.SWITCH, True),
            "pin": (client.host.cli.option.VALUE, TOKEN_PIN),
            "token-label": (client.host.cli.option.VALUE, TOKEN_LABEL),
            "delete-object": (client.host.cli.option.SWITCH, True),
            "type": (client.host.cli.option.VALUE, obj_type),
            "id": (client.host.cli.option.VALUE, CERT_ID),
        }
        client.host.conn.run(client.host.cli.command("pkcs11-tool", args), raise_on_error=False)

    args = {
        "x509": (client.host.cli.option.SWITCH, True),
        "nodes": (client.host.cli.option.SWITCH, True),
        "sha256": (client.host.cli.option.SWITCH, True),
        "days": (client.host.cli.option.VALUE, "365"),
        "newkey": (client.host.cli.option.VALUE, "rsa:2048"),
        "keyout": (client.host.cli.option.VALUE, key_path),
        "out": (client.host.cli.option.VALUE, cert_path),
        "subj": (client.host.cli.option.VALUE, CERT_SUBJ),
    }
    client.host.conn.run(client.host.cli.command("openssl req", args))

    for obj_type, path in (("privkey", key_path), ("cert", cert_path)):
        args = {
            "module": (client.host.cli.option.VALUE, OPENSC_MODULE),
            "login": (client.host.cli.option.SWITCH, True),
            "pin": (client.host.cli.option.VALUE, TOKEN_PIN),
            "token-label": (client.host.cli.option.VALUE, TOKEN_LABEL),
            "write-object": (client.host.cli.option.VALUE, path),
            "type": (client.host.cli.option.VALUE, obj_type),
            "id": (client.host.cli.option.VALUE, CERT_ID),
            "label": (client.host.cli.option.VALUE, TOKEN_LABEL),
        }
        client.host.conn.run(client.host.cli.command("pkcs11-tool", args))

    client.host.fs.rm("/etc/sssd/pki/sssd_auth_ca_db.pem")
    data = client.host.fs.read(cert_path)
    client.host.fs.append("/etc/sssd/pki/sssd_auth_ca_db.pem", data)


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.Client)
def test_smartcard_pinpad__su_as_local_user(client: Client):
    """
    :title: Local user smart card authentication with pinpad reader
    :setup:
        1. Verify pinpad smart card reader with expected token is connected
        2. Enroll certificate to the card and enable pinpad in OpenSC
        3. Create local user and configure SSSD for smart card authentication
    :steps:
        1. Authenticate as the local user via nested ``su``
        2. Check PAM responder log for protected authentication path detection
        3. Check p11_child log for login errors
    :expectedresults:
        1. PAM prompts with ``Use external keypad``, authentication succeeds,
           and ``whoami`` returns the local username
        2. PAM log contains ``protected authentication path [true]``
        3. No ``C_Login failed`` in the p11_child log
    :customerscenario: True
    """
    detect_pinpad_reader(client)
    username = "pinpadlocal1"
    client.local.user(username).add()

    enroll_card(client)
    enable_opensc_pinpad(client)

    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.common.local()
    client.sssd.dom("local")["local_auth_policy"] = "only"
    client.sssd.section(f"certmap/local/{username}")["matchrule"] = "<SUBJECT>.*CN=SSSD Test Cert.*"
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

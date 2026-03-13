"""
SSSD Socket Activation Tests.

:requirement: sssd_socket
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.roles.nfs import NFS
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("responder", ["nss", "pam", "ssh"])
def test_socket__responders__socket_activation_lifecycle(client: Client, provider: LDAP, responder: str):
    """
    :title: Socket-Activated Responder Lifecycle
    :description: |
        Verify that socket-activated responders:
        1. Have their socket unit active
        2. Have their service unit inactive initially
        3. Start automatically on first client request via systemd socket activation
    :setup:
        1. Configure SSSD with socket activation enabled
        2. Add test user to LDAP backend
    :steps:
        1. Verify socket unit is active and service unit is inactive
        2. Trigger first request, service unit becomes active
    :expectedresults:
        1. Service unit is inactive before first request
        2. Service unit becomes active after first request
    :customerscenario: False
    """
    u = provider.user("user1").add(password="Secret123")

    if responder in ["pam", "sudo", "ssh"]:
        client.sssd.sssd["services"] = "nss"
    else:
        client.sssd.sssd["services"] = ""

    client.sssd.restart()
    client.sssd.common.socket_responders([responder])

    socket_unit = f"sssd-{responder}.socket"
    service_unit = f"sssd-{responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{responder} socket should be active"
    assert not client.sssd.svc.is_active(service_unit), f"{responder} service should be inactive initially"

    if responder == "nss":
        client.tools.getent.passwd(u.name)
    elif responder == "pam":
        result = client.auth.ssh.password(u.name, "Secret123")
        assert result, f"PAM authentication failed for {u.name}"
    elif responder == "ssh":
        client.host.conn.run(f"sss_ssh_authorizedkeys {u.name}", raise_on_error=False)

    assert client.sssd.svc.is_active(service_unit), f"{responder} service should be active after request"


@pytest.mark.topology(KnownTopology.LDAP)
def test_socket__responders__socket_activation_lifecycle_autofs(client: Client, provider: GenericProvider, nfs: NFS):
    """
    :title: Socket-Activated Autofs Responder Lifecycle
    :description: |
        Verify that socket-activated autofs responder:
        1. Have their socket unit active
        2. Have their service unit inactive initially
        3. Start automatically on first client request via systemd socket activation
    :setup:
        1. Configure SSSD with socket activation enabled
        2. Add test user and autofs maps to LDAP backend
    :steps:
        1. Verify socket unit is active and service unit is inactive
        2. Trigger first autofs request, service unit becomes active
    :expectedresults:
        1. Service unit is inactive before first request
        2. Service unit becomes active after first request
    :customerscenario: False
    """
    responder = "autofs"
    provider.user("user1").add(password="Secret123")

    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    auto_export.key("export").add(info=nfs_export)

    client.sssd.sssd["services"] = ""
    client.sssd.restart()
    client.sssd.common.socket_responders([responder])

    socket_unit = f"sssd-{responder}.socket"
    service_unit = f"sssd-{responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{responder} socket should be active"
    assert not client.sssd.svc.is_active(service_unit), f"{responder} service should be inactive initially"

    client.automount.reload()
    result = client.automount.mount("/var/export/export", nfs_export)
    assert result, "AUTOFS mount failed for /var/export/export"

    assert client.sssd.svc.is_active(service_unit), f"{responder} service should be active after request"


@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("socket_responder", ["nss", "ssh"])
def test_socket__responders__mixed_socket_and_traditional_services(
    client: Client, provider: LDAP, socket_responder: str
):
    """
    :title: Mixed Socket-Activated and Traditional Services (NSS/SSH)
    :description: |
        Verify that some responders can be socket-activated while others run as traditional services
    :setup:
        1. Configure mixed socket-activated and traditional services
        2. Add test user to LDAP backend
    :steps:
        1. Verify socket unit is active and service unit is inactive for socket-activated responder
        2. Verify traditional responder is configured in services
        3. Trigger request for socket-activated responder
        4. Verify its service unit becomes active
    :expectedresults:
        1. Socket-activated responder is inactive before request
        2. Traditional responder is configured in traditional mode
        3. Request triggered for socket-activated responder
        4. Socket-activated responder starts automatically on first request
    :customerscenario: False
    """
    u = provider.user("user1").add(password="Secret123")

    if socket_responder == "nss":
        traditional_responder = "ssh"
    else:
        traditional_responder = "nss"

    client.sssd.sssd["services"] = traditional_responder
    client.sssd.restart()

    client.sssd.common.socket_responders([socket_responder])

    socket_unit = f"sssd-{socket_responder}.socket"
    socket_service = f"sssd-{socket_responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{socket_responder} socket should be active"
    assert not client.sssd.svc.is_active(socket_service), f"{socket_responder} service should be inactive initially"
    assert (
        traditional_responder in client.sssd.sssd["services"]
    ), f"{traditional_responder} should be listed in services (traditional mode)"

    if socket_responder == "nss":
        client.tools.getent.passwd(u.name)
    elif socket_responder == "ssh":
        client.host.conn.run(f"sss_ssh_authorizedkeys {u.name}", raise_on_error=False)

    assert client.sssd.svc.is_active(socket_service), f"{socket_responder} service should be active after request"


@pytest.mark.topology(KnownTopology.LDAP)
def test_socket__responders__mixed_socket_and_traditional_services_autofs(
    client: Client, provider: GenericProvider, nfs: NFS
):
    """
    :title: Mixed Socket-Activated and Traditional Services (Autofs)
    :description: |
        Verify that autofs can be socket-activated while other responders run as traditional services
    :setup:
        1. Configure mixed socket-activated autofs and traditional services
        2. Add test user and autofs maps to LDAP backend
    :steps:
        1. Verify autofs socket unit is active and service unit is inactive
        2. Verify traditional responder is configured in services
        3. Trigger autofs request
        4. Verify autofs service unit becomes active
    :expectedresults:
        1. Autofs responder is inactive before request
        2. Traditional responder is configured in traditional mode
        3. Autofs request triggered successfully
        4. Autofs responder starts automatically on first request
    :customerscenario: False
    """
    socket_responder = "autofs"
    traditional_responder = "nss"

    provider.user("user1").add(password="Secret123")

    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    auto_export.key("export").add(info=nfs_export)

    client.sssd.sssd["services"] = traditional_responder
    client.sssd.restart()

    client.sssd.common.socket_responders([socket_responder])

    socket_unit = f"sssd-{socket_responder}.socket"
    socket_service = f"sssd-{socket_responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{socket_responder} socket should be active"
    assert not client.sssd.svc.is_active(socket_service), f"{socket_responder} service should be inactive initially"
    assert (
        traditional_responder in client.sssd.sssd["services"]
    ), f"{traditional_responder} should be listed in services (traditional mode)"

    client.automount.reload()
    result = client.automount.mount("/var/export/export", nfs_export)
    assert result, "AUTOFS mount failed for /var/export/export"

    assert client.sssd.svc.is_active(socket_service), f"{socket_responder} service should be active after request"

"""
SSSD Socket Activation Tests.

:requirement: sssd_socket
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.nfs import NFS
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("responder", ["nss", "pam", "ssh"])
def test_socket__responders__socket_activation_lifecycle(client: Client, provider: GenericProvider, responder: str):
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

    if responder in ["pam", "ssh"]:
        client.sssd.sssd["services"] = "nss"
    else:
        client.sssd.sssd["services"] = ""

    client.sssd.restart(clean=True)
    client.sssd.common.socket_responders([responder])

    socket_unit = f"sssd-{responder}.socket"
    service_unit = f"sssd-{responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{responder} socket should be active"

    if responder == "nss":
        entry = client.tools.getent.passwd(u.name)
        assert entry is not None, f"NSS provider failed for {u.name}"
        assert entry.name == u.name, f"Expected user {u.name}, got {entry.name}"
    elif responder == "pam":
        result = client.auth.ssh.password(u.name, "Secret123")
        assert result, f"PAM authentication failed for {u.name}"
    elif responder == "ssh":
        ssh_result = client.host.conn.run(f"sss_ssh_authorizedkeys {u.name}", raise_on_error=False)
        assert ssh_result.rc == 0, f"SSH authorizedkeys lookup failed for {u.name}"

    assert client.sssd.svc.is_active(service_unit), f"{responder} service should be active after request"


@pytest.mark.importance("low")
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

    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    auto_export.key("export").add(info=nfs_export)

    client.sssd.sssd["services"] = ""
    client.sssd.restart(clean=True)
    client.sssd.common.socket_responders([responder])

    socket_unit = f"sssd-{responder}.socket"
    service_unit = f"sssd-{responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{responder} socket should be active"

    client.automount.reload()
    result = client.automount.mount("/var/export/export", nfs_export)
    assert result, "AUTOFS mount failed for /var/export/export"

    assert client.sssd.svc.is_active(service_unit), f"{responder} service should be active after request"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.parametrize("socket_responder", ["nss", "ssh"])
def test_socket__responders__mixed_socket_and_traditional_services(
    client: Client, provider: GenericProvider, socket_responder: str
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
    client.sssd.restart(clean=True)

    client.sssd.common.socket_responders([socket_responder])

    socket_unit = f"sssd-{socket_responder}.socket"
    socket_service = f"sssd-{socket_responder}.service"

    assert client.sssd.svc.is_active(socket_unit), f"{socket_responder} socket should be active"

    if socket_responder == "nss":
        client.tools.getent.passwd(u.name)
    elif socket_responder == "ssh":
        client.host.conn.run(f"sss_ssh_authorizedkeys {u.name}", raise_on_error=False)

    assert client.sssd.svc.is_active(socket_service), f"{socket_responder} service should be active after request"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_socket__responders__conflict_socket_and_traditional_config(client: Client):
    """
    :title: Conflict when responder is both in sssd.conf and socket-activated
    :description: |
        Verify that socket activated 'sssd_nss' refuses to start when a responder is
        configured both in the services line and also enabled for socket activation, as
        this creates a configuration conflict.
    :setup:
        1. Configure SSSD with NSS responder in services line
    :steps:
        1. Add NSS to services line in sssd.conf and attempt to enable socket activation for NSS
    :expectedresults:
        1. socket_responders() raises an exception or logs error
    :customerscenario: False
    """
    client.sssd.common.local()

    client.sssd.sssd["services"] = "nss"
    client.sssd.restart(clean=True)

    with pytest.raises(Exception, match="Misconfiguration found for the 'nss' responder"):
        client.sssd.common.socket_responders(["nss"])

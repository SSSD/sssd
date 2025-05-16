"""
Automount Test Cases

:requirement: autofs
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.nfs import NFS
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.ticket(gh=6739)
@pytest.mark.parametrize("cache_first", [False, True])
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_autofs__cache_first_set_to_true(
    client: Client, nfs: NFS, provider: GenericProvider, cache_first: bool, sssd_service_user: str
):
    """
    :title: Autofs works correctly with any cache_first value
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Enable autofs responder
        7. Set [autofs]/cache_first = $cache_first
        8. Start SSSD
        9. Reload autofs daemon
    :steps:
        1. Access /var/export/export
        2. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory can be accessed and it is correctly mounted to the NFS share
        2. /var/export contains auto.export map and "export" key
    :customerscenario: False
    """
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key = auto_export.key("export").add(info=nfs_export)

    # Start SSSD
    client.sssd.common.autofs()
    client.sssd.autofs["cache_first"] = str(cache_first)
    client.sssd.start(service_user=sssd_service_user)

    # Reload automounter in order fetch updated maps
    client.automount.reload()

    # Check that we can mount the exported directory
    assert client.automount.mount("/var/export/export", nfs_export), "Unable to mount /var/export/export!"

    # Check that the maps are correctly fetched
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__propagate_offline_status_for_a_single_domain(client: Client, provider: GenericProvider):
    """
    :title: Autofs propagates offline status if a domain is offline
    :setup:
        1. Block traffic to the provider
        2. Enable autofs responder
        3. Start SSSD
        4. Reload autofs daemon
    :steps:
        1. Read autofs responder logs
    :expectedresults:
        1. cache_req returns "SSSD is offline" when data provider is offline for auto.master search
    :customerscenario: False
    """
    # Render the provider offline
    client.firewall.outbound.reject_host(provider)

    # Start SSSD
    client.sssd.common.autofs()
    client.sssd.start()

    # Reload automounter in order fetch updated maps
    client.automount.reload()

    # Check that offline status was returned from cache req
    log = client.fs.read(client.sssd.logs.autofs).splitlines()
    offline_status_propagated = False
    for index, line in enumerate(log):
        if "cache_req_process_result" in line and "Finished: Error" in line and "SSSD is offline" in line:
            if "Object [auto.master] was not found in cache" in log[index - 1]:
                offline_status_propagated = True
                break

    assert offline_status_propagated, "Offline status not propagated!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__propagate_offline_status_for_multiple_domains(client: Client):
    """
    :title: Autofs propagates offline status if a domain is offline in multi domain environment
    :setup:
        1. Create two fake LDAP domains that will be offline (the provider is online but does not have autofs maps)
        2. Enable autofs responder
        3. Start SSSD
        4. Reload autofs daemon
    :steps:
        1. Read autofs responder logs
    :expectedresults:
        1. cache_req returns "SSSD is offline" when data provider is offline for auto.master search
    :customerscenario: False
    """
    # Create fake domains, these will be offline
    client.sssd.dom("fake1").update(
        enabled="true",
        id_provider="ldap",
        ldap_uri="ldap://fake1.test",
    )

    client.sssd.dom("fake2").update(
        enabled="true",
        id_provider="ldap",
        ldap_uri="ldap://fake2.test",
    )

    # Start SSSD
    client.sssd.common.autofs()
    client.sssd.start()

    # Reload automounter in order fetch updated maps
    client.automount.reload()

    # Check that offline status was returned from cache req
    log = client.fs.read(client.sssd.logs.autofs).splitlines()
    offline_status_propagated = False
    for index, line in enumerate(log):
        if "cache_req_process_result" in line and "Finished: Error" in line and "SSSD is offline" in line:
            if "Object [auto.master] was not found in cache" in log[index - 1]:
                offline_status_propagated = True
                break

    assert offline_status_propagated, "Offline status not propagated!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__works_with_some_offline_domains(client: Client, nfs: NFS, provider: GenericProvider):
    """
    :title: Autofs works if some domain is offline in multi domain environment
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Create two fake LDAP domains that will be offline (the provider is online)
        7. Enable autofs responder
        8. Start SSSD
        9. Reload autofs daemon
    :steps:
        1. Access /var/export/export
        2. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory can be accessed and it is correctly mounted to the NFS share
        2. /var/export contains auto.export map and "export" key
    :customerscenario: False
    """

    # Create autofs maps
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key = auto_export.key("export").add(info=nfs_export)

    # Create fake domains, these will be offline
    client.sssd.dom("fake1").update(
        enabled="true",
        id_provider="ldap",
        ldap_uri="ldap://fake1.test",
    )

    client.sssd.dom("fake2").update(
        enabled="true",
        id_provider="ldap",
        ldap_uri="ldap://fake2.test",
    )

    # Start SSSD
    client.sssd.sssd["domain_resolution_order"] = f"fake1, fake2, {client.sssd.default_domain}"
    client.sssd.common.autofs()
    client.sssd.start()

    # Reload automounter in order fetch updated maps
    client.automount.reload()

    # Check that we can mount the exported directory
    assert client.automount.mount("/var/export/export", nfs_export), "Unable to mount /var/export/export!"

    # Check that the maps are correctly fetched
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match!"

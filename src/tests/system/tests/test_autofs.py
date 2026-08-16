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


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__maps_are_served_from_cache_when_provider_is_offline(
    client: Client, nfs: NFS, provider: GenericProvider
):
    """
    :title: Automount maps are served from cache when provider is offline
    :description:
        Once SSSD has fetched automount maps from an online provider it stores them in its
        cache. This test verifies that the autofs responder keeps serving those cached maps
        after the provider becomes unreachable: the maps are first loaded and mounted while
        online, then all traffic to the provider is blocked so SSSD goes offline, and the same
        mount must still succeed from cache without contacting the provider.
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Enable autofs responder
        7. Start SSSD
        8. Reload autofs daemon
    :steps:
        1. Access /var/export/export (populates cache)
        2. Block traffic to the provider
        3. Reload autofs daemon
        4. Access /var/export/export again
        5. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory is mounted to the NFS share
        2. Provider becomes unreachable
        3. Autofs daemon reloads successfully
        4. Directory is still accessible from cache
        5. /var/export contains auto.export map and "export" key
    :customerscenario: False
    """
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key = auto_export.key("export").add(info=nfs_export)

    client.sssd.common.autofs()
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount("/var/export/export", nfs_export), "Unable to mount /var/export/export while online!"

    client.firewall.outbound.reject_host(provider)
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export while offline!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match while offline!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__explicit_ldap_autofs_search_base_configures_lookup_scope(
    client: Client, nfs: NFS, provider: GenericProvider
):
    """
    :title: Automount maps are found when ldap_autofs_search_base is explicitly set
    :description:
        By default SSSD derives the search base for automount maps from the domain
        configuration. The ldap_autofs_search_base option lets an administrator restrict the
        lookup to a specific subtree. This test sets ldap_autofs_search_base explicitly to the
        provider naming context and verifies that the maps are still discovered and mounted
        correctly, confirming the option scopes the search without breaking map resolution.
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Enable autofs responder
        7. Set ldap_autofs_search_base to the provider naming context
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

    client.sssd.common.autofs()
    client.sssd.domain["ldap_autofs_search_base"] = provider.naming_context
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount("/var/export/export", nfs_export), "Unable to mount /var/export/export!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__autofs_provider_none_serves_maps_from_warm_cache(client: Client, nfs: NFS, provider: GenericProvider):
    """
    :title: Automount maps are served from warm cache when autofs_provider is set to none
    :description:
        A "warm cache" is a cache that was already populated by earlier online lookups against
        the provider. This test first runs with a live autofs provider so the automount maps are
        fetched and stored in the SSSD cache. The provider is then disabled by setting
        autofs_provider = none, which stops SSSD from performing any live map lookups. The maps
        must still be served from the previously populated (warm) cache.
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Enable autofs responder
        7. Start SSSD
        8. Reload autofs daemon
    :steps:
        1. Access /var/export/export (populates cache)
        2. Stop SSSD
        3. Set autofs_provider = none
        4. Start SSSD
        5. Reload autofs daemon
        6. Access /var/export/export
        7. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory is mounted to the NFS share
        2. SSSD is stopped
        3. autofs_provider is changed to none
        4. SSSD starts successfully
        5. Autofs daemon reloads successfully
        6. Directory is still accessible from warm cache
        7. /var/export contains auto.export map and "export" key
    :customerscenario: False
    """
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key = auto_export.key("export").add(info=nfs_export)

    client.sssd.common.autofs()
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export with provider!"

    client.sssd.stop()
    client.sssd.domain["autofs_provider"] = "none"
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export with provider=none!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match with provider=none!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__new_map_entries_added_to_provider_are_visible_after_reload(
    client: Client, nfs: NFS, provider: GenericProvider
):
    """
    :title: New automount map entries added to provider are visible after autofs reload
    :description:
        Automount maps can change on the provider after SSSD is already running. This test
        verifies that a newly added map key is picked up by SSSD and the autofs responder: it
        starts with a map that contains a single export, adds a second export key on the
        provider while SSSD is running, reloads the autofs daemon, and confirms both the old
        and the new entry are resolvable and mountable.
    :setup:
        1. Create two NFS exports
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add only the first NFS export key to auto.export
        6. Enable autofs responder
        7. Start SSSD
        8. Reload autofs daemon
    :steps:
        1. Access /var/export/export1
        2. Add the second NFS export key to auto.export
        3. Reload autofs daemon
        4. Access /var/export/export2
        5. Dump automount maps "automount -m"
    :expectedresults:
        1. First export is mounted successfully
        2. Second key is added to the provider
        3. Autofs daemon reloads successfully
        4. Second export is mounted successfully
        5. /var/export contains both export1 and export2 keys
    :customerscenario: False
    """
    nfs_export1 = nfs.export("export1").add()
    nfs_export2 = nfs.export("export2").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key1 = auto_export.key("export1").add(info=nfs_export1)

    client.sssd.common.autofs()
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount("/var/export/export1", nfs_export1), "Unable to mount /var/export/export1!"

    key2 = auto_export.key("export2").add(info=nfs_export2)
    client.automount.reload()

    assert client.automount.mount("/var/export/export2", nfs_export2), "Unable to mount /var/export/export2!"

    maps = client.automount.dumpmaps()
    assert str(key1) in maps["/var/export"]["keys"], "export1 key missing from automount maps!"
    assert str(key2) in maps["/var/export"]["keys"], "export2 key missing from automount maps!"

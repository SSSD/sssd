"""
Automount Test Cases

:requirement: autofs
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ldap import LDAP
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
        if "sbus_reply_check" in line and "SSSD is offline" in line:
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
        Verifies that the autofs responder keeps serving cached automount maps after the
        provider becomes unreachable and SSSD is brought offline.
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
        2. Block traffic to the provider and bring SSSD offline
        3. Reload autofs daemon
        4. Access /var/export/export again
        5. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory is mounted to the NFS share
        2. SSSD is offline
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
    # Blocking traffic does not terminate existing connections, so explicitly bring SSSD
    # offline to make sure the provider is really treated as unreachable.
    client.sssd.bring_offline()
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
        Verifies that automount maps are still discovered and mounted when the lookup subtree
        is restricted with the ldap_autofs_search_base option.
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
        A warm cache is one already populated by earlier online lookups. Verifies that with
        autofs_provider = none (no live lookups) the maps are still served from that cache.
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
        2. Configure autofs_provider = none and restart SSSD
        3. Reload autofs daemon
        4. Access /var/export/export
        5. Dump automount maps "automount -m"
    :expectedresults:
        1. Directory is mounted to the NFS share
        2. SSSD restarts with autofs_provider = none
        3. Autofs daemon reloads successfully
        4. Directory is still accessible from warm cache
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

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export with provider!"

    client.sssd.domain["autofs_provider"] = "none"
    client.sssd.restart()
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export with provider=none!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps do not match with provider=none!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__maps_are_loaded_when_autofs_provider_is_not_set(client: Client, nfs: NFS, provider: GenericProvider):
    """
    :title: Automount maps are loaded when autofs_provider is not explicitly set in sssd.conf
    :description:
        Verifies the default autofs_provider behavior when the key is absent from sssd.conf.
        SSSD should fall back to the id_provider and still serve automount maps.
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Enable autofs responder without setting autofs_provider
        7. Start SSSD
        8. Reload autofs daemon
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
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Mount failed when autofs_provider is not explicitly set!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps not loaded with default autofs_provider!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__new_map_entries_added_to_provider_are_visible_after_reload(
    client: Client, nfs: NFS, provider: GenericProvider
):
    """
    :title: New automount map entries added to provider are visible after autofs reload
    :description:
        Verifies that a map key added on the provider while SSSD is running is picked up after
        an autofs reload, alongside the existing entries.
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


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1113639)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__maps_are_fetched_after_sssd_comes_back_online(client: Client, nfs: NFS, provider: GenericProvider):
    """
    :title: Automount maps are fetched after SSSD comes back online from offline
    :description:
        Verifies that SSSD fetches the automount maps from the provider once it reconnects,
        even when it originally started with an empty cache while the provider was unreachable.
    :setup:
        1. Create NFS export
        2. Create auto.master map
        3. Create auto.export map
        4. Add /var/export (auto.export) key to auto.master
        5. Add "NFS export" key as "export" to auto.export
        6. Block traffic to the provider
        7. Enable autofs responder
        8. Start SSSD with a clean cache (it comes up offline)
    :steps:
        1. Restore traffic to the provider and bring SSSD back online
        2. Reload autofs daemon
        3. Access /var/export/export
        4. Dump automount maps "automount -m"
    :expectedresults:
        1. SSSD is back online
        2. Autofs daemon reloads successfully
        3. Directory can be accessed and it is correctly mounted to the NFS share
        4. /var/export contains auto.export map and "export" key
    :customerscenario: True
    """
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    key = auto_export.key("export").add(info=nfs_export)

    # Block the provider and start SSSD with an empty cache so it comes up offline.
    client.firewall.outbound.reject_host(provider)
    client.sssd.common.autofs()
    client.sssd.start(clean=True)

    # Restore connectivity and bring SSSD back online.
    client.firewall.outbound.accept_host(provider)
    client.sssd.bring_online()

    # Reload automounter in order fetch the maps now that we are online again.
    client.automount.reload()

    assert client.automount.mount(
        "/var/export/export", nfs_export
    ), "Unable to mount /var/export/export after coming back online!"
    assert client.automount.dumpmaps() == {
        "/var/export": {"map": "auto.export", "keys": [str(key)]},
    }, "Automount maps were not fetched after coming back online!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1873715)
@pytest.mark.topology(KnownTopology.LDAP)
def test_autofs__duplicate_case_insensitive_map_keys_both_accessible(client: Client, ldap: LDAP, nfs: NFS):
    """
    :title: Automount keys that differ only in case are both accessible
    :description:
        Two automount keys in the same map whose names differ only in case (MIT vs mit) must
        both resolve to their own distinct NFS export.
    :setup:
        1. Create two NFS exports (export1, export2)
        2. Create automountMap entries ou=auto.master and ou=auto.home
        3. Add the /var/export mount point (pointing to auto.home) to auto.master
        4. Add two automount entries under auto.home with cn=MIT and cn=mit, using a unique
           description attribute as the RDN so the case-insensitive cn values do not collide
        5. Configure SSSD autofs to use the automountMap/automount schema with cn as the key
        6. Start SSSD
        7. Reload autofs daemon
    :steps:
        1. Dump automount maps "automount -m"
        2. Access /var/export/MIT
        3. Access /var/export/mit
    :expectedresults:
        1. Both the MIT and mit keys are present in the auto.home map
        2. /var/export/MIT is mounted to export1
        3. /var/export/mit is mounted to export2
    :customerscenario: True
    """
    nfs_export1 = nfs.export("export1").add()
    nfs_export2 = nfs.export("export2").add()

    base = ldap.ldap.naming_context

    # Build the automount tree manually. The two keys that only differ in case (MIT vs mit) are
    # stored in the case-insensitive cn attribute (ldap_autofs_entry_key=cn), which is exactly the
    # condition from the bug. A neutral, uniquely-valued description attribute is used as the RDN so
    # the two entries have distinct DNs, while cn stays the autofs key that SSSD serves.
    ldap.ldap.add(f"ou=auto.master,{base}", {"objectClass": ["top", "automountMap"], "ou": "auto.master"})
    ldap.ldap.add(f"ou=auto.home,{base}", {"objectClass": ["top", "automountMap"], "ou": "auto.home"})
    ldap.ldap.add(
        f"description=master-home,ou=auto.master,{base}",
        {
            "objectClass": ["top", "automount"],
            "description": "master-home",
            "cn": "/var/export",
            "automountInformation": "auto.home",
        },
    )
    ldap.ldap.add(
        f"description=key-MIT,ou=auto.home,{base}",
        {
            "objectClass": ["top", "automount"],
            "description": "key-MIT",
            "cn": "MIT",
            "automountInformation": nfs_export1.get(),
        },
    )
    ldap.ldap.add(
        f"description=key-mit2,ou=auto.home,{base}",
        {
            "objectClass": ["top", "automount"],
            "description": "key-mit2",
            "cn": "mit",
            "automountInformation": nfs_export2.get(),
        },
    )

    # Configure SSSD to read the automountMap/automount schema, with cn as the key.
    client.sssd.common.autofs()
    client.sssd.domain["ldap_autofs_map_object_class"] = "automountMap"
    client.sssd.domain["ldap_autofs_map_name"] = "ou"
    client.sssd.domain["ldap_autofs_entry_object_class"] = "automount"
    client.sssd.domain["ldap_autofs_entry_key"] = "cn"
    client.sssd.domain["ldap_autofs_entry_value"] = "automountInformation"
    client.sssd.start()
    client.automount.reload()

    # Both keys, differing only in case, must be served in the same map. Dumping the maps also
    # populates the indirect mount point so the keys can then be accessed on demand.
    keys = [k.split(" | ")[0] for k in client.automount.dumpmaps()["/var/export"]["keys"]]
    assert "MIT" in keys, f"MIT key is not served: {keys}"
    assert "mit" in keys, f"mit key is not served: {keys}"

    # Both keys must mount their own distinct NFS export.
    assert client.automount.mount("/var/export/MIT", nfs_export1), "Unable to mount /var/export/MIT!"
    assert client.automount.mount("/var/export/mit", nfs_export2), "Unable to mount /var/export/mit!"


@pytest.mark.importance("medium")
@pytest.mark.ticket(bz=1206221)
@pytest.mark.topology(KnownTopology.LDAP)
def test_autofs__all_keys_read_despite_ldap_sizelimit(client: Client, ldap: LDAP, nfs: NFS):
    """
    :title: All automount keys are accessible even when the LDAP look-through limit is exceeded
    :description:
        Each automount key must remain individually accessible even when the map has more keys
        than the Directory Server look-through limit. SSSD looks keys up on demand instead of
        enumerating the whole map, so every key must still mount.
    :setup:
        1. Create auto.master map
        2. Create auto.home map
        3. Add /var/export (auto.home) key to auto.master
        4. Create 20 NFS exports and add them as keys export1..export20 to auto.home
        5. Set the Directory Server look-through limits (nsslapd-lookthroughlimit and
           nsslapd-pagedlookthroughlimit) to 10
        6. Enable autofs responder
        7. Start SSSD
        8. Reload autofs daemon
    :steps:
        1. Access each of the 20 keys /var/export/export1 .. /var/export/export20
    :expectedresults:
        1. Every key is mounted successfully, none is lost to the look-through limit
    :customerscenario: True
    """
    auto_master = ldap.automount.map("auto.master").add()
    auto_home = ldap.automount.map("auto.home").add()
    auto_master.key("/var/export").add(info=auto_home)

    exports = []
    for i in range(1, 21):
        export = nfs.export(f"export{i}").add()
        exports.append(export)
        auto_home.key(f"export{i}").add(info=export)

    # Restrict the Directory Server look-through limit below the number of automount keys, so
    # that enumerating the whole map exceeds it. Each key must still be accessible on demand.
    configdn = "cn=config,cn=ldbm database,cn=plugins,cn=config"
    ldap.ldap.modify(configdn, replace={"nsslapd-lookthroughlimit": "10", "nsslapd-pagedlookthroughlimit": "10"})

    client.sssd.common.autofs()
    client.sssd.start()
    client.automount.reload()

    for i, export in enumerate(exports, start=1):
        assert client.automount.mount(
            f"/var/export/export{i}", export
        ), f"Key export{i} is not accessible with the look-through limit set!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=2013218)
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
@pytest.mark.preferred_topology(KnownTopology.LDAP)
def test_autofs__unknown_mount_point_error_is_immediate(client: Client, nfs: NFS, provider: GenericProvider):
    """
    :title: Lookup of an unknown automount key fails immediately instead of being delayed
    :description:
        A lookup of a non-existent mount point must return an error quickly, it must not be
        delayed by the negative-cache timeout (~50s).
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
        1. Access the valid /var/export/export mount point
        2. Access the unknown /var/export/non_existing_key mount point and measure the time
    :expectedresults:
        1. Directory is mounted to the NFS share
        2. The lookup fails in less than 5 seconds
    :customerscenario: True
    """
    nfs_export = nfs.export("export").add()
    auto_master = provider.automount.map("auto.master").add()
    auto_export = provider.automount.map("auto.export").add()
    auto_master.key("/var/export").add(info=auto_export)
    auto_export.key("export").add(info=nfs_export)

    client.sssd.common.autofs()
    client.sssd.start()
    client.automount.reload()

    assert client.automount.mount("/var/export/export", nfs_export), "Unable to mount valid mount point!"

    # Measure the lookup time on the client itself to avoid counting ssh round-trip overhead.
    result = client.host.conn.run(
        "start=$(date +%s); stat /var/export/non_existing_key; rc=$?; "
        'end=$(date +%s); echo "elapsed=$((end - start))"; exit "$rc"',
        raise_on_error=False,
    )
    assert result.rc != 0, "Lookup of an unknown mount point unexpectedly succeeded!"

    elapsed = int(next(line for line in result.stdout_lines if line.startswith("elapsed=")).split("=")[1])
    assert elapsed < 5, f"Unknown mount point lookup was delayed ({elapsed}s), it should be immediate!"

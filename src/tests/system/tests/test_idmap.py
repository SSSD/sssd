"""
SSSD SID-based ID mapping (Active Directory / Samba) test cases.

:requirement: idmap
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.topology import KnownTopologyGroup


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__ldap_provider_maps_consistently_across_restart(client: Client, provider: GenericADProvider):
    """
    :title: SID-based ID mapping stays consistent when id_provider is set to ldap
    :setup:
        1. Add a user and a group with that user as a member
        2. Configure 'id_provider = ldap', 'ldap_schema = ad' and 'ldap_id_mapping = True', then start SSSD
    :steps:
        1. Lookup the user and group by name and login over SSH
        2. Restart SSSD with a cleared cache and lookup the user and group by name again
        3. Lookup the user and group by the UID/GID recorded before the restart
    :expectedresults:
        1. User and group are found and login succeeds
        2. User and group are found again after the cache is cleared
        3. UID and GID are unchanged after the cache clear
    :customerscenario: True
    """
    user = provider.user("user-1").add()
    group = provider.group("group-1").add().add_member(user)

    client.sssd.domain["id_provider"] = "ldap"
    client.sssd.domain["ldap_schema"] = "ad"
    client.sssd.domain["ldap_id_mapping"] = "True"
    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["override_homedir"] = "/home/%u"
    client.sssd.start()

    passwd = client.tools.getent.passwd(user.name)
    assert passwd is not None, f"'{user.name}' was not found!"
    assert passwd.uid is not None, f"'{user.name}' has no UID!"
    uid = passwd.uid

    grp = client.tools.getent.group(group.name)
    assert grp is not None, f"'{group.name}' was not found!"
    assert grp.gid is not None, f"'{group.name}' has no GID!"
    gid = grp.gid

    assert client.auth.ssh.password(user.name, "Secret123"), f"'{user.name}' failed to login over SSH!"

    client.sssd.restart(clean=True)

    passwd = client.tools.getent.passwd(user.name)
    assert passwd is not None, f"'{user.name}' was not found after cache clear!"
    assert passwd.uid == uid, f"'{user.name}' UID changed from {uid} to {passwd.uid} after cache clear!"

    grp = client.tools.getent.group(group.name)
    assert grp is not None, f"'{group.name}' was not found after cache clear!"
    assert grp.gid == gid, f"'{group.name}' GID changed from {gid} to {grp.gid} after cache clear!"

    assert client.tools.getent.passwd(uid) is not None, f"Lookup by UID '{uid}' failed after cache clear!"
    assert client.tools.getent.group(gid) is not None, f"Lookup by GID '{gid}' failed after cache clear!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=1077695)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.parametrize(
    "range_min, range_max, range_size, error",
    [
        ("5000", "6000", "", "Invalid settings for range selection"),
        ("-1000", "", "", "Invalid settings for range selection: [-1000][2000200000][200000]"),
        ("2147483648", "2147483648", "", "Failed to read [ldap_idmap_range_min]"),
        ("-1000000", "-1000", "-9000", "Invalid settings for range selection"),
        ("10000000", "10000", "", "Invalid settings for range selection: [10000000][10000][200000]"),
    ],
    ids=[
        "range_size_larger_than_window",
        "negative_range_min_bz1077695",
        "int_max_overflow",
        "all_values_negative",
        "range_max_less_than_min",
    ],
)
def test_idmap__invalid_range_config_rejects_lookup(
    client: Client, provider: GenericADProvider, range_min: str, range_max: str, range_size: str, error: str
):
    """
    :title: Invalid ldap_idmap_range configuration is rejected
    :setup:
        1. Add a user
        2. Configure an invalid 'ldap_idmap_range_min'/'ldap_idmap_range_max'/'ldap_idmap_range_size'
           combination and start SSSD
    :steps:
        1. Lookup the user
        2. Check the SSSD domain log
    :expectedresults:
        1. Lookup fails
        2. Log contains the range-selection error
    :customerscenario: True
    """
    user = provider.user("user-1").add()

    client.sssd.domain["ldap_idmap_range_min"] = range_min
    client.sssd.domain["ldap_idmap_range_max"] = range_max
    client.sssd.domain["ldap_idmap_range_size"] = range_size
    client.sssd.start(check_config=False)

    result = client.tools.getent.passwd(user.name)
    assert result is None, f"'{user.name}' was unexpectedly found with an invalid idmap range configuration!"

    log = client.fs.read(client.sssd.logs.domain())
    assert error in log, f"'{error}' not found in the domain log!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__range_min_zero_allows_lookup(client: Client, provider: GenericADProvider):
    """
    :title: ldap_idmap_range_min set to zero is a valid boundary
    :setup:
        1. Add a user
        2. Configure 'ldap_idmap_range_min = 0' and start SSSD
    :steps:
        1. Lookup the user
        2. Login over SSH
    :expectedresults:
        1. User is found
        2. Login is successful
    :customerscenario: True
    """
    user = provider.user("user-1").add()

    client.sssd.domain["ldap_idmap_range_min"] = "0"
    client.sssd.start()

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' was not found with 'ldap_idmap_range_min = 0'!"

    assert client.auth.ssh.password(user.name, "Secret123"), f"'{user.name}' failed to login over SSH!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__default_domain_sid_mismatch_still_maps(client: Client, provider: GenericADProvider):
    """
    :title: A valid but unrelated ldap_idmap_default_domain_sid still maps the domain
    :setup:
        1. Add a user
        2. Configure 'ldap_idmap_default_domain_sid' with a well-formed SID that does not
           belong to the provider's domain, and start SSSD
    :steps:
        1. Check the SSSD domain log
        2. Lookup the user and login over SSH
    :expectedresults:
        1. Log shows the explicit SID was added as an ID mapping
        2. User is found and login is successful
    :customerscenario: True
    """
    user = provider.user("user-1").add()

    unrelated_sid = "S-1-5-21-1111111-2222222-3333333"
    client.sssd.domain["ldap_idmap_default_domain_sid"] = unrelated_sid
    client.sssd.start()

    log = client.fs.read(client.sssd.logs.domain())
    assert f"[{unrelated_sid}]" in log, f"'{unrelated_sid}' was not added as an ID mapping!"

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' was not found!"

    assert client.auth.ssh.password(user.name, "Secret123"), f"'{user.name}' failed to login over SSH!"


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__default_domain_sid_match_avoids_remap(client: Client, provider: GenericADProvider):
    """
    :title: A matching ldap_idmap_default_domain_sid pins the domain to slice zero
    :setup:
        1. Add a user and a group with that user as a member
        2. Read the domain SID from the user's SID
        3. Configure 'ldap_idmap_default_domain_sid' and 'ldap_idmap_default_domain' to match
           the provider's own domain, and start SSSD
    :steps:
        1. Lookup the user and group; record UID/GID
        2. Check the SSSD domain log
        3. Clear the SSSD cache and lookup the user and group by the recorded UID/GID
    :expectedresults:
        1. User and group are found
        2. Log does not show a hash-based domain assignment
        3. UID and GID are unchanged after the cache clear
    :customerscenario: True
    """
    user = provider.user("user-1").add()
    group = provider.group("group-1").add().add_member(user)
    domain_sid = "-".join(user.sid.split("-")[:-1])  # type: ignore[attr-defined]

    client.sssd.domain["ldap_idmap_default_domain_sid"] = domain_sid
    client.sssd.domain["ldap_idmap_default_domain"] = "idmapdomain"
    client.sssd.start()

    passwd = client.tools.getent.passwd(user.name)
    assert passwd is not None, f"'{user.name}' was not found!"
    assert passwd.uid is not None, f"'{user.name}' has no UID!"
    uid = passwd.uid

    grp = client.tools.getent.group(group.name)
    assert grp is not None, f"'{group.name}' was not found!"
    assert grp.gid is not None, f"'{group.name}' has no GID!"
    gid = grp.gid

    log = client.fs.read(client.sssd.logs.domain())
    assert f"Adding domain [{domain_sid}]" not in log, f"Domain '{domain_sid}' was hash-assigned unexpectedly!"

    client.sssd.restart(clean=True)

    assert client.tools.getent.passwd(uid) is not None, f"Lookup by UID '{uid}' failed after cache clear!"
    assert client.tools.getent.group(gid) is not None, f"Lookup by GID '{gid}' failed after cache clear!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__invalid_default_domain_sid_rejected(client: Client, provider: GenericADProvider):
    """
    :title: A malformed ldap_idmap_default_domain_sid is rejected
    :setup:
        1. Add a user
        2. Configure 'ldap_idmap_default_domain_sid = junk' and start SSSD
    :steps:
        1. Check the SSSD domain log
        2. Lookup the user
    :expectedresults:
        1. Log shows the domain could not be added to the ID map with the junk SID
        2. User is still found through the hash-based fallback mapping
    :customerscenario: True
    """
    user = provider.user("user-1").add()

    client.sssd.domain["ldap_idmap_default_domain_sid"] = "junk"
    client.sssd.start(check_config=False)

    log = client.fs.read(client.sssd.logs.domain())
    assert "Could not add domain" in log, "'Could not add domain' not found in the domain log!"
    assert "[junk][0] to ID map" in log, "'[junk][0] to ID map' not found in the domain log!"

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' was not found via the hash-based fallback mapping!"


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.parametrize(
    "default_domain_sid, error",
    [
        (None, "ldap_idmap_default_domain_sid is not set"),
        ("S-1-5-21-1111111-2222222-3333333", "Adding new ID mapping"),
    ],
    ids=["default_sid_not_set", "default_sid_set_but_unrelated"],
)
def test_idmap__autorid_compat_logs_default_sid_state(
    client: Client, provider: GenericADProvider, default_domain_sid: str | None, error: str
):
    """
    :title: ldap_idmap_autorid_compat logs whether a default domain SID is pinned
    :setup:
        1. Add a user
        2. Configure 'ldap_idmap_autorid_compat = true', optionally with
           'ldap_idmap_default_domain_sid', and start SSSD
    :steps:
        1. Check the SSSD domain log
        2. Lookup the user
    :expectedresults:
        1. Log reflects whether the default domain SID was pinned
        2. User is found
    :customerscenario: True
    """
    user = provider.user("user-1").add()

    client.sssd.domain["ldap_idmap_autorid_compat"] = "true"
    if default_domain_sid is not None:
        client.sssd.domain["ldap_idmap_default_domain_sid"] = default_domain_sid
    client.sssd.start()

    log = client.fs.read(client.sssd.logs.domain())
    assert error in log, f"'{error}' not found in the domain log!"

    result = client.tools.getent.passwd(user.name)
    assert result is not None, f"'{user.name}' was not found!"


@pytest.mark.importance("high")
@pytest.mark.ticket(bz=874616)
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_idmap__builtin_sid_debug_silenced(client: Client, provider: GenericADProvider):
    """
    :title: Built-in SIDs do not produce noisy DEBUG messages
    :setup:
        1. Start SSSD with the default ID mapping configuration
    :steps:
        1. Lookup the well-known 'Administrator' identity
        2. Check the SSSD domain log
    :expectedresults:
        1. Lookup succeeds
        2. Log shows built-in SIDs are skipped without a parsing or conversion error
    :customerscenario: True
    """
    client.sssd.start()

    result = client.host.conn.run("id Administrator", raise_on_error=False)
    assert result.rc == 0, "'id Administrator' failed!"

    log = client.fs.read(client.sssd.logs.domain())
    assert "is a built-in one" in log, "'is a built-in one' not found in the domain log!"
    assert "Skipping built-in object" in log, "'Skipping built-in object' not found in the domain log!"
    assert "Could not parse domain SID" not in log, "Unexpected 'Could not parse domain SID' in the domain log!"
    assert "Could not convert SID to GID" not in log, "Unexpected 'Could not convert SID to GID' in the domain log!"

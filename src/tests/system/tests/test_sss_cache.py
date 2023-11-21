"""
sss_cache tests.

:requirement: IDM-SSSD-REQ: Status utility
"""

from __future__ import annotations

import time

import pytest
from pytest_mh.ssh import SSHProcessError
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.ticket(bz=1661182)
@pytest.mark.topology(KnownTopology.Client)
def test_sss_cache__cache_expire_message(client: Client):
    """
    :title: sss_cache do not print fake error messages
    :setup:
        1. Configure SSSD without any domain
        2. Set to sssd section "enable_files_domain" to "false"
        3. Create local user
    :steps:
        1. Restart SSSD
        2. Modify existing local user
        3. Expire cache with specific options
    :expectedresults:
        1. Error is raised, SSSD is not running
        2. Modified successfully
        3. Output did not contain wrong messages
    :customerscenario: True
    """
    client.sssd.sssd["enable_files_domain"] = "false"
    client.local.user("user1").add()

    with pytest.raises(SSHProcessError):
        client.sssd.restart()

    res = client.host.ssh.run("usermod -a -G wheel user1")
    assert "No domains configured, fatal error!" not in res.stdout

    for cmd in ("sss_cache -U", "sss_cache -G", "sss_cache -E", "sss_cache --user=nonexisting"):
        res = client.host.ssh.run(cmd)
        assert "No domains configured, fatal error!" not in res.stdout


@pytest.mark.importance("critical")
@pytest.mark.cache
@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_sss_cache__background_refresh(client: Client, provider: GenericProvider):
    """
    :title: Ensuring ldb cache data is refreshed correctly
    :setup:
        1. Create provider user
        2. Create provider group
        3. Create provider netgroup
        4. Configure SSSD and set 'entry_cache_timeout' to 1 and 'refresh_expired_interval' to 2
        5. Restart SSSD
        6. Populate the cache by performing 'getent' on the user, group and netgroup
    :steps:
        1. Search for user, group and netgroup lastUpdate and dataExpireTimestamp in the ldb database
        2. Wait 5 seconds and search for all timestamp in the cache again
    :expectedresults:
        1. The 'dataExpireTimestamp' value equals the 'lastUpdate + entry_cache_timeout' value
        2. User, group and netgroup 'lastUpdate' timestamp value has been refreshed
    :customerscenario: False
    """
    user = provider.user("test_user").add()
    provider.group("test_group").add().add_member(user)
    provider.netgroup("test_netgroup").add().add_member(user=user)

    domain = client.sssd.default_domain
    entry_cache_timeout = 1
    refresh_expired_interval = 2

    client.sssd.domain["entry_cache_timeout"] = str(entry_cache_timeout)
    client.sssd.domain["refresh_expired_interval"] = str(refresh_expired_interval)

    client.sssd.restart()
    client.tools.getent.passwd(f"test_user@{domain}")
    client.tools.getent.group(f"test_group@{domain}")
    client.tools.getent.netgroup(f"test_netgroup@{domain}")

    ldb_cache = f"/var/lib/sss/db/cache_{domain}.ldb"
    ldb_suffix = f"cn={domain},cn=sysdb"

    last_update: list[int] = []
    expire_time: list[int] = []

    for i in [f"test_user@{domain}", f"test_group@{domain}", "test_netgroup"]:
        result = client.ldb.search(ldb_cache, ldb_suffix, filter=f"name={i}")
        for k, v in result.items():
            for y in v.items():
                if y[0] == "lastUpdate":
                    last_update = last_update + [(int(y[1][0]))]
                if y[0] == "dataExpireTimestamp":
                    expire_time = expire_time + [(int(y[1][0]))]

    for m, n in enumerate(last_update):
        assert last_update[m] + entry_cache_timeout == expire_time[m]

    time.sleep(5)

    for s, t in enumerate([f"test_user@{domain}", f"test_group@{domain}", "test_netgroup"]):
        result = client.ldb.search(ldb_cache, ldb_suffix, filter=f"name={t}")
        for k, v in result.items():
            for y in v.items():
                if y[0] == "lastUpdate":
                    assert last_update[s] <= (int(y[1][0]))
